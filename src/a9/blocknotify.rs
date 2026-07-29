//! Run an external command whenever this node's chain tip changes.
//!
//! This is Bitcoin Core's `-blocknotify` contract, deliberately: every Stratum
//! backend — CKPool, NOMP, Yiimp, MiningCore — has consumed that interface since
//! 2011, so a pool points its existing script at this node and is done. Inventing
//! a bespoke long-poll or websocket would have obliged every integrator to write
//! new code for this chain alone.
//!
//! WHY IT EXISTS. A solo miner that learns of a new block late wastes one
//! miner's work. A Stratum pool that learns late keeps handing out work on the
//! stale parent to every connected miner, so one node's detection delay is
//! multiplied by the pool's entire hashrate. Without a push, a pool's only option
//! is polling `/explorer/tip`, and a node that is not richly peered otherwise
//! learns the tip from the 3-second beacon poll — 1.5s on average, which at a 5s
//! block target is 30% of an interval spent mining a parent that is already dead.
//! This turns that into a millisecond-scale push.
//!
//! WHY IT CANNOT AFFECT CONSENSUS. It is a read-only observer of a signal emitted
//! AFTER a block has already been applied. It does not validate, select, relay or
//! decide anything, and nothing consults its result — it has no return value that
//! any caller reads. A hook that can only observe cannot change what a node
//! accepts, so a node with it configured and a node without compute identical
//! chains. There is nothing here to prove with a test because there is no path
//! from this module back into block acceptance.
//!
//! THE ONE REAL HAZARD is back-pressure: a hook that blocked block application
//! would be far worse than the problem it solves. Four things prevent that, none
//! of them relying on the operator's script behaving:
//!
//!   * The tip signal is a `tokio::watch`. A watch sender NEVER blocks on a slow
//!     receiver — it overwrites. Ingest cannot be stalled by this task even in
//!     principle.
//!   * The loop below is single-flight by construction: at most one child process
//!     exists at any moment, so a hanging script cannot fork-bomb the machine.
//!     (Bitcoin's spawns are unbounded; this is deliberately stricter.)
//!   * Slow hooks COALESCE rather than queue. While a hook runs, further tip
//!     changes overwrite each other in the watch, so the next iteration fires once
//!     with the CURRENT tip. A pool is never handed a backlog of dead parents —
//!     which is exactly the failure this feature exists to prevent, and would be
//!     the ironic result of using an mpsc channel here instead.
//!   * A hook that outlives `HOOK_TIMEOUT` is killed. Bitcoin does not do this and
//!     it is a known way to leak processes forever.
//!
//! Stdout and stderr go to `/dev/null` on purpose. Inheriting them would let a
//! chatty script interleave into the client's own display, and PIPING them without
//! draining would deadlock the child once it filled the pipe buffer — a classic
//! trap in `blocknotify` reimplementations. A hook that wants to log should
//! redirect inside itself.

use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use log::{info, warn};
use tokio::process::Command;
use tokio::sync::RwLock;

use crate::a9::blockchain::Blockchain;

/// Command template. Unset (or blank) means the hook never runs and this module
/// costs nothing — the task is not even spawned.
const ENV_VAR: &str = "ALPHANUMERIC_BLOCKNOTIFY";

/// A hook still running after this is broken, not slow: the whole point is to
/// beat a 5s block interval. Killed rather than left to accumulate.
const HOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// `%s` is the block hash, matching Bitcoin's placeholder exactly so existing
/// pool scripts work unmodified. `%h` is this chain's addition — a pool that
/// wants the height would otherwise have to spend a round trip fetching it.
/// `%%` is a literal `%`.
///
/// Expansion applies to EVERY argument, not only ones that look like
/// placeholders — matching Bitcoin. A hook that needs a literal `%s` in its own
/// payload (a printf format, a URL-encoded value) must escape it as `%%s` or, far
/// better, keep it inside a script rather than in the template.
fn expand(arg: &str, hash_hex: &str, height: u32) -> String {
    let mut out = String::with_capacity(arg.len());
    let mut chars = arg.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push_str(hash_hex),
            Some('h') => out.push_str(&height.to_string()),
            Some('%') => out.push('%'),
            // Unknown escape: emit it verbatim rather than swallowing it, so a
            // path containing a stray '%' is not silently corrupted.
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Split the template into program + arguments on whitespace.
///
/// Executed directly, never through a shell. That removes command injection as a
/// category rather than arguing it is unreachable, and it means a hook cannot be
/// surprised by shell metacharacters. The cost is that pipes and `&&` are
/// unavailable — a hook wanting those should point at a script, which is what
/// pools do anyway. Returns None when the template is blank.
fn parse_template(raw: &str) -> Option<(String, Vec<String>)> {
    let mut parts = raw.split_whitespace();
    let program = parts.next()?.to_string();
    Some((program, parts.map(str::to_string).collect()))
}

/// Start the notifier if `ALPHANUMERIC_BLOCKNOTIFY` is set. Returns immediately;
/// the work happens on a detached task.
pub fn spawn(blockchain: Arc<RwLock<Blockchain>>) {
    let raw = match std::env::var(ENV_VAR) {
        Ok(v) => v,
        Err(_) => return,
    };
    let Some((program, args)) = parse_template(&raw) else {
        warn!("{ENV_VAR} is set but blank; block notifications are disabled");
        return;
    };

    tokio::spawn(async move {
        // Subscribing marks the CURRENT tip as seen, so the hook fires on the
        // next change rather than once at startup for a block the pool already
        // has. Matches Bitcoin, and avoids a spurious work restart on boot.
        let mut rx = { blockchain.read().await.subscribe_tip_changes() };
        info!(
            "Block notifications enabled: {} ({} arg{})",
            program,
            args.len(),
            if args.len() == 1 { "" } else { "s" }
        );

        loop {
            // Err only when the blockchain is dropped, i.e. shutdown.
            if rx.changed().await.is_err() {
                return;
            }
            // borrow_and_update marks this value seen. Anything that arrives
            // while the hook below runs will make the NEXT changed() return
            // immediately with the newest tip — the coalescing described above
            // falls out of the loop shape and needs no state of its own.
            let tip = *rx.borrow_and_update();
            fire(&program, &args, &hex::encode(tip.hash), tip.height, HOOK_TIMEOUT).await;
        }
    });
}

/// Outcome of one hook invocation. Returned rather than logged inline so the
/// process handling — the part with the real hazards — is testable without a
/// chain behind it.
#[derive(Debug, PartialEq, Eq)]
enum Fired {
    Ok,
    Failed,
    /// Exceeded HOOK_TIMEOUT and was killed.
    TimedOut,
    /// Could not be started at all (missing binary, not executable).
    NotStarted,
}

/// Run the hook once and wait for it, bounded by `timeout`.
///
/// Awaiting here is what makes the caller single-flight: the loop cannot begin
/// another hook until this returns, so at most one child exists at any moment.
///
/// The bound is a parameter rather than reading `HOOK_TIMEOUT` directly so the
/// kill path can be tested against a short deadline without pausing a runtime
/// clock — which would otherwise have cost a tokio feature for test support.
async fn fire(
    program: &str,
    args: &[String],
    hash_hex: &str,
    height: u32,
    timeout: Duration,
) -> Fired {
    let mut cmd = Command::new(program);
    for arg in args {
        cmd.arg(expand(arg, hash_hex, height));
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // If this task is ever cancelled mid-hook, take the child with it rather
        // than orphaning it to the init process.
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            // Logged per failure rather than once: a hook that starts failing
            // after months of working is worth seeing, and the rate is bounded
            // by the block interval.
            warn!("block notification failed to start ({program}): {e}");
            return Fired::NotStarted;
        }
    };

    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) if status.success() => Fired::Ok,
        Ok(Ok(status)) => {
            warn!("block notification exited with {status} at height {height}");
            Fired::Failed
        }
        Ok(Err(e)) => {
            warn!("block notification could not be awaited: {e}");
            Fired::Failed
        }
        Err(_) => {
            // kill() failing only means the child exited between the timeout
            // firing and this call, which is the outcome we wanted anyway.
            let _ = child.kill().await;
            warn!(
                "block notification exceeded {:?} at height {height} and was killed",
                timeout
            );
            Fired::TimedOut
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_bitcoin_compatible_placeholders() {
        let hash = "ab".repeat(32);
        // %s is the hash, exactly as Bitcoin's -blocknotify defines it, so an
        // existing pool script keeps working unmodified.
        assert_eq!(expand("%s", &hash, 42), hash);
        assert_eq!(expand("%h", &hash, 42), "42");
        assert_eq!(expand("--tip=%h", &hash, 7), "--tip=7");
        assert_eq!(
            expand("/n/%s/%h", &hash, 9),
            format!("/n/{hash}/9")
        );
    }

    #[test]
    fn leaves_unknown_and_trailing_escapes_intact() {
        let hash = "cd".repeat(32);
        // A stray '%' in a path must survive rather than eat the next character.
        assert_eq!(expand("100%", &hash, 1), "100%");
        assert_eq!(expand("%z", &hash, 1), "%z");
        assert_eq!(expand("%%s", &hash, 1), "%s");
        assert_eq!(expand("plain", &hash, 1), "plain");
    }

    #[test]
    fn parses_template_into_program_and_args() {
        let (p, a) = parse_template("/usr/bin/notify %s %h").unwrap();
        assert_eq!(p, "/usr/bin/notify");
        assert_eq!(a, vec!["%s", "%h"]);

        let (p, a) = parse_template("  spaced   out  ").unwrap();
        assert_eq!(p, "spaced");
        assert_eq!(a, vec!["out"]);

        let (p, a) = parse_template("bare").unwrap();
        assert_eq!(p, "bare");
        assert!(a.is_empty());

        // Blank templates disable the hook instead of spawning an empty program.
        assert!(parse_template("").is_none());
        assert!(parse_template("   ").is_none());
    }

    // ---- process handling: the half with the real hazards --------------------

    #[tokio::test]
    async fn a_successful_hook_reports_ok_and_receives_its_arguments() {
        let dir = std::env::temp_dir().join(format!("a9-bn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("fired");

        // NOTE: the script body deliberately contains no '%'. Expansion applies to
        // EVERY argument, so a "printf '%s'" here would have had its own format
        // string rewritten to the block hash. That is Bitcoin's behaviour too, and
        // the reason the doc on `expand` tells hooks to keep placeholders out of
        // their payload.
        let args = vec![
            "-c".to_string(),
            format!("echo \"$1 $2\" > {}", out.display()),
            "sh".to_string(),
            "%s".to_string(),
            "%h".to_string(),
        ];
        let hash = "ab".repeat(32);
        assert_eq!(fire("/bin/sh", &args, &hash, 4321, HOOK_TIMEOUT).await, Fired::Ok);

        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            written.trim(),
            format!("{hash} 4321"),
            "hook did not receive the expanded argv"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_reported_but_not_fatal() {
        // A pool's script failing must be visible and must not stop the loop.
        assert_eq!(
            fire("/bin/sh", &["-c".to_string(), "exit 3".to_string()], "aa", 1, HOOK_TIMEOUT).await,
            Fired::Failed
        );
    }

    #[tokio::test]
    async fn a_missing_program_does_not_panic() {
        // A typo'd path must degrade to a warning, never take the node down.
        assert_eq!(
            fire("/nonexistent/definitely-not-here", &[], "aa", 1, HOOK_TIMEOUT).await,
            Fired::NotStarted
        );
    }

    // The hazard that matters most: a hung hook must be killed rather than left
    // to accumulate one process per block forever. Uses tokio's clock so the test
    // does not actually wait HOOK_TIMEOUT.
    #[tokio::test]
    async fn a_hung_hook_is_killed_at_the_timeout() {
        let started = std::time::Instant::now();
        let fired = fire(
            "/bin/sh",
            &["-c".to_string(), "sleep 3600".to_string()],
            "aa",
            1,
            Duration::from_millis(50),
        )
        .await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the hook was awaited instead of being killed at its deadline"
        );
        assert_eq!(fired, Fired::TimedOut, "a hung hook must be killed, not awaited");
    }

    // The hook is spawned, never shell-interpreted, so a template containing
    // metacharacters is passed through as literal argv rather than being
    // evaluated. This is the property that makes injection a non-category.
    #[test]
    fn metacharacters_are_inert_argv_not_shell() {
        let (p, a) = parse_template("/bin/hook ; rm -rf / %s").unwrap();
        assert_eq!(p, "/bin/hook");
        assert_eq!(a, vec![";", "rm", "-rf", "/", "%s"]);
    }
}
