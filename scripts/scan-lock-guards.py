#!/usr/bin/env python3
"""Scan Rust sources for the two async-lock hazard classes that have caused
real network incidents on this codebase:

1. GUARD-ACROSS-AWAIT: a tokio RwLock/Mutex guard bound to a local and held
   across a later `.await` (fair-lock writer parks -> every later user wedges).
   Caught the v7.6.3/v7.6.4 wedge family.

2. GUARD SHADOWING: the same binding name re-bound to a fresh guard in one
   function, so a later `drop(name)` releases the SECOND guard while the first
   lives to scope end — invisible to check #1 because the drop LOOKS right.
   This was the v7.6.6 sync_with_network wedge (frozen beacon, 2026-07-09):
   the step-2 `let peers = ...` was only dropped on one path and shadowed on
   the other.

Heuristic, zero deps. Findings need human review — the point is a short list
worth reading after every p2p/lock change, not proof.

Usage: python3 scripts/scan-lock-guards.py [src/a9/node.rs ...]
       (defaults to all .rs files under src/)
"""
import re
import sys
import pathlib

LOCK_BIND = re.compile(
    r"let\s+(?:mut\s+)?(\w+)\s*=\s*[\w.]*\.(?:peers|blockchain|network_health|"
    r"peer_secrets|outbound_connections|outbound_circuit_breakers|webrtc_mesh)"
    # The statement must END at the guard: `... .read().await;`. A trailing method
    # call (`.read().await.len();`) binds the RESULT, the guard is a temporary
    # dropped at statement end — flagging those drowned the report in noise.
    r"\s*\.\s*(read|write)\(\)\s*\.\s*await\s*(?:;|$)"
)
INLINE_LOCK = re.compile(r"\.(read|write)\(\)\s*\.\s*await")
FN_DECL = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)")


def scan(path: pathlib.Path) -> list[str]:
    src = path.read_text().splitlines()
    findings: list[str] = []

    # Pass 1: guard held across a later await inside its scope.
    for i, line in enumerate(src):
        m = LOCK_BIND.search(line)
        if not m:
            continue
        name = m.group(1)
        depth = 0
        for j in range(i + 1, min(i + 120, len(src))):
            l = src[j]
            depth += l.count("{") - l.count("}")
            if depth < 0:
                break  # guard scope ended
            if re.search(r"drop\(\s*" + name + r"\s*\)", l):
                break
            if LOCK_BIND.search(l) and re.search(r"let\s+(?:mut\s+)?" + name + r"\s*=", l):
                break  # re-bound; pass 2 owns this case
            if ".await" in l and not INLINE_LOCK.search(l):
                findings.append(
                    f"{path}:{i+1}: guard `{name}` ({m.group(2)}) held across await at line {j+1}"
                )
                break

    # Pass 2: same guard name bound to a lock more than once in one function.
    fn_start, fn_name, binds = 0, "?", {}
    for i, line in enumerate(src):
        fm = FN_DECL.match(line)
        if fm:
            for nm, lines in binds.items():
                if len(lines) > 1:
                    findings.append(
                        f"{path}:{lines[0]}: fn `{fn_name}` binds lock guard `{nm}` "
                        f"{len(lines)}x (lines {lines}) — drop()/scope-end may release "
                        f"the WRONG guard (shadowing wedge class)"
                    )
            fn_start, fn_name, binds = i, fm.group(1), {}
        m = LOCK_BIND.search(line)
        if m:
            binds.setdefault(m.group(1), []).append(i + 1)
    for nm, lines in binds.items():
        if len(lines) > 1:
            findings.append(
                f"{path}:{lines[0]}: fn `{fn_name}` binds lock guard `{nm}` "
                f"{len(lines)}x (lines {lines}) — shadowing wedge class"
            )
    return findings


def main() -> int:
    args = [pathlib.Path(a) for a in sys.argv[1:]]
    if not args:
        args = sorted(pathlib.Path("src").rglob("*.rs"))
    all_findings: list[str] = []
    for p in args:
        all_findings.extend(scan(p))
    for f in all_findings:
        print(f)
    print(f"\n{len(all_findings)} finding(s) — review each; heuristic, not proof.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
