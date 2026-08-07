//! WebRTC DataChannel transport for the NAT-traversal mesh (feature `webrtc_mesh`).
//!
//! Every miner is behind residential NAT with no open inbound port, so direct libp2p-tcp never
//! connects and everything falls back to the slow serverless gateway relay. WebRTC fixes this: two
//! NAT'd peers exchange a one-time SDP offer/answer + ICE candidates through the gateway's signaling
//! mailbox (`/api/signal`), then ICE hole-punches a DIRECT, encrypted DataChannel between them —
//! and blocks flow peer-to-peer off the gateway entirely. This module owns the RTCPeerConnection /
//! DataChannel plumbing; the gateway is only a dumb signaling relay, and every block still gets the
//! node's full PoW + ML-DSA validation, so this is a transport-only change.

// Deliberate defense in depth: the parent module is feature-gated too, while this keeps the file
// fail-closed if its module declaration is ever moved or accidentally ungated.
#![allow(clippy::duplicated_attributes)]
#![cfg(feature = "webrtc_mesh")]

use std::sync::Arc;
use zeroize::Zeroizing;

use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// The label of the single reliable+ordered DataChannel we open per peer for block/tx gossip.
pub const MESH_CHANNEL_LABEL: &str = "a9/mesh/1";

/// webrtc's DTLS handshake uses rustls 0.23, which requires a process-wide crypto provider to be
/// installed before first use. This codebase already links `ring`, so pin that provider. Idempotent
/// (install_default errors if already set — we ignore it), so it's safe to call before every API build.
fn ensure_crypto_provider() {
    use std::sync::Once;
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// True for LAN / non-routable / link-local addresses — the ones we do NOT want as ICE candidates
/// on an internet-only mesh. Loopback is intentionally excluded here (kept via the filter below) so
/// same-machine tests still work.
fn is_lan_or_local(ip: std::net::IpAddr) -> bool {
    // Fold an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to IPv4 so the IPv4 arm classifies it; std
    // does not auto-fold, so ::ffff:<internal-ipv4> would otherwise slip past the V6 arm as
    // "public" and NOT be stripped from a remote peer's SDP (the internal-probe/SSRF primitive this
    // guards). Mirrors node.rs::canonical_ip / PeerInfo::new.
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(v6)),
        v4 => v4,
    };
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
        }
    }
}

/// True if an SDP candidate's connection-address (whitespace token 4) is a LAN/private/
/// link-local IP. Works for both full `a=candidate:` SDP lines and bare `candidate:` trickle
/// strings — the connection-address is token 4 in both layouts (see the leak test).
fn candidate_line_is_local(cand: &str) -> bool {
    cand.split_whitespace()
        .nth(4)
        .and_then(|tok| tok.parse::<std::net::IpAddr>().ok())
        .map(is_lan_or_local)
        .unwrap_or(false)
}

/// Rebuild an SDP dropping any `a=candidate:` line whose connection-address is LAN/private.
/// build_api's ip_filter only vets LOCALLY gathered candidates; a remote peer's candidates
/// arrive un-vetted inside its bundled SDP, so a malicious-but-authenticated peer could list
/// private/link-local addresses that our ICE agent would then send STUN connectivity checks to
/// (an internal-probe / SSRF reflection primitive). Filtering to the SAME is_lan_or_local
/// predicate proven on the outbound side removes it. Public server-reflexive candidates keep a
/// public connection-address and are preserved, so real connectivity is unaffected; mDNS
/// `.local` hostnames don't parse as an IpAddr and pass through harmlessly (mDNS is disabled).
fn strip_local_candidates_from_sdp(sdp: &str) -> String {
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.lines() {
        if line.trim_start().starts_with("a=candidate:") && candidate_line_is_local(line) {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

/// Build a webrtc API handle (data-channel only; no media codecs). Reused for all peer connections.
///
/// Configured for an INTERNET-only mesh: miners are across the internet, not a LAN. We disable mDNS
/// (so the node never does local multicast — the thing that triggers the OS "Local Network"
/// permission and Bonjour discovery) and filter private/LAN/link-local IPs out of ICE candidates
/// (so no local address is gathered, used, sent to, or leaked to peers). The public address STUN
/// discovers (server-reflexive) is what connects real peers and is unaffected.
///
/// `include_loopback` gathers 127.0.0.1/::1 candidates. Real deployments pass `false` — peers are
/// never on each other's loopback, and same-machine STUN reflexive addresses hairpin and fail, so
/// loopback is only meaningful when two meshes run in one process (the tests). Loopback is not a
/// "local network" address and never triggers the OS permission, so enabling it for tests is safe;
/// production keeps it off to keep SDPs minimal.
pub fn build_api(include_loopback: bool) -> Result<API, webrtc::Error> {
    ensure_crypto_provider();
    let mut media = MediaEngine::default();
    let registry = register_default_interceptors(Registry::new(), &mut media)?;
    let mut settings = webrtc::api::setting_engine::SettingEngine::default();
    settings.set_ice_multicast_dns_mode(webrtc::ice::mdns::MulticastDnsMode::Disabled);
    settings.set_include_loopback_candidate(include_loopback);
    settings.set_ip_filter(Box::new(move |ip: std::net::IpAddr| {
        if ip.is_loopback() {
            return include_loopback;
        }
        !is_lan_or_local(ip)
    }));
    Ok(APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .with_setting_engine(settings)
        .build())
}

/// STUN configuration: the public servers a node uses to discover its server-reflexive (public)
/// address so a NAT'd peer can be reached. Empty `ice_servers` (used by the local test) means
/// host-candidate-only, which is all that loopback needs.
pub fn ice_config(stun_urls: &[String]) -> RTCConfiguration {
    let ice_servers = if stun_urls.is_empty() {
        vec![]
    } else {
        vec![RTCIceServer {
            urls: stun_urls.to_vec(),
            ..Default::default()
        }]
    };
    RTCConfiguration {
        ice_servers,
        ..Default::default()
    }
}

/// Create a peer connection.
pub async fn new_peer_connection(
    api: &API,
    config: RTCConfiguration,
) -> Result<Arc<RTCPeerConnection>, webrtc::Error> {
    Ok(Arc::new(api.new_peer_connection(config).await?))
}

/// A reliable, ordered DataChannel init for block gossip.
pub fn mesh_channel_init() -> RTCDataChannelInit {
    RTCDataChannelInit {
        ordered: Some(true),
        ..Default::default()
    }
}

/// Set the local description and WAIT for ICE gathering to complete, then return the full SDP with
/// all candidates bundled in (non-trickle). This keeps signaling to a single offer + single answer
/// exchange over the mailbox — no per-candidate round-trips — which is what keeps the free-tier
/// Redis budget flat.
pub async fn set_local_and_gather(
    pc: &Arc<RTCPeerConnection>,
    desc: RTCSessionDescription,
) -> Result<RTCSessionDescription, Box<dyn std::error::Error + Send + Sync>> {
    let mut gather_complete = pc.gathering_complete_promise().await;
    pc.set_local_description(desc).await?;
    // Bound the wait so a peer whose STUN gathering never completes can't hang the handshake
    // indefinitely. On elapse proceed best-effort: local_description() still returns whatever
    // candidates were gathered so far, preserving the non-trickle single-exchange model.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), gather_complete.recv()).await;
    pc.local_description()
        .await
        .ok_or_else(|| "no local description after gathering".into())
}

// ---------------------------------------------------------------------------------------------
// Signaling client: the node's side of the gateway's /api/signal mailbox.
// ---------------------------------------------------------------------------------------------

/// One signaling envelope, wire-identical to what the gateway (lib/signal.ts) stores + verifies.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignalEnvelope {
    pub from: String,
    pub to: String,
    pub kind: String, // "offer" | "answer" | "candidate"
    pub payload: String,
    pub ts: u64,
    pub signature: String,
}

/// Typed body of `POST /api/signal/drain`. `envelopes` defaults to empty so an
/// omitted field stays the valid "mailbox is empty" response, while anything
/// present that is not a well-formed envelope list is a hard error rather than a
/// silent empty drain. Unknown sibling fields are ignored, so the gateway can add
/// response fields without breaking older nodes.
#[derive(serde::Deserialize)]
struct DrainResponse {
    #[serde(default)]
    envelopes: Vec<SignalEnvelope>,
}

/// Canonical JSON string, byte-identical to the gateway's canonicalize() (lib/canonical.ts) and the
/// node's canonicalize_json(): object keys sorted by codepoint, compact serialization. This is the
/// preimage both sides sign/verify — it MUST match or every envelope is rejected.
pub fn canonicalize(value: &serde_json::Value) -> String {
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for k in keys {
                    out.insert(k.clone(), sort(&m[k]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(sort).collect()),
            _ => v.clone(),
        }
    }
    serde_json::to_string(&sort(value)).unwrap_or_default()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Signs signaling envelopes with an Ed25519 key and moves them over the gateway mailbox. The node
/// implements this with its existing handshake key (node_id = hex(pubkey)); tests use a throwaway
/// key. Decoupling the mesh from the node behind this trait makes both testable in isolation.
#[async_trait::async_trait]
pub trait SignalTransport: Send + Sync {
    fn local_node_id(&self) -> &str;
    async fn post_signal(&self, to: &str, kind: &str, payload: &str) -> Result<(), String>;
    async fn drain_signals(&self) -> Result<Vec<SignalEnvelope>, String>;
}

/// Concrete HTTP transport: signs with a ring Ed25519 key and POSTs to a gateway base URL. Used by
/// the integration tests; the node provides its own impl reusing sign_with_handshake_key.
pub struct HttpSignalTransport {
    pub node_id: String,
    /// Ed25519 PKCS#8 mesh identity. Zeroized on drop: this key authenticates
    /// every signalling message this node sends, so a copy left in freed memory
    /// is enough to impersonate it on the mesh.
    key_pkcs8: Zeroizing<Vec<u8>>,
    http: reqwest::Client,
    gateway_base: String,
}

impl HttpSignalTransport {
    pub fn new(key_pkcs8: Zeroizing<Vec<u8>>, gateway_base: String) -> Result<Self, String> {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let kp = Ed25519KeyPair::from_pkcs8(&key_pkcs8).map_err(|e| e.to_string())?;
        let node_id = hex::encode(kp.public_key().as_ref());
        Ok(Self {
            node_id,
            key_pkcs8,
            http: reqwest::Client::new(),
            gateway_base,
        })
    }

    fn sign(&self, canonical: &str) -> Result<String, String> {
        use ring::signature::Ed25519KeyPair;
        let kp = Ed25519KeyPair::from_pkcs8(&self.key_pkcs8).map_err(|e| e.to_string())?;
        Ok(hex::encode(kp.sign(canonical.as_bytes()).as_ref()))
    }
}

#[async_trait::async_trait]
impl SignalTransport for HttpSignalTransport {
    fn local_node_id(&self) -> &str {
        &self.node_id
    }

    async fn post_signal(&self, to: &str, kind: &str, payload: &str) -> Result<(), String> {
        let ts = now_secs();
        let canonical = canonicalize(&serde_json::json!({
            "from": self.node_id, "to": to, "kind": kind, "payload": payload, "ts": ts,
        }));
        let signature = self.sign(&canonical)?;
        let body = serde_json::json!({
            "from": self.node_id, "to": to, "kind": kind, "payload": payload, "ts": ts,
            "signature": signature,
        });
        let resp = self
            .http
            .post(format!("{}/api/signal", self.gateway_base))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!(
                "post_signal {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        Ok(())
    }

    async fn drain_signals(&self) -> Result<Vec<SignalEnvelope>, String> {
        let ts = now_secs();
        let canonical = canonicalize(&serde_json::json!({ "peer": self.node_id, "ts": ts }));
        let signature = self.sign(&canonical)?;
        let body = serde_json::json!({ "peer": self.node_id, "ts": ts, "signature": signature });
        let resp = self
            .http
            .post(format!("{}/api/signal/drain", self.gateway_base))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!(
                "drain {}: {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        // Typed, and deliberately asymmetric. An ABSENT `envelopes` field is the
        // gateway's legitimate "nothing queued" answer, so it deserializes to an
        // empty list. A PRESENT but malformed one is a schema break and must
        // surface: the old `unwrap_or_default()` collapsed both into "no signals",
        // so a gateway contract change would have silently disabled mesh formation
        // — no error, no log, no backoff, just a node that quietly stops peering
        // and pays the propagation cost of being mesh-less.
        let body: DrainResponse = resp.json().await.map_err(|e| e.to_string())?;
        Ok(body.envelopes)
    }
}

// ---------------------------------------------------------------------------------------------
// WebRtcMesh: orchestrates DataChannel connections to peers via the gateway signaling.
// ---------------------------------------------------------------------------------------------

use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use webrtc::data_channel::data_channel_message::DataChannelMessage as DcMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;

/// Google's public STUN servers — how each NAT'd node learns its server-reflexive (public) address
/// so a peer can hole-punch to it. Free, no account, no TURN.
pub fn default_stun_urls() -> Vec<String> {
    vec![
        "stun:stun.l.google.com:19302".to_string(),
        "stun:stun1.l.google.com:19302".to_string(),
    ]
}

/// Bounded inbound queue depth. try_send DROPS when full instead of growing without bound, so a
/// peer that floods faster than validation can drain cannot OOM the node (blocks re-flood anyway).
const MESH_INBOUND_CAP: usize = 128;
/// Hard ceiling on simultaneous peer connections (inbound + outbound). Stops a random-key spammer
/// from forcing unbounded RTCPeerConnections / STUN gathers. A legitimate node runs well under this.
const MESH_MAX_CONNS: usize = 64;
/// A connection that has not reached Connected within this long is reaped (closed + removed). A
/// half-open pc (offer sent, no answer) never reaches Failed on its own — ICE needs a remote
/// description to start its timers — so without the reaper it would linger and leak forever.
const MESH_STALE_SECS: u64 = 45;
/// Per-peer inbound rate limit (token bucket): sustained msgs/sec and burst. Sheds a single peer's
/// flood at ingress so it can't monopolize the shared inbound queue (head-of-line blocking).
const MESH_MSG_RATE: f64 = 100.0;
const MESH_MSG_BURST: f64 = 200.0;
/// Live inbound DataChannels a single peer may hold open at once. The mesh needs exactly one
/// (`MESH_CHANNEL_LABEL`); the slack absorbs a re-open racing a close. Without a cap a remote can
/// open unbounded channels on its one RTCPeerConnection — `RTCSctpTransport::accept_data_channels`
/// has no limit of its own (`max_channels` gates only OUTBOUND id allocation) — retaining a closure
/// and SCTP stream per channel.
const MESH_MAX_CHANNELS_PER_PEER: usize = 4;

/// A peer connection plus when we created it (for the stale reaper).
struct PeerConn {
    pc: Arc<RTCPeerConnection>,
    created: Instant,
}

/// Per-PEER inbound accounting, shared by every DataChannel that peer opens.
///
/// The bucket used to be constructed inside `register_channel`, i.e. one bucket per CHANNEL. A
/// remote opening N channels on its single RTCPeerConnection therefore got N independent buckets
/// and N x MESH_MSG_RATE — defeating the exact head-of-line protection the limit exists for, since
/// the inbound queue (`MESH_INBOUND_CAP`) is shared and `try_send` drops other peers' gossip once
/// it saturates. One entry per peer id, dropped with the connection in `forget_if_current`.
struct PeerIngress {
    bucket: Arc<std::sync::Mutex<TokenBucket>>,
    /// Live channel count for this peer, capped at MESH_MAX_CHANNELS_PER_PEER. Incremented on
    /// registration, decremented by the channel's own on_close.
    live_channels: usize,
}

/// Simple per-peer token bucket for inbound message rate limiting.
struct TokenBucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}

impl TokenBucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last: Instant::now(),
            rate,
            burst,
        }
    }
    /// Refill by elapsed time, then try to spend one token. false => over budget, drop the message.
    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A running mesh of direct WebRTC DataChannels to peers, established over the gateway signaling
/// mailbox. Deterministic role assignment (perfect negotiation: the lexicographically-lower node_id
/// is the initiator) prevents double-dial. Inbound bytes from every peer are funneled to one channel
/// the node drains; `broadcast` writes to every open channel — so the node's block flood "just works"
/// over it. The gateway only carries the one-time offer/answer; blocks flow peer-to-peer.
pub struct WebRtcMesh {
    transport: Arc<dyn SignalTransport>,
    api: Arc<API>,
    config: RTCConfiguration,
    conns: Arc<Mutex<HashMap<String, PeerConn>>>,
    channels: Arc<Mutex<HashMap<String, Arc<RTCDataChannel>>>>,
    inbound_tx: mpsc::Sender<(String, Vec<u8>)>,
    /// The gateway peer directory, refreshed by the dialer. Inbound offers from ids NOT in here are
    /// ignored (anti-DoS) once it has been populated.
    known_peers: Arc<Mutex<HashSet<String>>>,
    /// Timestamp of the last signaling activity that ADVANCED a handshake. Drives poll cadence.
    last_signal: Arc<Mutex<Instant>>,
    /// Per-peer dial backoff: (consecutive failures, earliest next dial). A peer that can't be
    /// reached (symmetric NAT, offline) is retried on an exponentially growing interval instead of
    /// every ~60s, so doomed handshakes don't hold the node at the fast poll cadence.
    dial_backoff: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    /// Wakes the signaling poll loop out of its long safety-net sleep the instant there's a reason to
    /// drain (a dial, an inbound offer, a directory change, a lost link). Without this the event-
    /// driven cadence would still wait out the full 180s slow sleep before noticing.
    wake: Arc<tokio::sync::Notify>,
    /// Terminal flag set by the kill switch's shutdown(). Checked under the conns lock in new_pc so a
    /// dial/offer already in flight when shutdown() runs can't re-insert (and leak) a pc afterwards.
    closed: Arc<std::sync::atomic::AtomicBool>,
    /// Per-peer inbound rate limiter + live channel count, keyed by peer id. Shared across all of
    /// that peer's DataChannels so the limit is genuinely per-peer (see `PeerIngress`).
    ingress: Arc<Mutex<HashMap<String, PeerIngress>>>,
}

// Opaque Debug so a `#[derive(Debug)]` holder (the Node) compiles — the inner webrtc/transport
// types aren't Debug and their contents aren't useful to print anyway.
impl std::fmt::Debug for WebRtcMesh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebRtcMesh")
            .field("local_id", &self.local_id())
            .finish_non_exhaustive()
    }
}

impl WebRtcMesh {
    /// Build a mesh. Returns the mesh + the receiver the node drains for inbound peer messages
    /// (tagged with the sender's node_id).
    #[allow(clippy::type_complexity)] // Mesh plus authenticated-sender-tagged inbound receiver.
    pub fn new(
        transport: Arc<dyn SignalTransport>,
        api: Arc<API>,
        stun_urls: Vec<String>,
    ) -> Result<(Arc<Self>, mpsc::Receiver<(String, Vec<u8>)>), String> {
        let (inbound_tx, inbound_rx) = mpsc::channel(MESH_INBOUND_CAP);
        let mesh = Arc::new(Self {
            transport,
            api,
            config: ice_config(&stun_urls),
            conns: Arc::new(Mutex::new(HashMap::new())),
            channels: Arc::new(Mutex::new(HashMap::new())),
            inbound_tx,
            known_peers: Arc::new(Mutex::new(HashSet::new())),
            last_signal: Arc::new(Mutex::new(Instant::now())),
            dial_backoff: Arc::new(Mutex::new(HashMap::new())),
            wake: Arc::new(tokio::sync::Notify::new()),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ingress: Arc::new(Mutex::new(HashMap::new())),
        });
        Ok((mesh, inbound_rx))
    }

    pub fn local_id(&self) -> &str {
        self.transport.local_node_id()
    }

    pub async fn connected_peers(&self) -> Vec<String> {
        self.channels.lock().await.keys().cloned().collect()
    }

    /// Replace the known-peer directory (called by the dialer after each fetch). Used to gate
    /// inbound offers to peers actually announced on the gateway, and to bound the dial-backoff map
    /// by dropping entries for peers that have left the directory.
    pub async fn set_known_peers(&self, ids: &[String]) {
        let fresh: HashSet<String> = ids.iter().cloned().collect();
        {
            let mut k = self.known_peers.lock().await;
            *k = fresh.clone();
        }
        // Prune backoff for departed peers so the map can't grow without bound over a churning net.
        self.dial_backoff
            .lock()
            .await
            .retain(|id, _| fresh.contains(id));
    }

    /// Mark signaling activity now (a handshake in progress, or a reason to expect one soon — e.g. a
    /// directory change) AND wake the poll loop so it drains immediately. Public so the node can wake
    /// the poll on a directory change without draining Redis to find out.
    pub async fn touch(&self) {
        *self.last_signal.lock().await = Instant::now();
        self.wake.notify_one();
    }

    /// How long since the last signaling activity.
    pub async fn quiet_for(&self) -> Duration {
        self.last_signal.lock().await.elapsed()
    }

    /// Await the next wake signal (a touch() or an explicit wake()). The poll loop selects on this
    /// against its safety-net sleep so a touch() interrupts the long quiet cadence immediately.
    pub async fn wait_for_wake(&self) {
        self.wake.notified().await;
    }

    /// Wake the poll loop without recording activity — used by the kill switch to make it re-check
    /// the enabled flag and exit promptly.
    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// True if any connection is still negotiating (New/Connecting) — i.e. we're expecting an answer
    /// or completing a hole-punch, so the poll loop should stay fast to finish it.
    pub async fn has_forming_conns(&self) -> bool {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as St;
        self.conns
            .lock()
            .await
            .values()
            .any(|c| matches!(c.pc.connection_state(), St::New | St::Connecting))
    }

    /// Close every connection and clear both maps — used by the remote kill switch to stop the mesh
    /// cleanly (webrtc 0.17 has no Drop, so each pc must be close()d to free its ICE agent + socket).
    pub async fn shutdown(&self) {
        // Set BEFORE clearing conns so any dial/offer racing this (checking `closed` under the conns
        // lock in new_pc) refuses to insert instead of leaking a pc we never close here.
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let pcs: Vec<Arc<RTCPeerConnection>> = {
            let mut conns = self.conns.lock().await;
            let pcs = conns.values().map(|c| c.pc.clone()).collect();
            conns.clear();
            pcs
        };
        self.channels.lock().await.clear();
        self.ingress.lock().await.clear();
        for pc in pcs {
            let _ = pc.close().await;
        }
    }

    /// Remove `peer_id` from both maps ONLY if it still maps to exactly `pc` (Arc identity). This is
    /// the guard against ABA: a stale callback or the reaper must never evict a NEWER pc that a
    /// concurrent re-dial bound to the same id. Returns whether it removed. Does NOT close.
    async fn forget_if_current(&self, peer_id: &str, pc: &Arc<RTCPeerConnection>) -> bool {
        let removed = {
            let mut conns = self.conns.lock().await;
            if conns.get(peer_id).is_some_and(|c| Arc::ptr_eq(&c.pc, pc)) {
                conns.remove(peer_id);
                true
            } else {
                false
            }
        };
        if removed {
            self.channels.lock().await.remove(peer_id);
            // Drop this peer's rate limiter with its connection, so the map is bounded by live
            // peers (<= MESH_MAX_CONNS) rather than by every peer id ever seen.
            self.ingress.lock().await.remove(peer_id);
            // A lost link to a LOWER-id peer means that peer (the impolite initiator for this edge)
            // will re-dial us — stay responsive on the poll so we catch the re-offer promptly.
            if peer_id < self.local_id() {
                self.touch().await;
            }
        }
        removed
    }

    /// Identity-checked forget + close the SNAPSHOT pc (idempotent). Safe to await close() here —
    /// callers are NOT inside a state-change callback (that path spawns close() to avoid re-entrancy).
    /// webrtc 0.17 has no Drop, so close() is what actually frees the ICE agent + UDP socket.
    async fn remove_if_current_and_close(&self, peer_id: &str, pc: &Arc<RTCPeerConnection>) {
        self.forget_if_current(peer_id, pc).await;
        let _ = pc.close().await;
    }

    /// May we dial this peer now, or is it in backoff after recent failed attempts?
    async fn dial_allowed(&self, peer_id: &str) -> bool {
        match self.dial_backoff.lock().await.get(peer_id) {
            Some((_, next)) => Instant::now() >= *next,
            None => true,
        }
    }

    /// Record a failed dial to `peer_id`; grows the retry interval exponentially (15s, 30s, …, 600s).
    async fn note_dial_failure(&self, peer_id: &str) {
        let mut b = self.dial_backoff.lock().await;
        let entry = b.entry(peer_id.to_string()).or_insert((0, Instant::now()));
        entry.0 = entry.0.saturating_add(1);
        let shift = entry.0.min(6).saturating_sub(1);
        let secs = 15u64.saturating_mul(1u64 << shift).min(600);
        entry.1 = Instant::now() + Duration::from_secs(secs);
    }

    /// Handle a pc reaching a TERMINAL state (Failed or Closed). Always drops it from `conns` if it
    /// is still the current pc for `peer`; on `failed` (ICE gave up / a live link was lost) it also
    /// records dial backoff and closes the pc off-task. Recording backoff HERE — not only in
    /// `reap_stale` — is what actually throttles a low-id peer that keeps offering: the Failed
    /// state-change is the COMMON teardown, and `forget_if_current` removes the pc before the 45s
    /// reaper ever sees it, so without this the Failed path would escape the backoff entirely and
    /// keep the signaling poll loop hot. A previously-connected peer that drops to Failed takes a
    /// first-tier backoff before its next dial; `on_open` clears it on the next success.
    async fn on_terminal_pc_state(&self, peer: &str, pc: &Arc<RTCPeerConnection>, failed: bool) {
        let was_current = self.forget_if_current(peer, pc).await;
        if failed && was_current {
            self.note_dial_failure(peer).await;
            // Close off-task: close() drives more state changes, so awaiting it inside the
            // state-change handler would re-enter synchronously.
            let pc = pc.clone();
            tokio::spawn(async move {
                let _ = pc.close().await;
            });
        }
    }

    /// Close + remove any connection that has not reached Connected within MESH_STALE_SECS. Half-open
    /// pcs (offer sent, no answer arrived) never transition to Failed on their own, so this is the
    /// only thing that frees them and unblocks a re-dial of that peer.
    pub async fn reap_stale(&self) {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as St;
        let stale: Vec<(String, Arc<RTCPeerConnection>)> = {
            let conns = self.conns.lock().await;
            conns
                .iter()
                .filter(|(_, c)| {
                    // Only reap connections that never came up: New (half-open — offer sent, no
                    // answer), Connecting (hole-punch that never finished), or a Failed that slipped
                    // past the state-change callback. Deliberately NOT Disconnected: that is transient
                    // and ICE escalates it to Failed on its own — reaping it here would kill a link
                    // that is about to recover.
                    c.created.elapsed() > Duration::from_secs(MESH_STALE_SECS)
                        && matches!(
                            c.pc.connection_state(),
                            St::New | St::Connecting | St::Failed
                        )
                })
                .map(|(id, c)| (id.clone(), c.pc.clone()))
                .collect()
        };
        for (id, pc) in stale {
            // Identity-checked: never evict a fresh pc a concurrent re-dial bound to this id.
            self.remove_if_current_and_close(&id, &pc).await;
            // A reaped never-connected pc means a connection attempt with this peer failed — back
            // off regardless of which side offered. Previously only our OUTBOUND dials (id > local)
            // recorded backoff, so a low-id peer that repeatedly offers but never completes hole-
            // punch recorded none: dial_allowed(from) never throttled it, pinning the signaling poll
            // loop at its fast cadence and churning a fresh RTCPeerConnection every reap window.
            self.note_dial_failure(&id).await;
        }
    }

    /// Claim one channel slot for `peer_id` and hand back THAT PEER's shared rate limiter, or None
    /// if the peer already holds MESH_MAX_CHANNELS_PER_PEER live channels.
    ///
    /// Every channel a peer opens draws from the one bucket returned here, so a peer's inbound
    /// budget is MESH_MSG_RATE in total rather than per channel.
    async fn acquire_ingress_slot(
        &self,
        peer_id: &str,
    ) -> Option<Arc<std::sync::Mutex<TokenBucket>>> {
        let mut ingress = self.ingress.lock().await;
        let entry = ingress
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerIngress {
                bucket: Arc::new(std::sync::Mutex::new(TokenBucket::new(
                    MESH_MSG_RATE,
                    MESH_MSG_BURST,
                ))),
                live_channels: 0,
            });
        if entry.live_channels >= MESH_MAX_CHANNELS_PER_PEER {
            return None;
        }
        entry.live_channels += 1;
        Some(entry.bucket.clone())
    }

    /// Wire a DataChannel's lifecycle: on open, register it as a live link; on message, forward the
    /// bytes to the inbound sink tagged with the peer id.
    ///
    /// Returns false if this peer already holds MESH_MAX_CHANNELS_PER_PEER live channels, in which
    /// case NOTHING is wired and the caller must close the channel.
    async fn register_channel(&self, peer_id: String, dc: Arc<RTCDataChannel>) -> bool {
        let inbound = self.inbound_tx.clone();
        let peer_for_msg = peer_id.clone();
        // The rate limiter is looked up PER PEER and shared by every channel that peer opens — it
        // is deliberately not constructed here. Constructing it per channel handed a remote one
        // full budget per DataChannel, and nothing caps how many it may open.
        let Some(bucket) = self.acquire_ingress_slot(&peer_id).await else {
            return false;
        };

        // Release the slot when the channel closes, so a peer that legitimately re-opens over a
        // long-lived connection can't be wedged at the cap by a monotonic counter. The bucket
        // itself deliberately SURVIVES the close: dropping it per channel would restore the full
        // burst on every re-open and hand back the bypass this fix removes. It is dropped with the
        // peer in forget_if_current/shutdown.
        let ingress_for_close = self.ingress.clone();
        let peer_for_close = peer_id.clone();
        dc.on_close(Box::new(move || {
            let ingress = ingress_for_close.clone();
            let peer = peer_for_close.clone();
            Box::pin(async move {
                if let Some(entry) = ingress.lock().await.get_mut(&peer) {
                    entry.live_channels = entry.live_channels.saturating_sub(1);
                }
            })
        }));

        dc.on_message(Box::new(move |msg: DcMessage| {
            let inbound = inbound.clone();
            let peer = peer_for_msg.clone();
            let bucket = bucket.clone();
            Box::pin(async move {
                // Size cap (same 4 MiB frame limit as the TCP path), per-peer rate limit, then a
                // NON-blocking try_send into the bounded queue: a flooding peer is dropped at ingress
                // and can neither OOM the node nor starve other peers' blocks.
                let len = msg.data.len();
                if len == 0 || len > crate::a9::node::MAX_MESSAGE_SIZE {
                    return;
                }
                {
                    let allowed = bucket.lock().map(|mut b| b.allow()).unwrap_or(false);
                    if !allowed {
                        return;
                    }
                }
                let _ = inbound.try_send((peer, msg.data.to_vec()));
            })
        }));
        let channels = self.channels.clone();
        let backoff = self.dial_backoff.clone();
        // WEAK ref to the channel: a channel that NEVER opens (failed hole-punch) must not be pinned
        // alive by its own on_open handler, or it leaks when its pc is torn down.
        let dc_weak = Arc::downgrade(&dc);
        let peer_for_open = peer_id.clone();
        dc.on_open(Box::new(move || {
            let channels = channels.clone();
            let backoff = backoff.clone();
            let dc_weak = dc_weak.clone();
            let peer = peer_for_open.clone();
            Box::pin(async move {
                if let Some(dc) = dc_weak.upgrade() {
                    channels.lock().await.insert(peer.clone(), dc);
                    // The channel is live — this peer connected, so clear any dial backoff.
                    backoff.lock().await.remove(&peer);
                    // Operator-visible proof that a DIRECT peer-to-peer link hole-punched (as opposed
                    // to falling back to the gateway relay). This is the signal to watch in a real
                    // two-network test.
                    log::info!("mesh: direct link UP to {}…", &peer[..8.min(peer.len())]);
                }
            })
        }));
        true
    }

    /// Create a peer connection and, for the responder side, capture the inbound DataChannel.
    async fn new_pc(self: &Arc<Self>, peer_id: &str) -> Result<Arc<RTCPeerConnection>, String> {
        let pc = new_peer_connection(&self.api, self.config.clone())
            .await
            .map_err(|e| e.to_string())?;
        // Responder path: the remote opened the channel; wire it when it arrives. Hold a WEAK ref
        // to self — the pc is stored in self.conns and this callback lives on the pc, so a strong
        // ref would form a cycle that never frees the mesh on a long-running node.
        let me = Arc::downgrade(self);
        let peer = peer_id.to_string();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let me = me.clone();
            let peer = peer.clone();
            Box::pin(async move {
                if let Some(me) = me.upgrade() {
                    // Over the per-peer channel cap: wire no message handler (so it can never
                    // deliver anything or draw on the peer's budget) and close it.
                    if !me.register_channel(peer.clone(), Arc::clone(&dc)).await {
                        log::debug!(
                            "mesh: refusing excess DataChannel from {}…",
                            &peer[..8.min(peer.len())]
                        );
                        // Closing HERE would be a partial no-op: this callback runs BEFORE the
                        // SCTP stream is attached (sctp_transport::accept_data_channels invokes
                        // on_data_channel, and only then handle_open), so RTCDataChannel::close
                        // takes its `data_channel == None` path and the stream is attached a
                        // moment later regardless. handle_open sets the stream and THEN fires
                        // on_open, so closing from there actually tears it down. Weak ref for the
                        // same reason as the normal on_open below — a strong self-reference would
                        // pin a never-opened channel alive past its pc.
                        let dc_weak = Arc::downgrade(&dc);
                        dc.on_open(Box::new(move || {
                            let dc_weak = dc_weak.clone();
                            Box::pin(async move {
                                if let Some(dc) = dc_weak.upgrade() {
                                    let _ = dc.close().await;
                                }
                            })
                        }));
                    }
                }
            })
        }));
        // Drop dead connections from the maps so they can be re-dialed — and CLOSE them (webrtc 0.17
        // has no Drop, so without close() the ICE agent + UDP socket leak). Capture WEAK refs to both
        // the mesh and THIS pc: the removal is identity-checked (forget_if_current), so a stale
        // callback that fires after a concurrent re-dial rebound this id to a fresh pc is a no-op and
        // can't evict the newer connection (ABA).
        let mesh_weak = Arc::downgrade(self);
        let pc_weak = Arc::downgrade(&pc);
        let peer2 = peer_id.to_string();
        pc.on_peer_connection_state_change(Box::new(move |s| {
            use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as St;
            let mesh_weak = mesh_weak.clone();
            let pc_weak = pc_weak.clone();
            let peer2 = peer2.clone();
            Box::pin(async move {
                if !matches!(s, St::Failed | St::Closed) {
                    // Disconnected is TRANSIENT (brief packet loss / NAT rebind): ICE often recovers
                    // to Connected with the DataChannel still open. Tearing down here would drop a
                    // live link (silent gossip black hole). Leave it; the reaper closes it only if it
                    // stays un-Connected past MESH_STALE_SECS, and ICE itself escalates to Failed.
                    return;
                }
                if let (Some(mesh), Some(pc)) = (mesh_weak.upgrade(), pc_weak.upgrade()) {
                    mesh.on_terminal_pc_state(&peer2, &pc, matches!(s, St::Failed))
                        .await;
                }
            })
        }));
        {
            let mut conns = self.conns.lock().await;
            // If the kill switch shut us down while this pc was being built, don't track it (nothing
            // would ever close it) — close it now and bail.
            if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
                drop(conns);
                let _ = pc.close().await;
                return Err("mesh shut down".to_string());
            }
            // Enforce the connection cap under the SAME lock as the insert. dial()/handle_offer()
            // check len < MESH_MAX_CONNS and then drop the lock before we re-take it here, so
            // concurrent dials/offers could each pass that outer check and all insert, blowing the
            // bound (unbounded RTCPeerConnections/UDP sockets). The !contains_key guard keeps a
            // re-insert for an existing peer (which doesn't grow len) from being spuriously rejected.
            if !conns.contains_key(peer_id) && conns.len() >= MESH_MAX_CONNS {
                drop(conns);
                let _ = pc.close().await;
                return Err("mesh at capacity".to_string());
            }
            conns.insert(
                peer_id.to_string(),
                PeerConn {
                    pc: pc.clone(),
                    created: Instant::now(),
                },
            );
        }
        Ok(pc)
    }

    /// Initiate a connection IF we are the impolite (lower-id) side. Idempotent: skips peers we're
    /// already connecting to / connected to.
    pub async fn dial(self: &Arc<Self>, peer_id: &str) -> Result<(), String> {
        if peer_id == self.local_id() {
            return Ok(());
        }
        if self.local_id() >= peer_id {
            return Ok(()); // polite side waits for the offer
        }
        if !self.dial_allowed(peer_id).await {
            return Ok(()); // in backoff after recent failures — don't hammer an unreachable peer
        }
        if self.conns.lock().await.contains_key(peer_id) {
            return Ok(());
        }
        if self.conns.lock().await.len() >= MESH_MAX_CONNS {
            return Ok(());
        }
        let pc = self.new_pc(peer_id).await?;
        // Any failure after the pc is in `conns` must close + remove it. A half-open offerer never
        // reaches Failed on its own, so without this it would linger forever and blackhole the edge.
        match self.negotiate_offer(&pc, peer_id).await {
            Ok(()) => {
                self.touch().await;
                Ok(())
            }
            Err(e) => {
                self.remove_if_current_and_close(peer_id, &pc).await;
                self.note_dial_failure(peer_id).await;
                Err(e)
            }
        }
    }

    async fn negotiate_offer(
        self: &Arc<Self>,
        pc: &Arc<RTCPeerConnection>,
        peer_id: &str,
    ) -> Result<(), String> {
        let dc = pc
            .create_data_channel(MESH_CHANNEL_LABEL, Some(mesh_channel_init()))
            .await
            .map_err(|e| e.to_string())?;
        // Our own outbound channel; the cap can only bite if this peer already holds the maximum,
        // in which case the offer is pointless.
        if !self.register_channel(peer_id.to_string(), dc).await {
            return Err("mesh: peer already at the channel cap".to_string());
        }
        let offer = pc.create_offer(None).await.map_err(|e| e.to_string())?;
        let offer = set_local_and_gather(pc, offer)
            .await
            .map_err(|e| e.to_string())?;
        self.transport
            .post_signal(peer_id, "offer", &offer.sdp)
            .await
    }

    /// Returns Ok(true) only if this offer ADVANCED a handshake (a fresh answer was posted). A dropped
    /// offer (wrong role / not in directory / already connected / at cap) returns Ok(false) so it does
    /// NOT reset the poll cadence — otherwise anyone could pin us fast with signed junk offers.
    async fn handle_offer(self: &Arc<Self>, from: &str, sdp: &str) -> Result<bool, String> {
        // Perfect negotiation: only the polite (higher-id) side accepts an inbound offer.
        if self.local_id() < from {
            return Ok(false);
        }
        if self.conns.lock().await.contains_key(from) {
            return Ok(false); // already have a connection to this peer
        }
        // Anti-DoS: only accept offers from peers actually in the gateway directory (once we've
        // fetched it), and cap total connections. Otherwise a spammer with throwaway lower-id keys
        // could force unbounded RTCPeerConnections + STUN gathers.
        {
            let known = self.known_peers.lock().await;
            if !known.is_empty() && !known.contains(from) {
                return Ok(false);
            }
        }
        if self.conns.lock().await.len() >= MESH_MAX_CONNS {
            return Ok(false);
        }
        // Throttle a peer whose negotiations keep failing: each accepted offer spins up a full
        // RTCPeerConnection + STUN gather, so unbounded retries are a resource drain. Reuse the
        // exponential dial backoff — we are the polite (higher-id) side here and by construction
        // never dial `from`, so a backoff entry on `from` gates only this offer path.
        if !self.dial_allowed(from).await {
            return Ok(false);
        }
        let pc = self.new_pc(from).await?;
        match self.negotiate_answer(&pc, from, sdp).await {
            Ok(()) => Ok(true),
            Err(e) => {
                self.remove_if_current_and_close(from, &pc).await;
                self.note_dial_failure(from).await;
                Err(e)
            }
        }
    }

    async fn negotiate_answer(
        self: &Arc<Self>,
        pc: &Arc<RTCPeerConnection>,
        from: &str,
        sdp: &str,
    ) -> Result<(), String> {
        let remote = RTCSessionDescription::offer(strip_local_candidates_from_sdp(sdp))
            .map_err(|e| e.to_string())?;
        pc.set_remote_description(remote)
            .await
            .map_err(|e| e.to_string())?;
        let answer = pc.create_answer(None).await.map_err(|e| e.to_string())?;
        let answer = set_local_and_gather(pc, answer)
            .await
            .map_err(|e| e.to_string())?;
        self.transport
            .post_signal(from, "answer", &answer.sdp)
            .await
    }

    /// Ok(true) only if the answer advanced a still-FORMING handshake. A stray answer to an
    /// already-connected pc is junk and must not reset the poll cadence.
    async fn handle_answer(&self, from: &str, sdp: &str) -> Result<bool, String> {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as St;
        let pc = self.conns.lock().await.get(from).map(|c| c.pc.clone());
        if let Some(pc) = pc {
            if matches!(pc.connection_state(), St::Connected) {
                return Ok(false);
            }
            let remote = RTCSessionDescription::answer(strip_local_candidates_from_sdp(sdp))
                .map_err(|e| e.to_string())?;
            pc.set_remote_description(remote)
                .await
                .map_err(|e| e.to_string())?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Ok(true) only if the candidate actually APPLIED to a still-forming handshake. Candidates are
    /// bundled non-trickle, so a `candidate` envelope is never legitimately emitted — but a connected
    /// peer could post signed junk ones every poll to pin the fast cadence, so a candidate on an
    /// already-connected pc (or one that fails to apply) counts as no work.
    async fn handle_candidate(&self, from: &str, cand: &str) -> Result<bool, String> {
        use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState as St;
        let pc = self.conns.lock().await.get(from).map(|c| c.pc.clone());
        if let Some(pc) = pc {
            if matches!(pc.connection_state(), St::Connected) {
                return Ok(false);
            }
            // Drop a trickle candidate pointing at a LAN/private address (same reason as the
            // remote-SDP filter): never feed it to the ICE agent to probe.
            if candidate_line_is_local(cand) {
                return Ok(false);
            }
            let init = RTCIceCandidateInit {
                candidate: cand.to_string(),
                ..Default::default()
            };
            return Ok(pc.add_ice_candidate(init).await.is_ok());
        }
        Ok(false)
    }

    /// Drain the mailbox once and dispatch each envelope to the right handler. Returns the number of
    /// envelopes processed. Does NOT touch()/wake: it runs INSIDE the poll loop, so self-waking would
    /// just re-enter immediately. Staying fast while a handshake is in flight is handled by
    /// has_forming_conns(); the poll loop is woken for NEW work only by EXTERNAL touches (a dial, a
    /// directory change, a lost lower-id link) — which is what keeps signed junk from pinning it.
    pub async fn poll_signals(self: &Arc<Self>) -> Result<usize, String> {
        let envelopes = self.transport.drain_signals().await?;
        let n = envelopes.len();
        for e in envelopes {
            let r = match e.kind.as_str() {
                "offer" => self.handle_offer(&e.from, &e.payload).await,
                "answer" => self.handle_answer(&e.from, &e.payload).await,
                "candidate" => self.handle_candidate(&e.from, &e.payload).await,
                _ => Ok(false),
            };
            if let Err(err) = r {
                let from_prefix: String = e.from.chars().take(8).collect();
                log::debug!(
                    "mesh signal {} from {} failed: {}",
                    e.kind,
                    from_prefix,
                    err
                );
            }
        }
        Ok(n)
    }

    /// Send bytes to one peer over its DataChannel. Returns false if not connected.
    pub async fn send_to(&self, peer_id: &str, data: &[u8]) -> bool {
        self.send_to_bytes(peer_id, &Bytes::copy_from_slice(data))
            .await
    }

    /// Zero-copy variant: the caller wraps the frame in `Bytes` once and every
    /// per-peer send is a refcount bump (same pattern `broadcast` has always used).
    pub async fn send_to_bytes(&self, peer_id: &str, data: &Bytes) -> bool {
        let dc = self.channels.lock().await.get(peer_id).cloned();
        if let Some(dc) = dc {
            dc.send(data).await.is_ok()
        } else {
            false
        }
    }

    /// Send bytes to every connected peer (the block flood over the mesh). Sends CONCURRENTLY with a
    /// per-peer timeout, so a single slow / backpressured DataChannel can't stall delivery to the
    /// other peers (or keep the spawned gossip task alive indefinitely).
    pub async fn broadcast(&self, data: &[u8]) -> usize {
        let channels: Vec<Arc<RTCDataChannel>> =
            self.channels.lock().await.values().cloned().collect();
        let bytes = Bytes::copy_from_slice(data);
        let sends = channels.into_iter().map(|dc| {
            let bytes = bytes.clone(); // Bytes clone is a refcount bump, not a data copy
            async move {
                matches!(
                    tokio::time::timeout(Duration::from_secs(5), dc.send(&bytes)).await,
                    Ok(Ok(_))
                )
            }
        });
        futures_util::future::join_all(sends)
            .await
            .into_iter()
            .filter(|ok| *ok)
            .count()
    }
}

/// Choose which peers this node should DIAL, given the full sorted directory. Perfect negotiation
/// makes the lower-id side the initiator, so we only ever dial ids GREATER than our own. Selecting
/// relative to `local_id` (not by absolute global rank) is what makes EVERY node form edges: the old
/// "take the 12 smallest ids" rule combined with "only dial higher ids" left every node but the ~13
/// lowest with zero mesh links.
///
/// The immediate successors guarantee full connectivity (each node links to its next-higher neighbor
/// → one connected chain over all N), and the remaining slots are spread across the higher id space
/// to add long-range shortcuts for low gossip diameter. `sorted_ids` MUST be ascending.
pub fn select_dial_targets(local_id: &str, sorted_ids: &[String], degree: usize) -> Vec<String> {
    if degree == 0 {
        return Vec::new();
    }
    let higher: Vec<&String> = sorted_ids
        .iter()
        .filter(|id| id.as_str() > local_id)
        .collect();
    if higher.len() <= degree {
        return higher.into_iter().cloned().collect();
    }
    // Nearest successors (guarantee connectivity) ...
    let near = (degree / 2).max(1);
    let mut out: Vec<String> = higher[..near].iter().map(|s| (*s).clone()).collect();
    // ... then evenly spread the rest across the remaining higher ids (low-diameter shortcuts).
    let rest = &higher[near..];
    let want = degree - near;
    if want > 0 && !rest.is_empty() {
        for i in 0..want {
            let idx = (i * rest.len()) / want;
            out.push(rest[idx].clone());
        }
    }
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;
    use webrtc::data_channel::data_channel_message::DataChannelMessage;
    use webrtc::data_channel::RTCDataChannel;

    fn gen_key() -> Zeroizing<Vec<u8>> {
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;
        Zeroizing::new(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref()
                .to_vec(),
        )
    }

    // A remote peer's candidates arrive un-vetted inside its SDP. The strip filter must drop
    // private/LAN connection-addresses (an internal-probe primitive) while preserving public
    // server-reflexive candidates so real connectivity survives.
    #[test]
    fn strip_local_candidates_keeps_public_srflx_drops_private_host() {
        let public = "a=candidate:1 1 udp 1677729535 8.8.8.8 3478 typ srflx raddr 0.0.0.0 rport 0";
        let private = "a=candidate:2 1 udp 2122260223 192.168.1.5 54321 typ host";
        let linklocal = "a=candidate:3 1 udp 2122260223 169.254.1.1 54321 typ host";
        let sdp = format!(
            "v=0\r\n{public}\r\n{private}\r\n{linklocal}\r\nm=application 9 UDP/DTLS/SCTP\r\n"
        );

        let out = strip_local_candidates_from_sdp(&sdp);
        assert!(
            out.contains("8.8.8.8"),
            "public srflx candidate must be preserved"
        );
        assert!(
            !out.contains("192.168.1.5"),
            "private host candidate must be stripped"
        );
        assert!(
            !out.contains("169.254.1.1"),
            "link-local candidate must be stripped"
        );
        assert!(
            out.contains("v=0") && out.contains("m=application"),
            "non-candidate lines survive"
        );

        // The per-line predicate: public passes, private/link-local are flagged local.
        assert!(!candidate_line_is_local(public));
        assert!(candidate_line_is_local(private));
        assert!(candidate_line_is_local(linklocal));
        // A trickle candidate string (no "a=" prefix) uses the same token-4 layout.
        assert!(candidate_line_is_local(
            "candidate:2 1 udp 2122260223 10.0.0.9 54321 typ host"
        ));
        assert!(!candidate_line_is_local(
            "candidate:1 1 udp 1677729535 8.8.8.8 3478 typ srflx"
        ));
    }

    // The topology guarantee that was broken before: with the OLD "dial the 12 globally-smallest ids"
    // rule, only ~13 nodes ever meshed. This proves the fixed relative selection yields a SINGLE
    // connected component (every node reachable) with no isolated node, across many network sizes —
    // the property "hundreds of miners actually mesh" depends on.
    #[test]
    fn dial_targets_yield_one_connected_component_at_every_size() {
        fn find(parent: &mut [usize], x: usize) -> usize {
            let mut root = x;
            while parent[root] != root {
                root = parent[root];
            }
            let mut cur = x;
            while parent[cur] != cur {
                let next = parent[cur];
                parent[cur] = root;
                cur = next;
            }
            root
        }

        for &n in &[2usize, 3, 5, 12, 13, 14, 25, 50, 200, 300] {
            // Deterministic, strictly-increasing 64-hex node_ids (fixed width => lexicographic order
            // matches numeric order, same as real hex pubkeys sorted by the gateway/dialer).
            let mut ids: Vec<String> = (0..n).map(|i| format!("{:064x}", i * 131 + 17)).collect();
            ids.sort();
            let index: HashMap<&str, usize> = ids
                .iter()
                .enumerate()
                .map(|(i, s)| (s.as_str(), i))
                .collect();
            let mut parent: Vec<usize> = (0..n).collect();
            let mut degree = vec![0usize; n];

            for id in &ids {
                let targets = select_dial_targets(id, &ids, 12);
                let a = index[id.as_str()];
                for t in &targets {
                    assert!(
                        t.as_str() > id.as_str(),
                        "n={n}: must only ever dial higher ids"
                    );
                    let b = index[t.as_str()];
                    degree[a] += 1;
                    degree[b] += 1;
                    let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
                    parent[ra] = rb;
                }
            }

            let root = find(&mut parent, 0);
            for (i, node_degree) in degree.iter().enumerate().take(n) {
                assert_eq!(
                    find(&mut parent, i),
                    root,
                    "n={n}: node {i} is in a separate component"
                );
                assert!(
                    *node_degree > 0,
                    "n={n}: node {i} is isolated (zero mesh edges)"
                );
            }
        }
    }

    /// Minimal in-process transport. These tests exercise the mesh's own bookkeeping and never
    /// signal, so they should not depend on an HTTP client at all.
    ///
    /// Constructing `HttpSignalTransport` builds a `reqwest::Client`, and under SOME feature
    /// unifications that resolve rustls with no crypto provider installed it panics outright
    /// ("No rustls crypto provider is configured") before the test can assert anything — observed
    /// with `--features webrtc_mesh` alone. Both CI configurations (default features, and
    /// `bootstrap_publisher,webrtc_mesh`) happen to pull in a provider, so the sibling tests below
    /// that still build one are green there; they are simply carrying a dependency they do not
    /// need. New tests should prefer this mock.
    struct NullSignalTransport {
        id: String,
    }

    #[async_trait::async_trait]
    impl SignalTransport for NullSignalTransport {
        fn local_node_id(&self) -> &str {
            &self.id
        }
        async fn post_signal(&self, _to: &str, _kind: &str, _payload: &str) -> Result<(), String> {
            Ok(())
        }
        async fn drain_signals(&self) -> Result<Vec<SignalEnvelope>, String> {
            Ok(Vec::new())
        }
    }

    fn test_mesh() -> Arc<WebRtcMesh> {
        let t: Arc<dyn SignalTransport> = Arc::new(NullSignalTransport { id: "0".repeat(64) });
        WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new())
            .unwrap()
            .0
    }

    // THE security property: a peer's inbound budget is MESH_MSG_RATE in total, not per channel.
    // The bucket used to be constructed inside register_channel, so a remote opening N
    // DataChannels on its one RTCPeerConnection got N full budgets and could flood the shared
    // MESH_INBOUND_CAP queue, starving every other peer's block and tx gossip.
    #[tokio::test]
    async fn mesh_rate_limit_is_shared_across_one_peers_channels() {
        let mesh = test_mesh();

        let first = mesh
            .acquire_ingress_slot("peer-a")
            .await
            .expect("first channel");
        let second = mesh
            .acquire_ingress_slot("peer-a")
            .await
            .expect("second channel");
        assert!(
            Arc::ptr_eq(&first, &second),
            "every channel from one peer must draw on the SAME bucket"
        );

        // Drain the burst through the first channel.
        let mut spent = 0u32;
        while first.lock().unwrap().allow() {
            spent += 1;
            assert!(spent < 10_000, "bucket must be exhaustible");
        }
        assert!(spent > 0, "a fresh bucket starts with budget");

        // The second channel must find it empty. Before the fix it held a fresh full burst.
        assert!(
            !second.lock().unwrap().allow(),
            "opening another channel must not reset the peer's inbound budget"
        );

        // Per-peer isolation still holds: a different peer is unaffected.
        let other = mesh
            .acquire_ingress_slot("peer-b")
            .await
            .expect("other peer");
        assert!(!Arc::ptr_eq(&first, &other));
        assert!(
            other.lock().unwrap().allow(),
            "one peer's flood must not consume another peer's budget"
        );
    }

    // Bounds the retained-channel leak: nothing caps how many DataChannels a remote may open on a
    // single connection, so the mesh caps them itself and closes the excess.
    #[tokio::test]
    async fn mesh_refuses_channels_past_the_per_peer_cap() {
        let mesh = test_mesh();

        for i in 0..MESH_MAX_CHANNELS_PER_PEER {
            assert!(
                mesh.acquire_ingress_slot("flooder").await.is_some(),
                "channel {i} is within the cap"
            );
        }
        assert!(
            mesh.acquire_ingress_slot("flooder").await.is_none(),
            "past the cap the channel is refused, and the caller closes it"
        );
        assert!(
            mesh.acquire_ingress_slot("innocent").await.is_some(),
            "the cap is per peer, so a flooder cannot lock anyone else out"
        );
    }

    // The limiter map must be bounded by LIVE peers, not by every peer id ever seen — otherwise
    // the fix for one unbounded-growth bug introduces another.
    #[tokio::test]
    async fn mesh_ingress_state_is_dropped_with_the_peer_connection() {
        let mesh = test_mesh();
        let peer = "peer-gone";
        let pc = mesh.new_pc(peer).await.unwrap();
        mesh.acquire_ingress_slot(peer).await.expect("slot");
        assert!(mesh.ingress.lock().await.contains_key(peer));

        assert!(mesh.forget_if_current(peer, &pc).await);
        assert!(
            !mesh.ingress.lock().await.contains_key(peer),
            "the rate limiter must not outlive its connection"
        );
    }

    // Guards the ABA fix: a stale pc's teardown (reaper or a late state-change callback) must NEVER
    // evict a fresh pc that a concurrent re-dial rebound to the same peer id.
    #[tokio::test]
    async fn forget_if_current_only_removes_the_matching_pc() {
        // Was built on HttpSignalTransport, which panics under `rustls-no-provider` before this
        // test could assert anything; the transport is irrelevant to the ABA property under test.
        let mesh = test_mesh();
        let peer = "peer-x";
        let pc1 = mesh.new_pc(peer).await.unwrap();
        // A re-dial rebinds `peer` to a fresh pc (HashMap insert replaces the entry).
        let pc2 = mesh.new_pc(peer).await.unwrap();
        assert!(!Arc::ptr_eq(&pc1, &pc2));
        // A stale callback holding pc1 must be a no-op now that pc2 owns the id.
        assert!(
            !mesh.forget_if_current(peer, &pc1).await,
            "stale pc1 must not evict current pc2"
        );
        assert!(
            mesh.conns.lock().await.contains_key(peer),
            "pc2 must still be tracked"
        );
        // The current pc removes correctly.
        assert!(
            mesh.forget_if_current(peer, &pc2).await,
            "current pc2 removes"
        );
        assert!(!mesh.conns.lock().await.contains_key(peer));
        let _ = pc1.close().await;
        let _ = pc2.close().await;
    }

    // Guards the poll-cadence fix: an unreachable peer backs off exponentially instead of re-dialing
    // every ~60s (each re-dial would otherwise pin the node at the fast signaling cadence).
    #[tokio::test]
    async fn dial_backoff_grows_after_failures() {
        let t: Arc<dyn SignalTransport> = Arc::new(
            HttpSignalTransport::new(gen_key(), "http://127.0.0.1:0".to_string()).unwrap(),
        );
        let (mesh, _rx) =
            WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new()).unwrap();
        assert!(mesh.dial_allowed("p").await, "no history -> allowed");
        mesh.note_dial_failure("p").await;
        assert!(
            !mesh.dial_allowed("p").await,
            "after a failure -> backing off"
        );
        mesh.note_dial_failure("p").await;
        assert_eq!(
            mesh.dial_backoff.lock().await.get("p").map(|e| e.0),
            Some(2),
            "consecutive failures are counted"
        );
    }

    // Guards the backoff-map bound: a peer that leaves the directory must not keep its backoff entry
    // forever (else the map grows without bound on a churning network).
    #[tokio::test]
    async fn set_known_peers_prunes_departed_backoff() {
        let t: Arc<dyn SignalTransport> = Arc::new(
            HttpSignalTransport::new(gen_key(), "http://127.0.0.1:0".to_string()).unwrap(),
        );
        let (mesh, _rx) =
            WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new()).unwrap();
        mesh.note_dial_failure("gone").await;
        mesh.note_dial_failure("stays").await;
        mesh.set_known_peers(&["stays".to_string(), "other".to_string()])
            .await;
        let b = mesh.dial_backoff.lock().await;
        assert!(
            b.contains_key("stays"),
            "still-advertised peer keeps its backoff"
        );
        assert!(!b.contains_key("gone"), "departed peer's backoff is pruned");
    }

    // M4: a reaped never-connected pc must record dial backoff regardless of which side offered.
    // The former `id > local` guard recorded backoff only for our OUTBOUND dials, so a low-id peer
    // that keeps offering but never completes hole-punch was never throttled — pinning the
    // signaling poll loop at its fast cadence and churning a fresh pc every reap window.
    #[tokio::test]
    async fn reap_stale_backs_off_responder_side_peers_too() {
        use std::time::{Duration, Instant};
        let t: Arc<dyn SignalTransport> = Arc::new(
            HttpSignalTransport::new(gen_key(), "http://127.0.0.1:0".to_string()).unwrap(),
        );
        let (mesh, _rx) =
            WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new()).unwrap();
        // A responder-side id: strictly LESS than our local id, so the old guard skipped it.
        let peer = "!".to_string();
        assert!(
            peer.as_str() < mesh.local_id(),
            "test peer id must sort below the local id to exercise the responder path"
        );

        mesh.new_pc(&peer).await.unwrap();
        // Age the connection past the stale window, leaving it New (never connected).
        {
            let mut conns = mesh.conns.lock().await;
            let entry = conns.get_mut(&peer).expect("pc is tracked");
            entry.created = Instant::now() - Duration::from_secs(MESH_STALE_SECS + 5);
        }

        assert!(mesh.dial_allowed(&peer).await, "no backoff before the reap");
        mesh.reap_stale().await;
        assert!(
            !mesh.dial_allowed(&peer).await,
            "a reaped never-connected responder-side pc must record dial backoff"
        );
        assert!(
            !mesh.conns.lock().await.contains_key(&peer),
            "the reaped pc is removed"
        );
    }

    // M3 companion: is_lan_or_local must fold an IPv4-mapped IPv6 address before classifying, so a
    // remote peer cannot smuggle ::ffff:<internal-ipv4> past the SDP candidate strip (an SSRF probe
    // toward internal/metadata hosts).
    #[test]
    fn is_lan_or_local_folds_ipv4_mapped_ipv6() {
        use std::net::{IpAddr, Ipv4Addr};
        let mapped =
            |a: u8, b: u8, c: u8, d: u8| IpAddr::V6(Ipv4Addr::new(a, b, c, d).to_ipv6_mapped());
        // Internal mapped addresses classify as LAN/local (stripped from a remote SDP).
        assert!(is_lan_or_local(mapped(169, 254, 169, 254))); // link-local cloud metadata
        assert!(is_lan_or_local(mapped(10, 0, 0, 1))); // RFC1918
                                                       // A mapped PUBLIC address is preserved (real connectivity unaffected).
        assert!(!is_lan_or_local(mapped(8, 8, 8, 8)));
    }

    // M4 (completion): the Failed state-change is the common pc teardown; forget_if_current removes
    // the pc before the reaper sees it, so backoff must be recorded there too. failed=true drops the
    // pc AND records backoff; failed=false (a normal Close) drops it WITHOUT backoff.
    #[tokio::test]
    async fn failed_pc_teardown_records_backoff() {
        let t: Arc<dyn SignalTransport> = Arc::new(
            HttpSignalTransport::new(gen_key(), "http://127.0.0.1:0".to_string()).unwrap(),
        );
        let (mesh, _rx) =
            WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new()).unwrap();

        // Failed teardown -> pc dropped AND backoff recorded.
        let peer = "peer-failed";
        let pc = mesh.new_pc(peer).await.unwrap();
        assert!(mesh.dial_allowed(peer).await, "no backoff before failure");
        mesh.on_terminal_pc_state(peer, &pc, true).await;
        assert!(
            !mesh.conns.lock().await.contains_key(peer),
            "failed pc is dropped"
        );
        assert!(
            !mesh.dial_allowed(peer).await,
            "a Failed teardown records dial backoff"
        );

        // Closed teardown (normal shutdown) -> pc dropped WITHOUT backoff.
        let peer2 = "peer-closed";
        let pc2 = mesh.new_pc(peer2).await.unwrap();
        mesh.on_terminal_pc_state(peer2, &pc2, false).await;
        assert!(
            !mesh.conns.lock().await.contains_key(peer2),
            "closed pc is dropped"
        );
        assert!(
            mesh.dial_allowed(peer2).await,
            "a normal Close does not back off"
        );
        let _ = pc2.close().await;
    }

    // In-memory signal transport for multi-node tests: a shared map of per-recipient mailboxes —
    // exactly the store-and-forward the gateway provides, minus the network + signatures (the node
    // trusts the gateway and never verifies inbound envelope signatures).
    struct MockTransport {
        id: String,
        boxes: Arc<std::sync::Mutex<HashMap<String, Vec<SignalEnvelope>>>>,
    }
    #[async_trait::async_trait]
    impl SignalTransport for MockTransport {
        fn local_node_id(&self) -> &str {
            &self.id
        }
        async fn post_signal(&self, to: &str, kind: &str, payload: &str) -> Result<(), String> {
            let env = SignalEnvelope {
                from: self.id.clone(),
                to: to.to_string(),
                kind: kind.to_string(),
                payload: payload.to_string(),
                ts: 0,
                signature: String::new(),
            };
            self.boxes
                .lock()
                .unwrap()
                .entry(to.to_string())
                .or_default()
                .push(env);
            Ok(())
        }
        async fn drain_signals(&self) -> Result<Vec<SignalEnvelope>, String> {
            Ok(self
                .boxes
                .lock()
                .unwrap()
                .remove(&self.id)
                .unwrap_or_default())
        }
    }

    // End-to-end multi-node proof: N meshes with a shared in-memory signal relay + real WebRTC over
    // loopback form a connected overlay via select_dial_targets, and a block sent to a connected peer
    // is delivered P2P. Exercises the whole dial/answer/topology stack with N>2 real nodes — the
    // "hundreds of miners actually mesh" property, minus real-internet NAT (which no local test can
    // prove; the gateway relay is the documented fallback for pairs that can't hole-punch). Ignored by
    // default (spins up N real ICE stacks over loopback); run explicitly.
    #[tokio::test]
    #[ignore]
    async fn multi_node_mesh_forms_and_delivers_over_loopback() {
        const N: usize = 4;
        let boxes = Arc::new(std::sync::Mutex::new(
            HashMap::<String, Vec<SignalEnvelope>>::new(),
        ));
        let mut ids: Vec<String> = (0..N).map(|i| format!("{:064x}", i * 7 + 3)).collect();
        ids.sort();

        let mut meshes = Vec::new();
        let mut rxs = Vec::new();
        for id in &ids {
            let t: Arc<dyn SignalTransport> = Arc::new(MockTransport {
                id: id.clone(),
                boxes: boxes.clone(),
            });
            let (mesh, rx) =
                WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new()).unwrap();
            mesh.set_known_peers(&ids).await;
            meshes.push(mesh);
            rxs.push(rx);
        }

        // Each node polls signaling and dials its selected targets until the overlay forms.
        for mesh in &meshes {
            let mesh = mesh.clone();
            let ids = ids.clone();
            tokio::spawn(async move {
                let local = mesh.local_id().to_string();
                for _ in 0..300 {
                    let _ = mesh.poll_signals().await;
                    for target in select_dial_targets(&local, &ids, 12) {
                        let _ = mesh.dial(&target).await;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            });
        }

        // Every node ends up with at least one DIRECT link (the overlay formed across all N).
        let formed = tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                let mut all = true;
                for mesh in &meshes {
                    if mesh.connected_peers().await.is_empty() {
                        all = false;
                        break;
                    }
                }
                if all {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        })
        .await;
        assert!(formed.is_ok(), "not every node formed a direct mesh link");

        // A block sent to one of node 0's connected peers is delivered P2P intact.
        let peers0 = meshes[0].connected_peers().await;
        assert!(!peers0.is_empty(), "node 0 has a direct peer");
        let target = peers0[0].clone();
        let target_idx = ids.iter().position(|id| *id == target).unwrap();
        assert!(
            meshes[0].send_to(&target, b"multi-block").await,
            "send to a connected peer"
        );
        let got = tokio::time::timeout(Duration::from_secs(5), rxs[target_idx].recv())
            .await
            .expect("no inbound message")
            .expect("channel closed");
        assert_eq!(
            &got.1, b"multi-block",
            "block delivered intact P2P across the overlay"
        );
    }

    // Proves the node's Rust Ed25519 signing + canonicalization is byte-compatible with the
    // gateway's verification (lib/signal.ts) against the LIVE deployment — the exact interop contract
    // the whole mesh depends on. Ignored by default (needs network); run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn rust_signaling_interops_with_live_gateway() {
        let base = std::env::var("GW").unwrap_or_else(|_| "https://alphanumeric.blue".to_string());
        let alice = HttpSignalTransport::new(gen_key(), base.clone()).unwrap();
        let bob = HttpSignalTransport::new(gen_key(), base).unwrap();
        let payload = "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\na=ice-ufrag:aB3\r\na=ice-pwd:secretpwd\r\n";

        alice
            .post_signal(&bob.node_id, "offer", payload)
            .await
            .expect("gateway accepted the Rust-signed offer");

        let drained = bob.drain_signals().await.expect("drain");
        assert_eq!(drained.len(), 1, "bob received exactly the offer");
        assert_eq!(
            drained[0].payload, payload,
            "payload preserved byte-for-byte"
        );
        assert_eq!(drained[0].from, alice.node_id, "from = alice");
        assert_eq!(drained[0].kind, "offer");

        let again = bob.drain_signals().await.expect("drain2");
        assert_eq!(again.len(), 0, "second drain empty (atomic clear)");
    }

    // THE CAPSTONE: two independent meshes, two keys, establish a DIRECT DataChannel purely through
    // the LIVE gateway signaling (offer -> answer, perfect-negotiation roles) and exchange a payload
    // over it. This is the entire mesh mechanism end-to-end — signing, mailbox, offer/answer, ICE,
    // DataChannel, message delivery. On one machine ICE uses host/loopback candidates; between two
    // NAT'd machines it hole-punches via the STUN srflx candidates gathered here. Ignored by default
    // (needs network + STUN + the live gateway); run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn two_meshes_connect_via_live_gateway_and_exchange_a_message() {
        let base = std::env::var("GW").unwrap_or_else(|_| "https://alphanumeric.blue".to_string());
        let t_a: Arc<dyn SignalTransport> =
            Arc::new(HttpSignalTransport::new(gen_key(), base.clone()).unwrap());
        let t_b: Arc<dyn SignalTransport> =
            Arc::new(HttpSignalTransport::new(gen_key(), base).unwrap());
        let a_id = t_a.local_node_id().to_string();
        let b_id = t_b.local_node_id().to_string();

        let (mesh_a, _rx_a) =
            WebRtcMesh::new(t_a, Arc::new(build_api(true).unwrap()), default_stun_urls()).unwrap();
        let (mesh_b, mut rx_b) =
            WebRtcMesh::new(t_b, Arc::new(build_api(true).unwrap()), default_stun_urls()).unwrap();

        // Both run their signaling loop.
        for m in [mesh_a.clone(), mesh_b.clone()] {
            tokio::spawn(async move {
                for _ in 0..120 {
                    let _ = m.poll_signals().await;
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
            });
        }

        // Both dial; perfect-negotiation makes the lexicographically-lower id the initiator.
        mesh_a.dial(&b_id).await.expect("dial b");
        mesh_b.dial(&a_id).await.expect("dial a");

        // Wait for the DataChannel to open on both ends.
        let opened = tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if !mesh_a.connected_peers().await.is_empty()
                    && !mesh_b.connected_peers().await.is_empty()
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        })
        .await;
        assert!(
            opened.is_ok(),
            "DataChannel did not open via gateway signaling in time"
        );

        // Alice pushes a "block" to Bob directly over the mesh.
        assert!(
            mesh_a.send_to(&b_id, b"mesh-block-payload").await,
            "send over channel"
        );
        let got = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
            .await
            .expect("no inbound message")
            .expect("inbound channel closed");
        assert_eq!(got.0, a_id, "message tagged with the sender's node_id");
        assert_eq!(
            &got.1, b"mesh-block-payload",
            "payload delivered intact P2P"
        );

        let _ = mesh_a.broadcast(b"x").await;
    }

    // Proves the whole DataChannel handshake end-to-end IN PROCESS (both peers local, SDP exchanged
    // directly instead of via the gateway): offerer opens a channel, they exchange offer/answer with
    // bundled candidates, ICE connects over loopback, and a message crosses the channel. This is the
    // exact machinery the mesh uses; only the SDP transport (here: a direct move; in prod: the signed
    // /api/signal mailbox) differs. If this passes, the Rust WebRTC theory is solid.
    #[tokio::test]
    async fn datachannel_handshake_delivers_a_message() {
        let api = build_api(true).expect("api");
        let offerer = new_peer_connection(&api, ice_config(&[]))
            .await
            .expect("offerer pc");
        let answerer = new_peer_connection(&api, ice_config(&[]))
            .await
            .expect("answerer pc");

        // Receiver side: when the answerer sees the channel, forward its messages to a queue.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        answerer.on_data_channel(Box::new(move |d: Arc<RTCDataChannel>| {
            let tx = tx.clone();
            Box::pin(async move {
                d.on_message(Box::new(move |msg: DataChannelMessage| {
                    let tx = tx.clone();
                    Box::pin(async move {
                        let _ = tx.send(msg.data.to_vec()).await;
                    })
                }));
            })
        }));

        // Offerer opens the channel and sends once it's open.
        let dc = offerer
            .create_data_channel(MESH_CHANNEL_LABEL, Some(mesh_channel_init()))
            .await
            .expect("data channel");
        let dc_send = dc.clone();
        dc.on_open(Box::new(move || {
            let dc_send = dc_send.clone();
            Box::pin(async move {
                let _ = dc_send.send(&Bytes::from_static(b"hello-mesh")).await;
            })
        }));

        // Offer (with gathered candidates) -> answerer.
        let offer = offerer.create_offer(None).await.expect("create offer");
        let offer = set_local_and_gather(&offerer, offer)
            .await
            .expect("gather offer");
        answerer
            .set_remote_description(offer)
            .await
            .expect("set remote offer");

        // Answer (with gathered candidates) -> offerer.
        let answer = answerer.create_answer(None).await.expect("create answer");
        let answer = set_local_and_gather(&answerer, answer)
            .await
            .expect("gather answer");
        offerer
            .set_remote_description(answer)
            .await
            .expect("set remote answer");

        // The channel should open and deliver the message within a few seconds over loopback ICE.
        let got = tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .expect("handshake timed out")
            .expect("channel closed");
        assert_eq!(&got, b"hello-mesh", "message crossed the DataChannel");

        let _ = offerer.close().await;
        let _ = answerer.close().await;
    }

    // Guards the internet-only ICE config against the one way it could silently break: a real node
    // uses build_api(false) (loopback OFF, mDNS off, LAN/private filtered), so its ONLY path to a
    // reachable candidate is the server-reflexive address STUN reflects back. This asserts that
    // config actually yields a srflx candidate, and that NO candidate advertises a LAN/private or
    // loopback connection-address (no local-network access, no leak). Needs reachable public STUN.
    #[tokio::test]
    #[ignore]
    async fn production_config_gathers_public_candidate_and_leaks_no_lan() {
        let api = build_api(false).expect("api");
        let pc = new_peer_connection(&api, ice_config(&default_stun_urls()))
            .await
            .expect("pc");
        let _dc = pc
            .create_data_channel(MESH_CHANNEL_LABEL, Some(mesh_channel_init()))
            .await
            .expect("dc");
        let offer = pc.create_offer(None).await.expect("offer");
        let offer = set_local_and_gather(&pc, offer).await.expect("gather");
        let sdp = offer.sdp;

        assert!(
            sdp.contains("typ srflx"),
            "production config gathered no server-reflexive candidate — internet-only mesh would \
             have no reachable path:\n{sdp}"
        );

        // Every candidate's connection-address (SDP token 4) must be public: no LAN, no loopback.
        for line in sdp.lines().filter(|l| l.contains("candidate:")) {
            let toks: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr) = toks.get(4) {
                if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
                    assert!(
                        !is_lan_or_local(ip),
                        "leaked a LAN/private candidate: {line}"
                    );
                    assert!(
                        !ip.is_loopback(),
                        "gathered a loopback candidate in prod: {line}"
                    );
                }
            }
        }
        let _ = pc.close().await;
    }
    /// The drain response contract is deliberately asymmetric: an omitted
    /// `envelopes` field is the gateway's valid "mailbox empty" answer, while a
    /// PRESENT but malformed one is a schema break that must surface. Collapsing
    /// both into an empty list — the previous `unwrap_or_default()` — meant a
    /// gateway contract change would silently disable mesh formation, costing
    /// propagation with no error, no log and no backoff.
    #[test]
    fn drain_response_tolerates_absence_but_rejects_malformed_envelopes() {
        let empty: DrainResponse = serde_json::from_str(r#"{"ok":true}"#)
            .expect("absent envelopes is a valid empty drain");
        assert!(empty.envelopes.is_empty());

        let ok: DrainResponse = serde_json::from_str(
            r#"{"envelopes":[{"from":"a","to":"b","kind":"offer","payload":"p","ts":1,"signature":"s"}]}"#,
        )
        .expect("well-formed envelope list must parse");
        assert_eq!(ok.envelopes.len(), 1);
        assert_eq!(ok.envelopes[0].kind, "offer");

        for malformed in [
            // `#[serde(default)]` covers an ABSENT field, not a present null — so an explicit
            // null is a schema break like any other. It is also the most likely SHAPE of that
            // break (a null DB column, or JSON.stringify({envelopes: null}), neither of which
            // omits the key the way `undefined` would), which is why it belongs here rather
            // than being waved through. It used to be asserted via `unwrap_or(empty)`, which
            // holds whichever way it deserializes and so could not fail.
            r#"{"ok":true,"envelopes":null}"#,
            r#"{"envelopes":"not-a-list"}"#,
            r#"{"envelopes":[{"from":"a"}]}"#,
            r#"{"envelopes":[{"from":"a","to":"b","kind":"offer","payload":"p","ts":"not-a-number","signature":"s"}]}"#,
            r#"{"envelopes":{"from":"a"}}"#,
        ] {
            assert!(
                serde_json::from_str::<DrainResponse>(malformed).is_err(),
                "malformed drain body must error rather than read as empty: {malformed}"
            );
        }
    }

    /// Unknown sibling fields must not break older nodes: the gateway has to be
    /// able to add response fields without a lockstep client release.
    #[test]
    fn drain_response_ignores_unknown_fields() {
        let parsed: DrainResponse =
            serde_json::from_str(r#"{"envelopes":[],"cursor":"x","server_time":42}"#)
                .expect("unknown fields must be ignored");
        assert!(parsed.envelopes.is_empty());
    }
}
