//! WebRTC DataChannel transport for the NAT-traversal mesh (feature `webrtc_mesh`).
//!
//! Every miner is behind residential NAT with no open inbound port, so direct libp2p-tcp never
//! connects and everything falls back to the slow serverless gateway relay. WebRTC fixes this: two
//! NAT'd peers exchange a one-time SDP offer/answer + ICE candidates through the gateway's signaling
//! mailbox (`/api/signal`), then ICE hole-punches a DIRECT, encrypted DataChannel between them —
//! and blocks flow peer-to-peer off the gateway entirely. This module owns the RTCPeerConnection /
//! DataChannel plumbing; the gateway is only a dumb signaling relay, and every block still gets the
//! node's full PoW + ML-DSA validation, so this is a transport-only change.

#![cfg(feature = "webrtc_mesh")]

use std::sync::Arc;

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
    let _ = gather_complete.recv().await;
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
    key_pkcs8: Vec<u8>,
    http: reqwest::Client,
    gateway_base: String,
}

impl HttpSignalTransport {
    pub fn new(key_pkcs8: Vec<u8>, gateway_base: String) -> Result<Self, String> {
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
            return Err(format!("post_signal {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
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
            return Err(format!("drain {}: {}", resp.status(), resp.text().await.unwrap_or_default()));
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let envs = v.get("envelopes").cloned().unwrap_or(serde_json::Value::Null);
        Ok(serde_json::from_value(envs).unwrap_or_default())
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

/// A peer connection plus when we created it (for the stale reaper).
struct PeerConn {
    pc: Arc<RTCPeerConnection>,
    created: Instant,
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
        Self { tokens: burst, last: Instant::now(), rate, burst }
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
    /// inbound offers to peers actually announced on the gateway.
    pub async fn set_known_peers(&self, ids: &[String]) {
        let mut k = self.known_peers.lock().await;
        k.clear();
        k.extend(ids.iter().cloned());
    }

    /// Mark signaling activity now (a handshake in progress). The poll loop uses this to stay on the
    /// fast cadence while forming and back off hard once quiet.
    async fn touch(&self) {
        *self.last_signal.lock().await = Instant::now();
    }

    /// How long since the last signaling activity.
    pub async fn quiet_for(&self) -> Duration {
        self.last_signal.lock().await.elapsed()
    }

    /// Remove `peer_id` from both maps ONLY if it still maps to exactly `pc` (Arc identity). This is
    /// the guard against ABA: a stale callback or the reaper must never evict a NEWER pc that a
    /// concurrent re-dial bound to the same id. Returns whether it removed. Does NOT close.
    async fn forget_if_current(&self, peer_id: &str, pc: &Arc<RTCPeerConnection>) -> bool {
        let removed = {
            let mut conns = self.conns.lock().await;
            if conns.get(peer_id).map_or(false, |c| Arc::ptr_eq(&c.pc, pc)) {
                conns.remove(peer_id);
                true
            } else {
                false
            }
        };
        if removed {
            self.channels.lock().await.remove(peer_id);
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
        let local = self.local_id().to_string();
        for (id, pc) in stale {
            // Identity-checked: never evict a fresh pc a concurrent re-dial bound to this id.
            self.remove_if_current_and_close(&id, &pc).await;
            // A reaped never-connected pc means the dial to a peer we initiate to failed — back off.
            if id > local {
                self.note_dial_failure(&id).await;
            }
        }
    }

    /// Wire a DataChannel's lifecycle: on open, register it as a live link; on message, forward the
    /// bytes to the inbound sink tagged with the peer id.
    fn register_channel(&self, peer_id: String, dc: Arc<RTCDataChannel>) {
        let inbound = self.inbound_tx.clone();
        let peer_for_msg = peer_id.clone();
        // One token bucket per peer (this closure is this peer's only message handler).
        let bucket = Arc::new(std::sync::Mutex::new(TokenBucket::new(MESH_MSG_RATE, MESH_MSG_BURST)));
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
                }
            })
        }));
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
                    me.register_channel(peer, dc);
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
                    let was_current = mesh.forget_if_current(&peer2, &pc).await;
                    if matches!(s, St::Failed) && was_current {
                        // Close off-task: close() drives more state changes, so awaiting it inside
                        // this handler would re-enter synchronously.
                        tokio::spawn(async move {
                            let _ = pc.close().await;
                        });
                    }
                }
            })
        }));
        self.conns
            .lock()
            .await
            .insert(peer_id.to_string(), PeerConn { pc: pc.clone(), created: Instant::now() });
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
        self.register_channel(peer_id.to_string(), dc);
        let offer = pc.create_offer(None).await.map_err(|e| e.to_string())?;
        let offer = set_local_and_gather(pc, offer).await.map_err(|e| e.to_string())?;
        self.transport.post_signal(peer_id, "offer", &offer.sdp).await
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
        let pc = self.new_pc(from).await?;
        match self.negotiate_answer(&pc, from, sdp).await {
            Ok(()) => Ok(true),
            Err(e) => {
                self.remove_if_current_and_close(from, &pc).await;
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
        let remote = RTCSessionDescription::offer(sdp.to_string()).map_err(|e| e.to_string())?;
        pc.set_remote_description(remote).await.map_err(|e| e.to_string())?;
        let answer = pc.create_answer(None).await.map_err(|e| e.to_string())?;
        let answer = set_local_and_gather(pc, answer).await.map_err(|e| e.to_string())?;
        self.transport.post_signal(from, "answer", &answer.sdp).await
    }

    /// Ok(true) only if the answer matched an outstanding local offer (a real pc).
    async fn handle_answer(&self, from: &str, sdp: &str) -> Result<bool, String> {
        let pc = self.conns.lock().await.get(from).map(|c| c.pc.clone());
        if let Some(pc) = pc {
            let remote = RTCSessionDescription::answer(sdp.to_string()).map_err(|e| e.to_string())?;
            pc.set_remote_description(remote).await.map_err(|e| e.to_string())?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Ok(true) only if the candidate applied to an existing pc.
    async fn handle_candidate(&self, from: &str, cand: &str) -> Result<bool, String> {
        let pc = self.conns.lock().await.get(from).map(|c| c.pc.clone());
        if let Some(pc) = pc {
            let init = RTCIceCandidateInit {
                candidate: cand.to_string(),
                ..Default::default()
            };
            let _ = pc.add_ice_candidate(init).await;
            return Ok(true);
        }
        Ok(false)
    }

    /// Drain the mailbox once and dispatch each envelope to the right handler. Returns the number of
    /// envelopes processed. Resets the poll cadence ONLY if an envelope actually advanced a handshake
    /// (not merely arrived) — so signed junk can't hold the node at the fast cadence.
    pub async fn poll_signals(self: &Arc<Self>) -> Result<usize, String> {
        let envelopes = self.transport.drain_signals().await?;
        let n = envelopes.len();
        let mut worked = false;
        for e in envelopes {
            let r = match e.kind.as_str() {
                "offer" => self.handle_offer(&e.from, &e.payload).await,
                "answer" => self.handle_answer(&e.from, &e.payload).await,
                "candidate" => self.handle_candidate(&e.from, &e.payload).await,
                _ => Ok(false),
            };
            match r {
                Ok(true) => worked = true,
                Ok(false) => {}
                Err(err) => log::debug!(
                    "mesh signal {} from {} failed: {}",
                    e.kind,
                    &e.from[..8.min(e.from.len())],
                    err
                ),
            }
        }
        if worked {
            self.touch().await;
        }
        Ok(n)
    }

    /// Send bytes to one peer over its DataChannel. Returns false if not connected.
    pub async fn send_to(&self, peer_id: &str, data: &[u8]) -> bool {
        let dc = self.channels.lock().await.get(peer_id).cloned();
        if let Some(dc) = dc {
            dc.send(&Bytes::copy_from_slice(data)).await.is_ok()
        } else {
            false
        }
    }

    /// Send bytes to every connected peer (the block flood over the mesh).
    pub async fn broadcast(&self, data: &[u8]) -> usize {
        let channels: Vec<Arc<RTCDataChannel>> =
            self.channels.lock().await.values().cloned().collect();
        let bytes = Bytes::copy_from_slice(data);
        let mut sent = 0;
        for dc in channels {
            if dc.send(&bytes).await.is_ok() {
                sent += 1;
            }
        }
        sent
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
    let higher: Vec<&String> = sorted_ids.iter().filter(|id| id.as_str() > local_id).collect();
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

    fn gen_key() -> Vec<u8> {
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap().as_ref().to_vec()
    }

    // The topology guarantee that was broken before: with the OLD "dial the 12 globally-smallest ids"
    // rule, only ~13 nodes ever meshed. This proves the fixed relative selection yields a SINGLE
    // connected component (every node reachable) with no isolated node, across many network sizes —
    // the property "hundreds of miners actually mesh" depends on.
    #[test]
    fn dial_targets_yield_one_connected_component_at_every_size() {
        fn find(parent: &mut Vec<usize>, x: usize) -> usize {
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
            let index: HashMap<&str, usize> =
                ids.iter().enumerate().map(|(i, s)| (s.as_str(), i)).collect();
            let mut parent: Vec<usize> = (0..n).collect();
            let mut degree = vec![0usize; n];

            for id in &ids {
                let targets = select_dial_targets(id, &ids, 12);
                let a = index[id.as_str()];
                for t in &targets {
                    assert!(t.as_str() > id.as_str(), "n={n}: must only ever dial higher ids");
                    let b = index[t.as_str()];
                    degree[a] += 1;
                    degree[b] += 1;
                    let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
                    parent[ra] = rb;
                }
            }

            let root = find(&mut parent, 0);
            for i in 0..n {
                assert_eq!(find(&mut parent, i), root, "n={n}: node {i} is in a separate component");
                assert!(degree[i] > 0, "n={n}: node {i} is isolated (zero mesh edges)");
            }
        }
    }

    // Guards the ABA fix: a stale pc's teardown (reaper or a late state-change callback) must NEVER
    // evict a fresh pc that a concurrent re-dial rebound to the same peer id.
    #[tokio::test]
    async fn forget_if_current_only_removes_the_matching_pc() {
        let t: Arc<dyn SignalTransport> =
            Arc::new(HttpSignalTransport::new(gen_key(), "http://127.0.0.1:0".to_string()).unwrap());
        let (mesh, _rx) = WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new()).unwrap();
        let peer = "peer-x";
        let pc1 = mesh.new_pc(peer).await.unwrap();
        // A re-dial rebinds `peer` to a fresh pc (HashMap insert replaces the entry).
        let pc2 = mesh.new_pc(peer).await.unwrap();
        assert!(!Arc::ptr_eq(&pc1, &pc2));
        // A stale callback holding pc1 must be a no-op now that pc2 owns the id.
        assert!(!mesh.forget_if_current(peer, &pc1).await, "stale pc1 must not evict current pc2");
        assert!(mesh.conns.lock().await.contains_key(peer), "pc2 must still be tracked");
        // The current pc removes correctly.
        assert!(mesh.forget_if_current(peer, &pc2).await, "current pc2 removes");
        assert!(!mesh.conns.lock().await.contains_key(peer));
        let _ = pc1.close().await;
        let _ = pc2.close().await;
    }

    // Guards the poll-cadence fix: an unreachable peer backs off exponentially instead of re-dialing
    // every ~60s (each re-dial would otherwise pin the node at the fast signaling cadence).
    #[tokio::test]
    async fn dial_backoff_grows_after_failures() {
        let t: Arc<dyn SignalTransport> =
            Arc::new(HttpSignalTransport::new(gen_key(), "http://127.0.0.1:0".to_string()).unwrap());
        let (mesh, _rx) = WebRtcMesh::new(t, Arc::new(build_api(true).unwrap()), Vec::new()).unwrap();
        assert!(mesh.dial_allowed("p").await, "no history -> allowed");
        mesh.note_dial_failure("p").await;
        assert!(!mesh.dial_allowed("p").await, "after a failure -> backing off");
        mesh.note_dial_failure("p").await;
        assert_eq!(
            mesh.dial_backoff.lock().await.get("p").map(|e| e.0),
            Some(2),
            "consecutive failures are counted"
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
        assert_eq!(drained[0].payload, payload, "payload preserved byte-for-byte");
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
        assert!(opened.is_ok(), "DataChannel did not open via gateway signaling in time");

        // Alice pushes a "block" to Bob directly over the mesh.
        assert!(mesh_a.send_to(&b_id, b"mesh-block-payload").await, "send over channel");
        let got = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
            .await
            .expect("no inbound message")
            .expect("inbound channel closed");
        assert_eq!(got.0, a_id, "message tagged with the sender's node_id");
        assert_eq!(&got.1, b"mesh-block-payload", "payload delivered intact P2P");

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
        let offerer = new_peer_connection(&api, ice_config(&[])).await.expect("offerer pc");
        let answerer = new_peer_connection(&api, ice_config(&[])).await.expect("answerer pc");

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
        let offer = set_local_and_gather(&offerer, offer).await.expect("gather offer");
        answerer.set_remote_description(offer).await.expect("set remote offer");

        // Answer (with gathered candidates) -> offerer.
        let answer = answerer.create_answer(None).await.expect("create answer");
        let answer = set_local_and_gather(&answerer, answer).await.expect("gather answer");
        offerer.set_remote_description(answer).await.expect("set remote answer");

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
                    assert!(!is_lan_or_local(ip), "leaked a LAN/private candidate: {line}");
                    assert!(!ip.is_loopback(), "gathered a loopback candidate in prod: {line}");
                }
            }
        }
        let _ = pc.close().await;
    }
}
