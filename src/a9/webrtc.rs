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

/// Build a webrtc API handle (data-channel only; no media codecs). Reused for all peer connections.
pub fn build_api() -> Result<API, webrtc::Error> {
    ensure_crypto_provider();
    let mut media = MediaEngine::default();
    let registry = register_default_interceptors(Registry::new(), &mut media)?;
    Ok(APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
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

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::time::Duration;
    use webrtc::data_channel::data_channel_message::DataChannelMessage;
    use webrtc::data_channel::RTCDataChannel;

    // Proves the whole DataChannel handshake end-to-end IN PROCESS (both peers local, SDP exchanged
    // directly instead of via the gateway): offerer opens a channel, they exchange offer/answer with
    // bundled candidates, ICE connects over loopback, and a message crosses the channel. This is the
    // exact machinery the mesh uses; only the SDP transport (here: a direct move; in prod: the signed
    // /api/signal mailbox) differs. If this passes, the Rust WebRTC theory is solid.
    #[tokio::test]
    async fn datachannel_handshake_delivers_a_message() {
        let api = build_api().expect("api");
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
}
