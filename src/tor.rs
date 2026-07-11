//! Embedded Tor route: an in-process [`arti_client`] `TorClient` that dials arbitrary TCP (and
//! `.onion`) through the Tor network. One client per `type: tor` route, shared by every stream,
//! mirroring the shared `WgTunnel`. Construction is non-blocking (unbootstrapped + on-demand
//! bootstrap); a background task warms the bootstrap so a slow or failing Tor network degrades
//! this one route rather than blocking server startup.
//!
//! With arti's `tokio` feature (on by default) `DataStream` implements tokio's `AsyncRead` /
//! `AsyncWrite` directly, so it drops straight into `Conn` with no futures<->tokio bridge. Note:
//! `DataStream` buffers writes and only sends on flush, so the relay must flush after writing
//! (see `wisp::run_stream`).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{BootstrapBehavior, DataStream};

use crate::wisp::{R_TIMEOUT, R_UNREACHABLE};

/// The concrete arti client type used for `type: tor` routes.
pub type TorClient = arti_client::TorClient<tor_rtcompat::PreferredRuntime>;

/// Build a shared, non-bootstrapped Tor client and warm its bootstrap in the background.
///
/// Must be called inside a tokio runtime (the caller, `route::build_route`, already is — it runs
/// under `#[tokio::main]`). arti caches its directory state + keys under `data_dir`
/// (`<data_dir>/state`, `<data_dir>/cache`), created on demand.
pub fn build_client(data_dir: &Path) -> Result<Arc<TorClient>, String> {
    let cfg = TorClientConfigBuilder::from_directories(data_dir.join("state"), data_dir.join("cache"))
        .build()
        .map_err(|e| format!("tor config: {e}"))?;

    // `create_unbootstrapped` does no network I/O; it spawns arti's background daemon tasks and
    // returns immediately, like `WgTunnel::spawn`. `OnDemand` means the first request triggers
    // bootstrap if the warmup below hasn't finished yet. Returns an already-shared `Arc`.
    let client = arti_client::TorClient::builder()
        .config(cfg)
        .bootstrap_behavior(BootstrapBehavior::OnDemand)
        .create_unbootstrapped()
        .map_err(|e| format!("tor client init: {e}"))?;

    let warm = client.clone();
    tokio::spawn(async move {
        match warm.bootstrap().await {
            Ok(()) => tracing::info!("tor bootstrap complete"),
            Err(e) => tracing::warn!("tor bootstrap failed (route will retry on demand): {e}"),
        }
    });

    Ok(client)
}

/// Dial `host:port` through Tor, returning a tokio-compatible stream. Hostname resolution happens
/// at the exit relay (no DNS leaves this host); `.onion` targets are handled by arti. Coarse error
/// mapping: any connect failure → unreachable; the bounding timeout elapsing → timeout.
pub async fn connect(
    client: &TorClient,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<DataStream, u8> {
    match tokio::time::timeout(timeout, client.connect((host, port))).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => {
            tracing::debug!("tor connect {host}:{port} failed: {e}");
            Err(R_UNREACHABLE)
        }
        Err(_) => Err(R_TIMEOUT),
    }
}
