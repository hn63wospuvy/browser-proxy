//! The axum HTTP router: static assets + the `/wisp/` WebSocket endpoint.

use std::path::Path;
use std::sync::Arc;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::State;
use axum::http::header::{HeaderName, HeaderValue, CACHE_CONTROL};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::wisp;

/// Assemble routes: `/wisp/` WebSocket, the three vendored asset trees, and the frontend
/// as the fallback. Cross-origin-isolation headers are attached to every response.
pub fn build_router(cfg: Arc<Config>, static_dir: &str) -> Router {
    let sd = |sub: &str| {
        ServeDir::new(Path::new(static_dir).join(sub)).append_index_html_on_directories(false)
    };

    Router::new()
        .route("/wisp/", get(ws_handler))
        .route("/wisp", get(ws_handler))
        .nest_service("/scram", sd("scram"))
        .nest_service("/baremux", sd("baremux"))
        .nest_service("/libcurl", sd("libcurl"))
        .fallback_service(ServeDir::new(static_dir))
        // Cross-origin isolation: required so Scramjet/libcurl can use SharedArrayBuffer.
        .layer(header_layer("cross-origin-opener-policy", "same-origin"))
        .layer(header_layer("cross-origin-embedder-policy", "require-corp"))
        // Avoid stale service worker / assets.
        .layer(SetResponseHeaderLayer::if_not_present(
            CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(cfg)
}

/// A layer that unconditionally sets `name: value` on every response.
fn header_layer(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    )
}

async fn ws_handler(ws: WebSocketUpgrade, State(cfg): State<Arc<Config>>) -> Response {
    ws.on_upgrade(move |socket| wisp::handle_connection(socket, cfg))
}

/// Log a clear hint if the vendored client assets have not been fetched yet.
pub fn warn_if_assets_missing(static_dir: &str) {
    let probe = Path::new(static_dir).join("scram").join("scramjet.all.js");
    if !probe.exists() {
        tracing::warn!(
            "client assets not found at {}. Run `node scripts/fetch-assets.mjs` to vendor \
             Scramjet/bare-mux/libcurl before use.",
            probe.display()
        );
    }
}
