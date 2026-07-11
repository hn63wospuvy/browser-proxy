//! The axum HTTP router: static assets + the `/wisp/` WebSocket endpoint.

use std::path::Path;
use std::sync::Arc;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::{HeaderName, HeaderValue, CACHE_CONTROL};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio::sync::Semaphore;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::config::Config;
use crate::dns::DnsResolver;
use crate::route::DIRECT;
use crate::{metrics, wisp};

/// Cap on a single WebSocket message / frame. Wisp DATA frames from the real client are
/// ~16 KiB; this stops a hostile client from sending a single multi-MiB frame.
const MAX_WS_MESSAGE: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    /// Limits concurrent Wisp connections; a permit is held for each connection's lifetime.
    conn_sem: Arc<Semaphore>,
}

/// Assemble routes: `/wisp/` WebSocket, the three vendored asset trees, and the frontend
/// as the fallback. Cross-origin-isolation headers are attached to every response.
pub fn build_router(cfg: Arc<Config>, static_dir: &str) -> Router {
    let sd = |sub: &str| {
        ServeDir::new(Path::new(static_dir).join(sub)).append_index_html_on_directories(false)
    };

    let state = AppState {
        conn_sem: Arc::new(Semaphore::new(cfg.max_connections)),
        cfg,
    };

    Router::new()
        // Route and DNS are PATH segments, not query params, so the WebSocket URL keeps its
        // trailing slash — the libcurl client rejects a URL that doesn't end in `/`.
        // `/wisp/<route>/<dns>/` selects both; the shorter forms default DNS to `system`.
        .route("/wisp/", get(ws_handler_direct))
        .route("/wisp", get(ws_handler_direct))
        .route("/wisp/:route/", get(ws_handler_named))
        .route("/wisp/:route", get(ws_handler_named))
        .route("/wisp/:route/:dns/", get(ws_handler_route_dns))
        .route("/wisp/:route/:dns", get(ws_handler_route_dns))
        .route("/debug/stats", get(stats_handler))
        .route("/routes.json", get(routes_handler))
        .route("/dns.json", get(dns_handler))
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
        .with_state(state)
}

/// A layer that unconditionally sets `name: value` on every response.
fn header_layer(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    )
}

/// `/wisp/` (and `/wisp`): the default `direct` route, default DNS.
async fn ws_handler_direct(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    upgrade_wisp(ws, state, DIRECT, None).await
}

/// `/wisp/<route>/`: a named route selected by path segment, default DNS.
async fn ws_handler_named(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    AxumPath(route): AxumPath<String>,
) -> Response {
    upgrade_wisp(ws, state, &route, None).await
}

/// `/wisp/<route>/<dns>/`: a named route plus an explicit DNS resolver, both by path segment.
async fn ws_handler_route_dns(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    AxumPath((route, dns)): AxumPath<(String, String)>,
) -> Response {
    upgrade_wisp(ws, state, &route, Some(dns)).await
}

async fn upgrade_wisp(
    ws: WebSocketUpgrade,
    state: AppState,
    route_name: &str,
    dns_name: Option<String>,
) -> Response {
    tracing::debug!(route = %route_name, dns = ?dns_name, "wisp upgrade");
    // Resolve the requested route BEFORE acquiring a connection permit, so a bad request
    // doesn't consume a slot. Unknown route → 400, never a silent direct fallback.
    let route = match state.cfg.routes.get(route_name) {
        Some(r) => r.clone(), // clones the Arc<Route>, not the Route
        None => {
            return (StatusCode::BAD_REQUEST, format!("unknown route: {route_name}"))
                .into_response();
        }
    };

    // Resolve the DNS selection: a preset name → that resolver; a bare IP → an on-the-fly UDP
    // resolver for that server; anything else → 400 (fail-closed). An absent DNS segment uses the
    // server default (`system` — the OS resolver, i.e. no interference).
    let resolver: Arc<DnsResolver> = match &dns_name {
        Some(name) => {
            if let Some(r) = state.cfg.dns.get(name) {
                r.clone()
            } else if let Ok(ip) = name.parse::<std::net::IpAddr>() {
                match crate::dns::build_ip_resolver(ip) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(dns = %name, error = %e, "failed to build IP resolver");
                        return (StatusCode::INTERNAL_SERVER_ERROR, "dns resolver build failed")
                            .into_response();
                    }
                }
            } else {
                return (StatusCode::BAD_REQUEST, format!("unknown dns: {name}")).into_response();
            }
        }
        None => state
            .cfg
            .dns
            .get(&state.cfg.default_dns)
            .cloned()
            .unwrap_or_else(|| Arc::new(DnsResolver::System)),
    };

    // Reject the upgrade if we're already at the connection cap.
    let permit = match state.conn_sem.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            metrics::inc(&metrics::connections_rejected_maxconn);
            return (StatusCode::SERVICE_UNAVAILABLE, "too many connections").into_response();
        }
    };

    let cfg = state.cfg.clone();
    ws.max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |socket| async move {
            // Hold the permit for the whole connection; released when this future ends.
            let _permit = permit;
            wisp::handle_connection(socket, cfg, route, resolver).await;
        })
}

/// List the configured route names as JSON. `direct` is sorted first so the UI shows it as
/// the default; the rest are alphabetical for stable output.
async fn routes_handler(State(state): State<AppState>) -> Response {
    let mut names: Vec<&String> = state.cfg.routes.keys().collect();
    names.sort_by(|a, b| (a.as_str() != DIRECT, a.as_str()).cmp(&(b.as_str() != DIRECT, b.as_str())));
    let items = names
        .iter()
        .map(|n| format!("{n:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!("{{\"routes\":[{items}]}}");
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// List the configured DNS resolver names as JSON, with the server default sorted first and
/// echoed as `default` so the UI can preselect it. Mirrors `/routes.json`.
async fn dns_handler(State(state): State<AppState>) -> Response {
    let default = state.cfg.default_dns.as_str();
    let mut names: Vec<&String> = state.cfg.dns.keys().collect();
    names.sort_by(|a, b| (a.as_str() != default, a.as_str()).cmp(&(b.as_str() != default, b.as_str())));
    let items = names
        .iter()
        .map(|n| format!("{n:?}"))
        .collect::<Vec<_>>()
        .join(",");
    let body = format!("{{\"dns\":[{items}],\"default\":{default:?}}}");
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

async fn stats_handler() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        metrics::snapshot_json(),
    )
        .into_response()
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
