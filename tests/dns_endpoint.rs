//! HTTP-level tests for the DNS selection surface: the `/dns.json` listing and the fail-closed
//! `?dns=` handling on the Wisp upgrade. Offline — no name resolution happens (a resolver is only
//! used once a stream CONNECTs, which these tests never do).

use std::sync::Arc;

use browser_proxy::config::Config;
use browser_proxy::dns;
use browser_proxy::server::build_router;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::connect_async;

/// Start the proxy with the built-in DNS presets (SSRF guard off); return its port.
async fn spawn_proxy() -> u16 {
    spawn(false).await
}

/// Start the proxy with the given `block_private` setting; return its port.
async fn spawn(block_private: bool) -> u16 {
    let cfg = Config {
        dns: dns::build_defaults().expect("build dns defaults"),
        default_dns: dns::DEFAULT_DNS.to_string(),
        block_private,
        ..Config::default()
    };
    let app = build_router(Arc::new(cfg), "static");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

/// Minimal HTTP/1.1 GET returning the response body.
async fn http_get_body(port: u16, path: &str) -> String {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn dns_json_lists_presets_with_default_first() {
    let port = spawn_proxy().await;
    let body = http_get_body(port, "/dns.json").await;
    for name in ["system", "cloudflare", "google", "quad9"] {
        assert!(body.contains(&format!("\"{name}\"")), "missing {name} in {body}");
    }
    assert!(body.contains("\"default\":\"system\""), "default not echoed: {body}");
    // Default is sorted first in the list.
    assert!(
        body.find("\"system\"").unwrap() < body.find("\"cloudflare\"").unwrap(),
        "default should sort first: {body}"
    );
}

#[tokio::test]
async fn unknown_dns_is_rejected_fail_closed() {
    let port = spawn_proxy().await;
    // DNS is a path segment (`/wisp/<route>/<dns>/`) so the WebSocket URL keeps its trailing slash.
    let url = format!("ws://127.0.0.1:{port}/wisp/direct/bogus/");
    assert!(
        connect_async(url.as_str()).await.is_err(),
        "an unknown dns segment must be refused (400), not silently accepted"
    );
}

#[tokio::test]
async fn ip_dns_segment_upgrades_ok() {
    let port = spawn_proxy().await;
    // A bare IP (not a preset name) builds an on-the-fly UDP resolver; the upgrade succeeds
    // (no name resolution happens until a stream CONNECTs).
    let url = format!("ws://127.0.0.1:{port}/wisp/direct/1.1.1.1/");
    let (mut ws, _) = connect_async(url.as_str())
        .await
        .expect("a bare-IP dns segment should upgrade");
    let bytes = ws.next().await.unwrap().unwrap().into_data();
    assert_eq!(bytes[0], 0x03, "first frame should be CONTINUE");
}

#[tokio::test]
async fn private_dns_server_ip_blocked_when_block_private() {
    let port = spawn(true).await;
    // SSRF guard: with block_private on, a private DNS-server IP is refused before the upgrade.
    let url = format!("ws://127.0.0.1:{port}/wisp/direct/192.168.1.1/");
    assert!(
        connect_async(url.as_str()).await.is_err(),
        "a private dns-server IP must be blocked when block_private is on"
    );
    // A public DNS-server IP is still accepted.
    let url = format!("ws://127.0.0.1:{port}/wisp/direct/1.1.1.1/");
    assert!(
        connect_async(url.as_str()).await.is_ok(),
        "a public dns-server IP should still upgrade"
    );
}

#[tokio::test]
async fn known_dns_upgrades_ok() {
    let port = spawn_proxy().await;
    let url = format!("ws://127.0.0.1:{port}/wisp/direct/cloudflare/");
    let (mut ws, _) = connect_async(url.as_str())
        .await
        .expect("a known dns segment should upgrade");
    // Wisp v1 greets with CONTINUE on stream 0 — proof the upgrade succeeded.
    let msg = ws.next().await.unwrap().unwrap();
    let bytes = msg.into_data();
    assert_eq!(bytes[0], 0x03, "first frame should be CONTINUE");
}
