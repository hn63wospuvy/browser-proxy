//! WireGuard route integration: building a tunnel route from YAML, plus an ignored end-to-end
//! test that registers with the real Cloudflare WARP API and fetches a page through the tunnel.

use browser_proxy::route::routes_from_yaml;

// 44-char base64 of 32 zero bytes — a syntactically valid (if useless) WireGuard key.
const ZERO_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

#[tokio::test]
async fn builds_wireguard_route_from_yaml() {
    // A loopback endpoint resolves without DNS; the tunnel task starts and idles harmlessly.
    let yaml = format!(
        "routes:\n  - name: wg\n    type: wireguard\n    private_key: \"{ZERO_KEY}\"\n    \
         peer_public_key: \"{ZERO_KEY}\"\n    endpoint: \"127.0.0.1:2408\"\n    \
         address: \"172.16.0.2/32\"\n"
    );
    let m = routes_from_yaml(&yaml).expect("wireguard route should build");
    assert!(m.contains_key("wg"));
    assert!(m.contains_key("direct"));
}

#[tokio::test]
async fn rejects_wireguard_bad_key() {
    let yaml = "routes:\n  - name: wg\n    type: wireguard\n    private_key: \"not-base64!\"\n    \
                peer_public_key: \"x\"\n    endpoint: \"127.0.0.1:2408\"\n    address: \"172.16.0.2/32\"\n";
    assert!(routes_from_yaml(yaml).is_err());
}

// Registers with the real Cloudflare WARP API and fetches a page through the tunnel. Needs
// internet and may hit rate limits. Run with: cargo test --test wireguard -- --ignored
#[tokio::test]
#[ignore]
async fn warp_end_to_end() {
    use browser_proxy::config::Config;
    use browser_proxy::server::build_router;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::Arc;
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let yaml = "routes:\n  - name: warp\n    type: warp\n";
    let cfg = Config {
        routes: routes_from_yaml(yaml).unwrap(),
        ..Default::default()
    };
    let app = build_router(Arc::new(cfg));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });

    let url = format!("ws://127.0.0.1:{port}/wisp/warp/");
    let (mut ws, _) = connect_async(url.as_str()).await.unwrap();
    let _ = ws.next().await.unwrap().unwrap(); // handshake CONTINUE

    let mut cp = vec![0x01u8];
    cp.extend_from_slice(&1u32.to_le_bytes());
    cp.push(0x01);
    cp.extend_from_slice(&80u16.to_le_bytes());
    cp.extend_from_slice(b"example.com");
    ws.send(Message::Binary(cp)).await.unwrap();

    let req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let mut dp = vec![0x02u8];
    dp.extend_from_slice(&1u32.to_le_bytes());
    dp.extend_from_slice(req.as_bytes());
    ws.send(Message::Binary(dp)).await.unwrap();

    let mut body = Vec::new();
    while let Some(Ok(Message::Binary(f))) = ws.next().await {
        if f[0] == 0x02 {
            body.extend_from_slice(&f[5..]);
        }
        if f[0] == 0x04 {
            break;
        }
        if body.windows(8).any(|w| w == b"HTTP/1.1") {
            break;
        }
    }
    assert!(String::from_utf8_lossy(&body).contains("HTTP/1.1"));
}
