//! Integration test: drive the real axum router over a WebSocket, speak Wisp v1, and prove
//! bytes are relayed to a target TCP socket and back.

use std::sync::Arc;
use std::time::Duration;

use browser_proxy::config::Config;
use browser_proxy::server::build_router;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

// --- Wisp packet helpers (mirror of the server's wire format) ---

fn connect_pkt(id: u32, port: u16, host: &str) -> Vec<u8> {
    let mut p = vec![0x01]; // CONNECT
    p.extend_from_slice(&id.to_le_bytes());
    p.push(0x01); // TCP
    p.extend_from_slice(&port.to_le_bytes());
    p.extend_from_slice(host.as_bytes());
    p
}

fn data_pkt(id: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x02]; // DATA
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(payload);
    p
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn expect_binary(msg: Message) -> Vec<u8> {
    match msg {
        Message::Binary(b) => b,
        other => panic!("expected binary Wisp frame, got {other:?}"),
    }
}

/// Start a TCP echo server; return its port.
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    port
}

/// Start the proxy router on an ephemeral port; return its port.
async fn spawn_proxy() -> u16 {
    let cfg = Arc::new(Config::default());
    let app = build_router(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

#[tokio::test]
async fn wisp_relays_tcp_echo() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let echo_port = spawn_echo().await;
        let proxy_port = spawn_proxy().await;

        let url = format!("ws://127.0.0.1:{proxy_port}/wisp/");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");

        // The server must greet with CONTINUE on stream 0 (Wisp v1 handshake).
        let greeting = expect_binary(ws.next().await.unwrap().unwrap());
        assert_eq!(greeting[0], 0x03, "first frame should be CONTINUE");
        assert_eq!(u32_le(&greeting[1..5]), 0, "handshake CONTINUE is stream 0");

        // Open a stream to the echo server and send data.
        ws.send(Message::Binary(connect_pkt(1, echo_port, "127.0.0.1")))
            .await
            .unwrap();
        ws.send(Message::Binary(data_pkt(1, b"hello wisp")))
            .await
            .unwrap();

        // Collect DATA frames for stream 1 until we've seen the echoed payload.
        let mut got = Vec::new();
        while got.len() < b"hello wisp".len() {
            let frame = expect_binary(ws.next().await.unwrap().unwrap());
            match frame[0] {
                0x02 => {
                    assert_eq!(u32_le(&frame[1..5]), 1);
                    got.extend_from_slice(&frame[5..]);
                }
                0x03 => { /* flow-control CONTINUE: ignore */ }
                0x04 => panic!("unexpected CLOSE while expecting echo"),
                t => panic!("unexpected packet type {t:#x}"),
            }
        }
        assert_eq!(got, b"hello wisp");
    })
    .await
    .expect("test timed out");
}

/// Relays a real HTTP request to example.com over the network. Ignored by default (needs
/// internet); run with `cargo test -- --ignored`.
#[tokio::test]
#[ignore]
async fn wisp_relays_real_http() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let proxy_port = spawn_proxy().await;
        let url = format!("ws://127.0.0.1:{proxy_port}/wisp/");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        let _ = expect_binary(ws.next().await.unwrap().unwrap()); // handshake CONTINUE

        ws.send(Message::Binary(connect_pkt(1, 80, "example.com")))
            .await
            .unwrap();
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        ws.send(Message::Binary(data_pkt(1, req.as_bytes())))
            .await
            .unwrap();

        let mut body = Vec::new();
        loop {
            let frame = expect_binary(ws.next().await.unwrap().unwrap());
            match frame[0] {
                0x02 => body.extend_from_slice(&frame[5..]),
                0x04 => break, // remote closed (Connection: close)
                _ => {}
            }
            if body.windows(8).any(|w| w == b"HTTP/1.1") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("HTTP/1.1"),
            "expected an HTTP status line, got: {:?}",
            &text[..text.len().min(120)]
        );
    })
    .await
    .expect("test timed out");
}

#[tokio::test]
async fn wisp_close_on_refused_connection() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let proxy_port = spawn_proxy().await;
        let url = format!("ws://127.0.0.1:{proxy_port}/wisp/");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");

        // Consume the handshake CONTINUE.
        let _ = expect_binary(ws.next().await.unwrap().unwrap());

        // Connect to a port that should refuse (nothing listens on 127.0.0.1:1).
        ws.send(Message::Binary(connect_pkt(7, 1, "127.0.0.1")))
            .await
            .unwrap();

        // Expect a CLOSE for stream 7 (refused/unreachable/timeout).
        loop {
            let frame = expect_binary(ws.next().await.unwrap().unwrap());
            if frame[0] == 0x04 {
                assert_eq!(u32_le(&frame[1..5]), 7);
                let reason = frame[5];
                assert!(
                    matches!(reason, 0x42..=0x44),
                    "expected an unreachable/timeout/refused reason, got {reason:#x}"
                );
                break;
            }
        }
    })
    .await
    .expect("test timed out");
}
