//! Integration test: an HTTP-CONNECT proxy relays to an echo server, driven through the real
//! router over a Wisp WebSocket.

use std::sync::Arc;
use std::time::Duration;

use browser_proxy::config::Config;
use browser_proxy::route::routes_from_yaml;
use browser_proxy::server::build_router;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

fn connect_pkt(id: u32, port: u16, host: &str) -> Vec<u8> {
    let mut p = vec![0x01];
    p.extend_from_slice(&id.to_le_bytes());
    p.push(0x01);
    p.extend_from_slice(&port.to_le_bytes());
    p.extend_from_slice(host.as_bytes());
    p
}
fn data_pkt(id: u32, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0x02];
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(payload);
    p
}
fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn expect_binary(m: Message) -> Vec<u8> {
    match m {
        Message::Binary(b) => b,
        o => panic!("want binary, got {o:?}"),
    }
}

async fn spawn_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                loop {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&b[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Fake HTTP CONNECT proxy: reads the request headers, dials the target, replies 200, splices.
async fn spawn_fake_http() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    match c.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => head.push(byte[0]),
                    }
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&head);
                let target = line.split_whitespace().nth(1).unwrap_or("").to_string();
                let up = match TcpStream::connect(&target).await {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        return;
                    }
                };
                let _ = c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                let (mut cr, mut cw) = c.into_split();
                let (mut ur, mut uw) = up.into_split();
                let _ = tokio::join!(
                    tokio::io::copy(&mut cr, &mut uw),
                    tokio::io::copy(&mut ur, &mut cw)
                );
            });
        }
    });
    port
}

async fn spawn_proxy(yaml: &str) -> u16 {
    let cfg = Config {
        routes: routes_from_yaml(yaml).unwrap(),
        ..Default::default()
    };
    let app = build_router(Arc::new(cfg), "static");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(l, app).await.unwrap();
    });
    port
}

#[tokio::test]
async fn routes_through_http_connect_to_echo() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let echo = spawn_echo().await;
        let http = spawn_fake_http().await;
        let yaml =
            format!("routes:\n  - name: web\n    type: http\n    address: \"127.0.0.1:{http}\"\n");
        let proxy = spawn_proxy(&yaml).await;

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=web");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws");
        let _ = expect_binary(ws.next().await.unwrap().unwrap());

        ws.send(Message::Binary(connect_pkt(1, echo, "127.0.0.1")))
            .await
            .unwrap();
        ws.send(Message::Binary(data_pkt(1, b"hi http")))
            .await
            .unwrap();

        let mut got = Vec::new();
        while got.len() < b"hi http".len() {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            match f[0] {
                0x02 => {
                    assert_eq!(u32_le(&f[1..5]), 1);
                    got.extend_from_slice(&f[5..]);
                }
                0x03 => {}
                0x04 => panic!("unexpected CLOSE"),
                t => panic!("packet {t:#x}"),
            }
        }
        assert_eq!(got, b"hi http");
    })
    .await
    .expect("timed out");
}
