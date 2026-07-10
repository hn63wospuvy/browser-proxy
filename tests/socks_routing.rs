//! Integration tests for SOCKS5 routing: a fake in-process SOCKS5 proxy relays to a TCP echo
//! server, driven end-to-end through the real axum router over a Wisp WebSocket.

use std::sync::Arc;
use std::time::Duration;

use browser_proxy::config::Config;
use browser_proxy::route::parse_routes;
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
fn expect_binary(msg: Message) -> Vec<u8> {
    match msg {
        Message::Binary(b) => b,
        other => panic!("expected binary frame, got {other:?}"),
    }
}

async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
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

/// Minimal SOCKS5 proxy: no-auth, CONNECT only, ATYP 1/3/4. `reply_override`, when set,
/// makes it answer every CONNECT with that REP code and close (for failure tests).
async fn spawn_fake_socks(reply_override: Option<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            tokio::spawn(async move {
                // Greeting.
                let mut g = [0u8; 2];
                if c.read_exact(&mut g).await.is_err() {
                    return;
                }
                let mut methods = vec![0u8; g[1] as usize];
                let _ = c.read_exact(&mut methods).await;
                let _ = c.write_all(&[0x05, 0x00]).await; // choose no-auth

                // Request: VER CMD RSV ATYP ...
                let mut h = [0u8; 4];
                if c.read_exact(&mut h).await.is_err() {
                    return;
                }
                let dst_host = match h[3] {
                    0x01 => {
                        let mut a = [0u8; 4];
                        let _ = c.read_exact(&mut a).await;
                        std::net::IpAddr::from(a).to_string()
                    }
                    0x04 => {
                        let mut a = [0u8; 16];
                        let _ = c.read_exact(&mut a).await;
                        std::net::IpAddr::from(a).to_string()
                    }
                    0x03 => {
                        let mut l = [0u8; 1];
                        let _ = c.read_exact(&mut l).await;
                        let mut d = vec![0u8; l[0] as usize];
                        let _ = c.read_exact(&mut d).await;
                        String::from_utf8_lossy(&d).into_owned()
                    }
                    _ => return,
                };
                let mut p = [0u8; 2];
                let _ = c.read_exact(&mut p).await;
                let dst_port = u16::from_be_bytes(p);

                if let Some(rep) = reply_override {
                    // Reply with the forced error and a dummy BND (ATYP=1, 0.0.0.0:0).
                    let _ = c.write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return;
                }

                // Success path: connect to the real target, reply OK, then splice both ways.
                let upstream = match TcpStream::connect((dst_host.as_str(), dst_port)).await {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = c.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                        return;
                    }
                };
                let _ = c.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                let (mut cr, mut cw) = c.into_split();
                let (mut ur, mut uw) = upstream.into_split();
                let a = tokio::io::copy(&mut cr, &mut uw);
                let b = tokio::io::copy(&mut ur, &mut cw);
                let _ = tokio::join!(a, b);
            });
        }
    });
    port
}

async fn spawn_proxy_with_routes(spec: &str) -> u16 {
    let cfg = Config {
        routes: parse_routes(spec).unwrap(),
        ..Default::default()
    };
    let app = build_router(Arc::new(cfg), "static");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

#[tokio::test]
async fn routes_through_socks_to_echo() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let echo = spawn_echo().await;
        let socks = spawn_fake_socks(None).await;
        let spec = format!("test=socks5://127.0.0.1:{socks}");
        let proxy = spawn_proxy_with_routes(&spec).await;

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=test");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        let _ = expect_binary(ws.next().await.unwrap().unwrap()); // handshake CONTINUE

        ws.send(Message::Binary(connect_pkt(1, echo, "127.0.0.1")))
            .await
            .unwrap();
        ws.send(Message::Binary(data_pkt(1, b"hello socks")))
            .await
            .unwrap();

        let mut got = Vec::new();
        while got.len() < b"hello socks".len() {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            match f[0] {
                0x02 => {
                    assert_eq!(u32_le(&f[1..5]), 1);
                    got.extend_from_slice(&f[5..]);
                }
                0x03 => {}
                0x04 => panic!("unexpected CLOSE"),
                t => panic!("unexpected packet {t:#x}"),
            }
        }
        assert_eq!(got, b"hello socks");
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn unknown_route_is_rejected() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let proxy = spawn_proxy_with_routes("test=socks5://127.0.0.1:1").await;
        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=nope");
        // tungstenite surfaces a non-101 upgrade as an Http error; just assert it fails.
        assert!(
            connect_async(url.as_str()).await.is_err(),
            "expected upgrade to be refused"
        );
    })
    .await
    .expect("timed out");
}

#[tokio::test]
async fn socks_refused_closes_stream() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socks = spawn_fake_socks(Some(0x05)).await; // connection refused
        let spec = format!("test=socks5://127.0.0.1:{socks}");
        let proxy = spawn_proxy_with_routes(&spec).await;

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=test");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        let _ = expect_binary(ws.next().await.unwrap().unwrap());

        ws.send(Message::Binary(connect_pkt(3, 80, "example.com")))
            .await
            .unwrap();
        loop {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            if f[0] == 0x04 {
                assert_eq!(u32_le(&f[1..5]), 3);
                assert_eq!(f[5], 0x44, "REP=05 should map to R_REFUSED"); // R_REFUSED
                break;
            }
        }
    })
    .await
    .expect("timed out");
}

async fn spawn_silent_socks() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((c, _)) = listener.accept().await {
            // Hold the socket open and never speak SOCKS.
            tokio::spawn(async move {
                let _c = c;
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn silent_proxy_times_out() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let socks = spawn_silent_socks().await;
        let spec = format!("test=socks5://127.0.0.1:{socks}");
        let cfg = Config {
            routes: parse_routes(&spec).unwrap(),
            connect_timeout: Duration::from_secs(1), // short, so the test is fast
            ..Default::default()
        };
        let app = build_router(Arc::new(cfg), "static");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("ws://127.0.0.1:{proxy}/wisp/?route=test");
        let (mut ws, _) = connect_async(url.as_str()).await.expect("ws connect");
        let _ = expect_binary(ws.next().await.unwrap().unwrap());

        ws.send(Message::Binary(connect_pkt(5, 80, "example.com")))
            .await
            .unwrap();
        loop {
            let f = expect_binary(ws.next().await.unwrap().unwrap());
            if f[0] == 0x04 {
                assert_eq!(u32_le(&f[1..5]), 5);
                assert_eq!(f[5], 0x43, "silent proxy should map to R_TIMEOUT"); // R_TIMEOUT
                break;
            }
        }
    })
    .await
    .expect("timed out");
}
