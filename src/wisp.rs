//! Wisp v1 server: multiplexes many TCP streams over a single WebSocket.
//!
//! Wire format (little-endian): `[type: u8][stream_id: u32][payload]`. One Wisp packet per
//! WebSocket binary message. Spec: <https://github.com/MercuryWorkshop/wisp-protocol/tree/v1>.
//!
//! Concurrency model (per WebSocket connection):
//! - one **writer task** owns the WS sink; every stream sends outgoing packets through a
//!   bounded channel to it (serializes writes, gives backpressure to slow clients);
//! - one **read loop** owns the WS stream and the stream table (single owner → no lock).
//!   It routes DATA to per-stream channels, and reaps finished streams via a `done` channel;
//! - one **stream task** per stream owns its TCP socket and relays both directions, sending
//!   CONTINUE packets as it drains client data to implement the flow-control window.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures_util::{sink::SinkExt, stream::StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::{is_private_ip, Config};

// Packet types.
const T_CONNECT: u8 = 0x01;
const T_DATA: u8 = 0x02;
const T_CONTINUE: u8 = 0x03;
const T_CLOSE: u8 = 0x04;

// Stream types (CONNECT payload).
const ST_TCP: u8 = 0x01;
const ST_UDP: u8 = 0x02;

// Close reasons.
const R_VOLUNTARY: u8 = 0x02;
const R_NETWORK: u8 = 0x03;
const R_INVALID: u8 = 0x41;
const R_UNREACHABLE: u8 = 0x42;
const R_TIMEOUT: u8 = 0x43;
const R_REFUSED: u8 = 0x44;
const R_BLOCKED: u8 = 0x48;

/// How many bytes of TCP payload we read per DATA packet toward the client.
const READ_CHUNK: usize = 16 * 1024;
/// Bound on the WS writer queue (packets). Provides global backpressure to slow clients.
const WS_WRITE_QUEUE: usize = 512;
/// Reject absurdly long hostnames in CONNECT.
const MAX_HOST_LEN: usize = 255;

/// A parsed Wisp packet borrowing from the WS frame buffer.
enum Packet<'a> {
    Connect {
        stream_id: u32,
        stream_type: u8,
        port: u16,
        host: &'a [u8],
    },
    Data {
        stream_id: u32,
        payload: &'a [u8],
    },
    Close {
        stream_id: u32,
    },
    /// CONTINUE (client → server) and any unknown type: accepted and ignored.
    Ignored,
}

fn parse_packet(buf: &[u8]) -> Option<Packet<'_>> {
    if buf.len() < 5 {
        return None;
    }
    let ptype = buf[0];
    let stream_id = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let payload = &buf[5..];
    match ptype {
        T_CONNECT => {
            if payload.len() < 3 {
                return None;
            }
            let stream_type = payload[0];
            let port = u16::from_le_bytes([payload[1], payload[2]]);
            let host = &payload[3..];
            Some(Packet::Connect {
                stream_id,
                stream_type,
                port,
                host,
            })
        }
        T_DATA => Some(Packet::Data { stream_id, payload }),
        T_CLOSE => Some(Packet::Close { stream_id }),
        T_CONTINUE => Some(Packet::Ignored),
        _ => Some(Packet::Ignored),
    }
}

fn data_packet(stream_id: u32, payload: &[u8]) -> Message {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(T_DATA);
    out.extend_from_slice(&stream_id.to_le_bytes());
    out.extend_from_slice(payload);
    Message::Binary(out)
}

fn continue_packet(stream_id: u32, buffer_remaining: u32) -> Message {
    let mut out = Vec::with_capacity(9);
    out.push(T_CONTINUE);
    out.extend_from_slice(&stream_id.to_le_bytes());
    out.extend_from_slice(&buffer_remaining.to_le_bytes());
    Message::Binary(out)
}

fn close_packet(stream_id: u32, reason: u8) -> Message {
    let mut out = Vec::with_capacity(6);
    out.push(T_CLOSE);
    out.extend_from_slice(&stream_id.to_le_bytes());
    out.push(reason);
    Message::Binary(out)
}

/// Table entry for a live stream, held only by the read loop.
struct StreamHandle {
    data_tx: mpsc::UnboundedSender<Bytes>,
    abort: tokio::task::AbortHandle,
}

/// Entry point: drive one Wisp connection to completion.
pub async fn handle_connection(socket: WebSocket, cfg: Arc<Config>) {
    let (mut sink, mut ws_stream) = socket.split();

    // Writer task: the single owner of the WS sink.
    let (ws_tx, mut ws_rx) = mpsc::channel::<Message>(WS_WRITE_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(msg) = ws_rx.recv().await {
            if sink.send(msg).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    // Announce Wisp v1 + the initial per-stream credit (stream id 0).
    if ws_tx
        .send(continue_packet(0, cfg.buffer_size))
        .await
        .is_err()
    {
        writer.abort();
        return;
    }

    let mut streams: HashMap<u32, StreamHandle> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<u32>();

    loop {
        tokio::select! {
            // A stream task finished on its own → reap its table entry.
            Some(id) = done_rx.recv() => {
                streams.remove(&id);
            }
            // Next frame from the client.
            msg = ws_stream.next() => {
                let msg = match msg {
                    Some(Ok(m)) => m,
                    _ => break, // closed or errored
                };
                let data = match msg {
                    Message::Binary(d) => d,
                    Message::Close(_) => break,
                    // Ping/Pong are handled by the WS layer; Text is not used by Wisp.
                    _ => continue,
                };
                let packet = match parse_packet(&data) {
                    Some(p) => p,
                    None => continue, // malformed frame: ignore, keep the connection alive
                };
                match packet {
                    Packet::Connect { stream_id, stream_type, port, host } => {
                        // Ignore a CONNECT that reuses a live stream id.
                        if streams.contains_key(&stream_id) {
                            continue;
                        }
                        if stream_type == ST_UDP {
                            let _ = ws_tx.send(close_packet(stream_id, R_INVALID)).await;
                            continue;
                        }
                        if stream_type != ST_TCP || host.len() > MAX_HOST_LEN {
                            let _ = ws_tx.send(close_packet(stream_id, R_INVALID)).await;
                            continue;
                        }
                        let host = match std::str::from_utf8(host) {
                            Ok(h) if !h.is_empty() => h.to_string(),
                            _ => {
                                let _ = ws_tx.send(close_packet(stream_id, R_INVALID)).await;
                                continue;
                            }
                        };

                        let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
                        let jh = tokio::spawn(run_stream(
                            stream_id,
                            host,
                            port,
                            data_rx,
                            ws_tx.clone(),
                            done_tx.clone(),
                            cfg.clone(),
                        ));
                        streams.insert(stream_id, StreamHandle { data_tx, abort: jh.abort_handle() });
                    }
                    Packet::Data { stream_id, payload } => {
                        if let Some(h) = streams.get(&stream_id) {
                            // Unbounded, non-blocking send: never head-of-line-blocks other
                            // streams. Memory is bounded by the CONTINUE credit window.
                            let _ = h.data_tx.send(Bytes::copy_from_slice(payload));
                        }
                    }
                    Packet::Close { stream_id } => {
                        if let Some(h) = streams.remove(&stream_id) {
                            h.abort.abort(); // tears down the TCP socket
                        }
                    }
                    Packet::Ignored => {}
                }
            }
        }
    }

    // Connection teardown: abort every remaining stream and stop the writer.
    for (_, h) in streams.drain() {
        h.abort.abort();
    }
    writer.abort();
}

/// Resolve + connect to the target, honoring the SSRF guard and blacklist.
/// Returns the connected socket, or a Wisp close reason on failure.
async fn connect_target(host: &str, port: u16, cfg: &Config) -> Result<TcpStream, u8> {
    if cfg.is_host_blacklisted(host) {
        return Err(R_BLOCKED);
    }

    let mut addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(it) => it.collect(),
        Err(_) => return Err(R_UNREACHABLE),
    };
    if cfg.block_private {
        addrs.retain(|a| !is_private_ip(&a.ip()));
    }
    if addrs.is_empty() {
        // Nothing resolved, or every result was filtered by the SSRF guard.
        return Err(if cfg.block_private { R_BLOCKED } else { R_UNREACHABLE });
    }

    let mut last = R_UNREACHABLE;
    for addr in addrs {
        match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(e)) => {
                last = match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => R_REFUSED,
                    _ => R_UNREACHABLE,
                };
            }
            Err(_) => last = R_TIMEOUT, // elapsed
        }
    }
    Err(last)
}

/// Relay one stream: connect, then pump both directions until either side ends.
async fn run_stream(
    stream_id: u32,
    host: String,
    port: u16,
    mut data_rx: mpsc::UnboundedReceiver<Bytes>,
    ws_tx: mpsc::Sender<Message>,
    done_tx: mpsc::UnboundedSender<u32>,
    cfg: Arc<Config>,
) {
    let tcp = match connect_target(&host, port, &cfg).await {
        Ok(s) => s,
        Err(reason) => {
            let _ = ws_tx.send(close_packet(stream_id, reason)).await;
            let _ = done_tx.send(stream_id);
            return;
        }
    };

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // How many packets to drain before topping the client's credit back up. Half the window
    // keeps the pipe full without letting more than ~buffer_size packets sit in flight.
    let refill_at = (cfg.buffer_size / 2).max(1);
    let credit = cfg.buffer_size;

    // Dedicated clones so each direction owns its sender; `ws_tx` stays for the final CLOSE.
    let ws_tx_cont = ws_tx.clone();
    let ws_tx_data = ws_tx.clone();

    // client → TCP: write request bytes, replenish credit as we drain.
    let client_to_tcp = async move {
        let mut processed: u32 = 0;
        while let Some(chunk) = data_rx.recv().await {
            if tcp_write.write_all(&chunk).await.is_err() {
                break;
            }
            processed += 1;
            if processed >= refill_at {
                processed = 0;
                // Backpressure: if the writer queue is full the client is slow, so blocking
                // here (and thus not crediting more) is the desired throttle.
                if ws_tx_cont.send(continue_packet(stream_id, credit)).await.is_err() {
                    break;
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    // TCP → client: stream response bytes back as DATA packets.
    let tcp_to_client = async move {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => return R_VOLUNTARY,          // server closed cleanly
                Ok(n) => {
                    if ws_tx_data.send(data_packet(stream_id, &buf[..n])).await.is_err() {
                        return R_NETWORK;             // client gone
                    }
                }
                Err(_) => return R_NETWORK,
            }
        }
    };

    // Whichever direction ends first ends the stream. The response direction decides the
    // close reason sent to the client; the request direction ending just means no more
    // request body, so we keep the reason neutral.
    let reason = tokio::select! {
        _ = client_to_tcp => R_VOLUNTARY,
        r = tcp_to_client => r,
    };

    let _ = ws_tx.send(close_packet(stream_id, reason)).await;
    let _ = done_tx.send(stream_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect_ok() {
        // type=CONNECT, id=1, stype=TCP, port=443, host="example.com"
        let mut p = vec![T_CONNECT, 1, 0, 0, 0, ST_TCP];
        p.extend_from_slice(&443u16.to_le_bytes());
        p.extend_from_slice(b"example.com");
        match parse_packet(&p).unwrap() {
            Packet::Connect { stream_id, stream_type, port, host } => {
                assert_eq!(stream_id, 1);
                assert_eq!(stream_type, ST_TCP);
                assert_eq!(port, 443);
                assert_eq!(host, b"example.com");
            }
            _ => panic!("expected CONNECT"),
        }
    }

    #[test]
    fn parse_data_ok() {
        let mut p = vec![T_DATA, 2, 0, 0, 0];
        p.extend_from_slice(b"hello");
        match parse_packet(&p).unwrap() {
            Packet::Data { stream_id, payload } => {
                assert_eq!(stream_id, 2);
                assert_eq!(payload, b"hello");
            }
            _ => panic!("expected DATA"),
        }
    }

    #[test]
    fn parse_close_and_continue() {
        let p = vec![T_CLOSE, 3, 0, 0, 0, R_VOLUNTARY];
        assert!(matches!(parse_packet(&p).unwrap(), Packet::Close { stream_id: 3 }));
        let p = vec![T_CONTINUE, 0, 0, 0, 0, 128, 0, 0, 0];
        assert!(matches!(parse_packet(&p).unwrap(), Packet::Ignored));
    }

    #[test]
    fn parse_too_short_is_none() {
        assert!(parse_packet(&[T_DATA, 1, 2]).is_none());
        assert!(parse_packet(&[]).is_none());
        // CONNECT with <3 payload bytes is malformed.
        assert!(parse_packet(&[T_CONNECT, 1, 0, 0, 0, ST_TCP]).is_none());
    }

    #[test]
    fn build_packets_roundtrip() {
        let m = data_packet(7, b"abc");
        if let Message::Binary(b) = m {
            assert_eq!(b[0], T_DATA);
            assert_eq!(u32::from_le_bytes([b[1], b[2], b[3], b[4]]), 7);
            assert_eq!(&b[5..], b"abc");
        } else {
            panic!("expected binary");
        }

        let m = continue_packet(9, 128);
        if let Message::Binary(b) = m {
            assert_eq!(b[0], T_CONTINUE);
            assert_eq!(u32::from_le_bytes([b[1], b[2], b[3], b[4]]), 9);
            assert_eq!(u32::from_le_bytes([b[5], b[6], b[7], b[8]]), 128);
        } else {
            panic!("expected binary");
        }

        let m = close_packet(4, R_BLOCKED);
        if let Message::Binary(b) = m {
            assert_eq!(b[0], T_CLOSE);
            assert_eq!(b[5], R_BLOCKED);
        } else {
            panic!("expected binary");
        }
    }
}
