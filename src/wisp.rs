//! Wisp v1 server: multiplexes many TCP streams over a single WebSocket.
//!
//! Wire format (little-endian): `[type: u8][stream_id: u32][payload]`. One Wisp packet per
//! WebSocket binary message. Spec: <https://github.com/MercuryWorkshop/wisp-protocol/tree/v1>.
//!
//! Concurrency model (per WebSocket connection):
//! - one **writer task** owns the WS sink; every stream sends outgoing packets through a
//!   bounded channel to it (serializes writes, gives backpressure to slow clients);
//! - one **read loop** owns the WS stream and the stream table (single owner → no lock).
//!   It routes DATA to per-stream channels, reaps finished streams via a `done` channel,
//!   and enforces the advertised flow-control window;
//! - one **stream task** per stream owns its TCP socket and relays both directions.
//!
//! Flow control: each stream's intake channel is **bounded** to `buffer_size`. The server
//! advertises the *actual* free space (`buffer_size - outstanding`) in every CONTINUE, so a
//! conforming client never overruns it. A client that ignores its window overflows the
//! bounded channel; that is a protocol violation and the stream is closed. Either way,
//! per-stream memory is hard-capped — it can never grow without bound.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use bytes::Bytes;
use futures_util::{sink::SinkExt, stream::StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::config::Config;
use crate::dns::DnsResolver;
use crate::metrics;
use crate::route::Route;

// Packet types.
const T_CONNECT: u8 = 0x01;
const T_DATA: u8 = 0x02;
const T_CONTINUE: u8 = 0x03;
const T_CLOSE: u8 = 0x04;

// Stream type (CONNECT payload). Only TCP is supported; UDP (0x02) is refused.
const ST_TCP: u8 = 0x01;

// Close reasons.
pub(crate) const R_VOLUNTARY: u8 = 0x02;
pub(crate) const R_NETWORK: u8 = 0x03;
pub(crate) const R_INVALID: u8 = 0x41;
pub(crate) const R_UNREACHABLE: u8 = 0x42;
pub(crate) const R_TIMEOUT: u8 = 0x43;
pub(crate) const R_REFUSED: u8 = 0x44;
pub(crate) const R_BLOCKED: u8 = 0x48;

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
    data_tx: mpsc::Sender<Bytes>,
    abort: tokio::task::AbortHandle,
    /// Packets accepted but not yet drained to TCP. Shared with the stream task, which
    /// decrements it; the read loop increments it. Drives the advertised credit.
    outstanding: Arc<AtomicU32>,
}

/// Entry point: drive one Wisp connection to completion. `resolver` is the DNS resolver chosen
/// for this connection (via `?dns=`); it applies to the `direct` route's name resolution.
pub async fn handle_connection(
    socket: WebSocket,
    cfg: Arc<Config>,
    route: Arc<Route>,
    resolver: Arc<DnsResolver>,
) {
    metrics::inc(&metrics::connections_total);
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
                        // Cap concurrent streams per connection.
                        if streams.len() >= cfg.max_streams {
                            metrics::inc(&metrics::streams_refused_maxstreams);
                            let _ = ws_tx.send(close_packet(stream_id, R_REFUSED)).await;
                            continue;
                        }
                        if stream_type != ST_TCP {
                            // UDP (0x02) is not supported; anything else is invalid.
                            let _ = ws_tx.send(close_packet(stream_id, R_INVALID)).await;
                            continue;
                        }
                        if host.len() > MAX_HOST_LEN {
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

                        tracing::debug!(stream_id, host = %host, port, active = streams.len(), "CONNECT");
                        metrics::inc(&metrics::streams_total);
                        let (data_tx, data_rx) = mpsc::channel::<Bytes>(cfg.buffer_size as usize);
                        let outstanding = Arc::new(AtomicU32::new(0));
                        let jh = tokio::spawn(run_stream(
                            stream_id,
                            host,
                            port,
                            data_rx,
                            ws_tx.clone(),
                            done_tx.clone(),
                            cfg.clone(),
                            route.clone(),
                            resolver.clone(),
                            outstanding.clone(),
                        ));
                        streams.insert(
                            stream_id,
                            StreamHandle { data_tx, abort: jh.abort_handle(), outstanding },
                        );
                    }
                    Packet::Data { stream_id, payload } => {
                        // Decide the outcome first so we don't hold an immutable borrow of
                        // `streams` while mutating it.
                        let outcome = if let Some(h) = streams.get(&stream_id) {
                            // Increment before enqueue so the stream task's decrement (after
                            // it drains the item) can never run before this add.
                            h.outstanding.fetch_add(1, Ordering::AcqRel);
                            match h.data_tx.try_send(Bytes::copy_from_slice(payload)) {
                                Ok(()) => Outcome::Ok,
                                Err(TrySendError::Full(_)) => {
                                    h.outstanding.fetch_sub(1, Ordering::AcqRel);
                                    Outcome::WindowViolation
                                }
                                Err(TrySendError::Closed(_)) => {
                                    h.outstanding.fetch_sub(1, Ordering::AcqRel);
                                    Outcome::Stale
                                }
                            }
                        } else {
                            Outcome::Unknown
                        };
                        match outcome {
                            Outcome::WindowViolation => {
                                metrics::inc(&metrics::streams_window_violation);
                                tracing::warn!(stream_id, "window violation -> closing stream");
                                let _ = ws_tx.send(close_packet(stream_id, R_INVALID)).await;
                                if let Some(h) = streams.remove(&stream_id) {
                                    h.abort.abort();
                                }
                            }
                            Outcome::Stale => {
                                streams.remove(&stream_id);
                            }
                            Outcome::Ok | Outcome::Unknown => {}
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

enum Outcome {
    Ok,
    WindowViolation,
    Stale,
    Unknown,
}

/// Relay one stream: connect, then pump both directions until either side ends.
#[allow(clippy::too_many_arguments)]
async fn run_stream(
    stream_id: u32,
    host: String,
    port: u16,
    mut data_rx: mpsc::Receiver<Bytes>,
    ws_tx: mpsc::Sender<Message>,
    done_tx: mpsc::UnboundedSender<u32>,
    cfg: Arc<Config>,
    route: Arc<Route>,
    resolver: Arc<DnsResolver>,
    outstanding: Arc<AtomicU32>,
) {
    let conn = match route.connect(&host, port, &cfg, &resolver).await {
        Ok(s) => {
            metrics::inc(&metrics::streams_connected);
            tracing::debug!(stream_id, host = %host, port, "connected");
            s
        }
        Err(reason) => {
            metrics::inc(&metrics::streams_connect_failed);
            tracing::debug!(stream_id, host = %host, port, reason, "connect failed");
            let _ = ws_tx.send(close_packet(stream_id, reason)).await;
            let _ = done_tx.send(stream_id);
            return;
        }
    };

    // `Conn` may be a real TCP socket or a virtual WireGuard stream; split generically.
    let (mut tcp_read, mut tcp_write) = tokio::io::split(conn);

    let buffer_size = cfg.buffer_size;
    // Replenish the window after draining half of it: keeps the pipe full without stalls.
    let refill_at = (buffer_size / 2).max(1);
    let idle_timeout = cfg.idle_timeout;

    // Dedicated clones so each direction owns its sender; `ws_tx` stays for the final CLOSE.
    let ws_tx_cont = ws_tx.clone();
    let ws_tx_data = ws_tx.clone();

    // client → TCP: write request bytes; credit the client back with the ACTUAL free space.
    let client_to_tcp = async move {
        let mut drained_since = 0u32;
        while let Some(chunk) = data_rx.recv().await {
            if tcp_write.write_all(&chunk).await.is_err() {
                break;
            }
            // arti's Tor `DataStream` buffers writes and only sends on flush; for a real
            // `TcpStream`/`WgStream` this flush is a no-op. Without it, a proxied request that
            // fits in arti's buffer would never be sent.
            if tcp_write.flush().await.is_err() {
                break;
            }
            outstanding.fetch_sub(1, Ordering::AcqRel);
            drained_since += 1;
            if drained_since >= refill_at {
                drained_since = 0;
                let credit = buffer_size.saturating_sub(outstanding.load(Ordering::Acquire));
                if ws_tx_cont
                    .send(continue_packet(stream_id, credit))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    };

    // TCP → client: stream response bytes back as DATA packets, with an optional idle timer.
    let tcp_to_client = async move {
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            let read = tcp_read.read(&mut buf);
            let n = match idle_timeout {
                Some(to) => match tokio::time::timeout(to, read).await {
                    Ok(r) => r,
                    Err(_) => return R_TIMEOUT, // no traffic from the target for too long
                },
                None => read.await,
            };
            match n {
                Ok(0) => return R_VOLUNTARY, // server closed cleanly
                Ok(n) => {
                    if ws_tx_data
                        .send(data_packet(stream_id, &buf[..n]))
                        .await
                        .is_err()
                    {
                        return R_NETWORK; // client gone
                    }
                }
                Err(_) => return R_NETWORK,
            }
        }
    };

    // Whichever direction ends first ends the stream. The response direction decides the
    // close reason; the request direction ending just means no more request body.
    let reason = tokio::select! {
        _ = client_to_tcp => R_VOLUNTARY,
        r = tcp_to_client => r,
    };

    metrics::inc(&metrics::streams_closed);
    tracing::debug!(stream_id, reason, "stream closed");
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
