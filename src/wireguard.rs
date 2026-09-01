//! Embedded WireGuard route: WARP registration + a userspace tunnel (boringtun + smoltcp) that
//! dials arbitrary TCP through the tunnel. The registration API is Cloudflare's unofficial
//! endpoint (the same shape wgcf uses) and may change without notice.
//!
//! One `WgTunnel` (one boringtun `Tunn` + one smoltcp `Interface` + one UDP socket to the WG
//! endpoint) is shared by every stream on a WireGuard route. A single background task owns all
//! of it — no locks — and shuttles packets between boringtun and smoltcp, servicing dial /
//! read / write commands from `WgStream` handles.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde::Deserialize;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::wisp::R_UNREACHABLE;

/// WARP's tunnel MTU.
const WG_MTU: usize = 1280;
/// smoltcp per-socket buffer size.
const SOCK_BUF: usize = 64 * 1024;
/// Dynamic (ephemeral) source-port range for tunnel sockets.
const PORT_LO: u16 = 49152;
const PORT_HI: u16 = 65535;
/// Max bytes buffered for one stream between the tunnel and its reader. While this much is
/// outstanding the driver stops draining smoltcp, so the receive window closes and the peer
/// stops sending — bounded memory instead of a slow reader buffering a whole download in RAM.
const RECV_HIGH_WATER: usize = SOCK_BUF;
/// How long a socket asked to close may sit unfinished before it is aborted. A peer that never
/// answers the FIN would otherwise pin the socket — and its source port — for the process's life.
const CLOSE_GRACE: u64 = 10;
/// Max bytes a stream may have queued toward the tunnel before its writer has to wait. Without
/// this the Wisp layer credits the client back the instant a write is *queued*, so a client
/// uploading faster than the tunnel drains would grow `pending_write` without bound.
const SEND_HIGH_WATER: usize = SOCK_BUF;
/// Consecutive dials that die without the tunnel delivering a single packet before the session
/// is presumed dead. Inbound traffic of any kind (including a refusal) resets the streak, so a
/// run of genuinely unreachable targets cannot be mistaken for a dead tunnel.
const DEAD_AFTER_FAILED_DIALS: u32 = 3;
/// Minimum gap between WARP re-registrations. Cloudflare throttles bursts from one IP, and a
/// throttled device fails to handshake exactly like the fault that prompted the re-registration
/// — so an ungated retry loop turns a blip into a permanent outage.
const REREGISTER_COOLDOWN: Duration = Duration::from_secs(60);

/// How long an unanswered handshake initiation is given before the source port is redrawn.
/// Cloudflare's WARP endpoint is anycast: the UDP 5-tuple picks the edge server, and some of
/// them never answer a given device's handshake at all. That outcome is *sticky to the source
/// port* — retransmitting from the same socket re-hashes to the same silent edge forever — so a
/// stalled handshake is a routing draw to redo, not a slow peer to wait for. A good edge answers
/// in well under a second, so this is generous.
const HANDSHAKE_REBIND_AFTER: Duration = Duration::from_millis(1500);

/// Rebinds to try before concluding the device itself is gone and re-registering. Each draw is
/// independent, so this makes a run of bad edges vanishingly unlikely while still bounding how
/// long a genuinely culled device looks merely unlucky.
const MAX_HANDSHAKE_REBINDS: u32 = 10;

/// WireGuard message type 1: handshake initiation.
const HANDSHAKE_INITIATION: u8 = 1;

// ===================== WARP registration =====================

/// The subset of the WARP registration response we need.
pub struct PartialWgConfig {
    pub peer_public_key_b64: String,
    pub endpoint_hostport: String,
    pub address_v4: Ipv4Addr,
}

#[derive(Deserialize)]
struct RegResp {
    config: RegConfig,
}
#[derive(Deserialize)]
struct RegConfig {
    interface: RegIface,
    peers: Vec<RegPeer>,
}
#[derive(Deserialize)]
struct RegIface {
    addresses: RegAddrs,
}
#[derive(Deserialize)]
struct RegAddrs {
    v4: String,
}
#[derive(Deserialize)]
struct RegPeer {
    public_key: String,
    endpoint: RegEndpoint,
}
#[derive(Deserialize)]
struct RegEndpoint {
    host: String,
}

/// Parse the WARP `/reg` JSON body into the fields we need.
pub fn parse_registration(json: &str) -> Result<PartialWgConfig, String> {
    let r: RegResp = serde_json::from_str(json).map_err(|e| format!("reg parse: {e}"))?;
    let peer = r.config.peers.into_iter().next().ok_or("reg: no peers")?;
    let address_v4 = r
        .config
        .interface
        .addresses
        .v4
        .parse()
        .map_err(|_| "reg: bad v4 address".to_string())?;
    Ok(PartialWgConfig {
        peer_public_key_b64: peer.public_key,
        endpoint_hostport: peer.endpoint.host,
        address_v4,
    })
}

/// Fully-resolved WireGuard parameters for a tunnel.
#[derive(Clone)]
pub struct WgConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub address_v4: Ipv4Addr,
}

/// Decode a base64 (standard alphabet) 32-byte key.
pub fn decode_key_b64(s: &str) -> Result<[u8; 32], String> {
    let v = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|_| "invalid base64 key".to_string())?;
    v.try_into().map_err(|_| "key must be 32 bytes".to_string())
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Resolve `host:port`, preferring an IPv4 result. The tunnel's UDP socket to the WG peer is
/// IPv4, so an IPv6 endpoint (which WARP's DNS often returns first) would be unreachable.
pub fn resolve_v4_first(hostport: &str) -> Result<SocketAddr, String> {
    let addrs: Vec<SocketAddr> = hostport
        .to_socket_addrs()
        .map_err(|e| format!("endpoint resolve: {e}"))?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| "endpoint did not resolve".to_string())
}

/// Register a new WARP account (or load a cached one) and return full WG parameters.
/// Blocking: called once at startup.
pub fn register_warp(cache_path: &Path) -> Result<WgConfig, String> {
    if let Ok(body) = std::fs::read_to_string(cache_path) {
        if let Ok(cfg) = load_cached(&body) {
            return Ok(cfg);
        }
    }
    register_fresh(cache_path)
}

/// Register a brand-new WARP account (ignoring any cache) and overwrite the cache with it.
/// Used both for the first-ever registration and to self-heal when Cloudflare culls a device
/// (a stale cached registration whose endpoint has stopped answering handshakes). Blocking.
pub fn register_fresh(cache_path: &Path) -> Result<WgConfig, String> {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);

    let body = serde_json::json!({
        "key": b64(public.as_bytes()),
        "install_id": "",
        "fcm_token": "",
        "tos": "2020-01-01T00:00:00.000Z",
        "model": "PC",
        "type": "Android",
        "locale": "en_US"
    })
    .to_string();

    let resp = ureq::post("https://api.cloudflareclient.com/v0a2158/reg")
        .set("User-Agent", "okhttp/3.12.1")
        .set("CF-Client-Version", "a-6.11-2223")
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| format!("WARP registration failed: {e}"))?;
    let text = resp
        .into_string()
        .map_err(|e| format!("WARP registration read: {e}"))?;

    // A fresh device registers with WARP disabled; the WireGuard endpoint won't answer
    // handshakes until we PATCH warp_enabled=true (authorized by the returned token).
    #[derive(Deserialize)]
    struct RegIds {
        id: String,
        token: String,
    }
    let ids: RegIds =
        serde_json::from_str(&text).map_err(|e| format!("reg id/token parse: {e}"))?;
    ureq::request(
        "PATCH",
        &format!("https://api.cloudflareclient.com/v0a2158/reg/{}", ids.id),
    )
    .set("User-Agent", "okhttp/3.12.1")
    .set("CF-Client-Version", "a-6.11-2223")
    .set("Authorization", &format!("Bearer {}", ids.token))
    .set("Content-Type", "application/json")
    .send_string("{\"warp_enabled\": true}")
    .map_err(|e| format!("WARP enable failed: {e}"))?;

    let partial = parse_registration(&text)?;
    let endpoint = resolve_v4_first(&partial.endpoint_hostport)?;
    let cfg = WgConfig {
        private_key: secret.to_bytes(),
        peer_public_key: decode_key_b64(&partial.peer_public_key_b64)?,
        endpoint,
        address_v4: partial.address_v4,
    };

    let cached = serde_json::json!({
        "private_key": b64(&cfg.private_key),
        "peer_public_key": partial.peer_public_key_b64,
        "endpoint": cfg.endpoint.to_string(),
        "address_v4": cfg.address_v4.to_string(),
    })
    .to_string();
    write_cache(cache_path, &cached);
    Ok(cfg)
}

fn load_cached(body: &str) -> Result<WgConfig, String> {
    #[derive(Deserialize)]
    struct Cached {
        private_key: String,
        peer_public_key: String,
        endpoint: String,
        address_v4: String,
    }
    let c: Cached = serde_json::from_str(body).map_err(|e| e.to_string())?;
    Ok(WgConfig {
        private_key: decode_key_b64(&c.private_key)?,
        peer_public_key: decode_key_b64(&c.peer_public_key)?,
        endpoint: c.endpoint.parse().map_err(|_| "cached endpoint".to_string())?,
        address_v4: c.address_v4.parse().map_err(|_| "cached v4".to_string())?,
    })
}

#[cfg(unix)]
fn write_cache(path: &Path, body: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
    {
        let _ = f.write_all(body.as_bytes());
    }
}
#[cfg(not(unix))]
fn write_cache(path: &Path, body: &str) {
    let _ = std::fs::write(path, body);
}

// ===================== DNS (over TCP, through the tunnel) =====================

/// Build a DNS A-record query for `host`. Fixed id 0, RD=1, one question.
pub fn dns_query(host: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(host.len() + 18);
    q.extend_from_slice(&[0x00, 0x00]); // id
    q.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    for label in host.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00); // root label
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
    q
}

/// Extract the first A record from a DNS response as `(address, ttl_seconds)`, skipping the
/// question section and any non-A answers (CNAME, etc.). Handles compressed names by
/// length-skipping. The TTL drives how long the tunnel's [`DnsCache`] may serve the answer.
pub fn dns_first_a(resp: &[u8]) -> Option<(Ipv4Addr, u32)> {
    if resp.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([resp[4], resp[5]]);
    let an = u16::from_be_bytes([resp[6], resp[7]]);
    let mut pos = 12;
    // Skip questions.
    for _ in 0..qd {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?; // QTYPE + QCLASS
    }
    // Walk answers.
    for _ in 0..an {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2), then the record data.
        let ttl = u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            let ip = Ipv4Addr::new(resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]);
            return Some((ip, ttl));
        }
        pos += rdlen;
    }
    None
}

/// Advance past a DNS name at `pos`, returning the position just after it. Follows the
/// length-prefix labels and handles a compression pointer as the terminator.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        if len & 0xc0 == 0xc0 {
            return Some(pos + 2); // pointer: 2 bytes, name ends here
        }
        if len == 0 {
            return Some(pos + 1);
        }
        pos += 1 + len as usize;
    }
}

// ===================== DNS cache =====================

/// Hostnames the tunnel's DNS cache holds. Every miss costs a TCP connection through the tunnel
/// (and a source port), so with many users a cache is the difference between one lookup per host
/// and one per request — but it must stay bounded or it becomes its own memory leak.
const DNS_CACHE_MAX: usize = 512;
/// TTL floor: authoritative answers with a very short TTL would otherwise defeat the cache.
const DNS_TTL_MIN: u64 = 30;
/// TTL ceiling: keeps a stale answer from pinning a dead IP for hours.
const DNS_TTL_MAX: u64 = 3600;

/// Bounded hostname -> address cache for lookups made through the tunnel. `now` is passed in
/// rather than read from the clock so expiry is exercised directly by tests.
struct DnsCache {
    entries: HashMap<String, (Ipv4Addr, std::time::Instant)>,
}

impl DnsCache {
    fn new() -> Self {
        DnsCache {
            entries: HashMap::new(),
        }
    }

    /// The cached address for `host`, if it has not expired.
    fn get(&self, host: &str, now: std::time::Instant) -> Option<Ipv4Addr> {
        match self.entries.get(host) {
            Some((ip, expires)) if *expires > now => Some(*ip),
            _ => None,
        }
    }

    /// Cache `ip` for `host`, clamping `ttl_secs` into [`DNS_TTL_MIN`, `DNS_TTL_MAX`] and
    /// evicting as needed to stay within [`DNS_CACHE_MAX`].
    fn insert(&mut self, host: &str, ip: Ipv4Addr, ttl_secs: u32, now: std::time::Instant) {
        if self.entries.len() >= DNS_CACHE_MAX && !self.entries.contains_key(host) {
            self.entries.retain(|_, (_, expires)| *expires > now);
            // Everything is still live: drop one arbitrary entry to make room. Which one barely
            // matters — a wrong guess costs one lookup, and the cap is what must hold.
            while self.entries.len() >= DNS_CACHE_MAX {
                let victim = match self.entries.keys().next() {
                    Some(k) => k.clone(),
                    None => break,
                };
                self.entries.remove(&victim);
            }
        }
        let ttl = (ttl_secs as u64).clamp(DNS_TTL_MIN, DNS_TTL_MAX);
        self.entries
            .insert(host.to_string(), (ip, now + Duration::from_secs(ttl)));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

// ===================== Backpressure toward the tunnel =====================

/// Bytes a stream has queued toward the tunnel but that the driver has not yet pushed into the
/// socket. Shared by both sides: the writer parks when it hits [`SEND_HIGH_WATER`] and the
/// driver wakes it as it drains.
#[derive(Clone)]
struct SendWindow(Arc<SendWindowInner>);

struct SendWindowInner {
    queued: AtomicUsize,
    /// Set when the socket is gone, so a parked writer is released instead of hanging.
    closed: AtomicBool,
    waker: std::sync::Mutex<Option<std::task::Waker>>,
}

impl SendWindow {
    fn new() -> Self {
        SendWindow(Arc::new(SendWindowInner {
            queued: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
            waker: std::sync::Mutex::new(None),
        }))
    }

    /// Ready once the writer may queue more bytes — or the socket died, which the caller
    /// distinguishes with [`SendWindow::is_closed`].
    fn poll_reserve(&self, cx: &mut Context<'_>) -> Poll<()> {
        if self.ready() {
            return Poll::Ready(());
        }
        self.park(cx.waker());
        // Re-check after parking: the driver may have drained between the check above and the
        // waker being visible to it, and it only wakes a waker it can see.
        if self.ready() {
            return Poll::Ready(());
        }
        Poll::Pending
    }

    fn ready(&self) -> bool {
        self.is_closed() || self.0.queued.load(Ordering::Acquire) < SEND_HIGH_WATER
    }

    fn park(&self, waker: &std::task::Waker) {
        let mut slot = self.lock_waker();
        *slot = Some(waker.clone());
    }

    /// Take the parked waker, if any, and wake it. One-shot: a writer re-parks on its next poll.
    fn wake(&self) {
        let taken = self.lock_waker().take();
        if let Some(w) = taken {
            w.wake();
        }
    }

    fn lock_waker(&self) -> std::sync::MutexGuard<'_, Option<std::task::Waker>> {
        self.0
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The writer queued `n` bytes.
    fn queued(&self, n: usize) {
        self.0.queued.fetch_add(n, Ordering::AcqRel);
    }

    /// The driver pushed `n` bytes into the socket, freeing that much of the window.
    fn drained(&self, n: usize) {
        let before = self.0.queued.fetch_sub(n, Ordering::AcqRel);
        if before >= SEND_HIGH_WATER && before - n < SEND_HIGH_WATER {
            self.wake();
        }
    }

    /// The socket is gone: release any parked writer.
    fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        self.wake();
    }

    fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }
}

/// The driver's half of a [`SendWindow`]. Closing on drop makes the release structural: a writer
/// parked on a socket the driver has lost — reaped, or dropped wholesale when a session is
/// rebuilt — is woken without every teardown path having to remember to do it.
struct SendGuard(SendWindow);

impl SendGuard {
    fn new(window: SendWindow) -> Self {
        SendGuard(window)
    }

    fn window(&self) -> &SendWindow {
        &self.0
    }
}

impl Drop for SendGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

// ===================== Session health & re-registration =====================

/// Which tunnel session a stream belongs to. A re-registration gives the tunnel new keys and a
/// new source address, so connections opened before it cannot survive — they must report a
/// reset rather than a clean EOF, which would tell the client the peer had closed normally.
#[derive(Clone)]
struct SessionMark {
    current: Arc<AtomicU64>,
    mine: u64,
}

impl SessionMark {
    fn is_stale(&self) -> bool {
        self.current.load(Ordering::Acquire) != self.mine
    }
}

/// Decides when a tunnel session looks dead. Dials that die *while the tunnel is silent* are the
/// signal: an idle-but-healthy tunnel is silent too, so silence alone would be a false alarm,
/// and a refused connection arrives as an inbound packet, which clears the streak.
struct SessionHealth {
    failed_dials: u32,
}

impl SessionHealth {
    fn new() -> Self {
        SessionHealth { failed_dials: 0 }
    }

    /// A socket was reaped without ever establishing. True once the streak says "re-register".
    fn dial_failed(&mut self) -> bool {
        self.failed_dials += 1;
        self.failed_dials >= DEAD_AFTER_FAILED_DIALS
    }

    /// The tunnel delivered something (a packet arrived, or a socket established).
    fn alive(&mut self) {
        self.failed_dials = 0;
    }
}

/// Rate-limits re-registration; see [`REREGISTER_COOLDOWN`].
struct ReregisterGate {
    last: Option<std::time::Instant>,
}

impl ReregisterGate {
    fn new() -> Self {
        ReregisterGate { last: None }
    }

    /// Whether a re-registration may start now, recording it when it may.
    fn allow(&mut self, now: std::time::Instant) -> bool {
        if let Some(last) = self.last {
            if now.duration_since(last) < REREGISTER_COOLDOWN {
                return false;
            }
        }
        self.last = Some(now);
        true
    }
}

// ===================== Tunnel pool =====================

/// Next slot in a round-robin over `len` items.
fn rr_index(counter: &AtomicUsize, len: usize) -> usize {
    counter.fetch_add(1, Ordering::Relaxed) % len.max(1)
}

/// A set of independent tunnels for one route, dialed round-robin. Each tunnel is a separate
/// WARP device with its own keys, exit address, driver task and source-port space, so adding
/// tunnels adds both throughput (the driver is single-threaded) and port headroom.
pub struct WgPool {
    tunnels: Vec<Arc<WgTunnel>>,
    next: AtomicUsize,
}

impl WgPool {
    pub fn new(tunnels: Vec<Arc<WgTunnel>>) -> Self {
        WgPool {
            tunnels,
            next: AtomicUsize::new(0),
        }
    }

    /// Dial through the next tunnel in the rotation.
    pub async fn dial(&self, host: &str, port: u16, timeout: Duration) -> Result<WgStream, u8> {
        let i = rr_index(&self.next, self.tunnels.len());
        self.tunnels[i].dial(host, port, timeout).await
    }
}

// ===================== Tunnel driver =====================

/// Command from a `WgStream` / dialer to the driver task.
enum Cmd {
    Dial {
        ip: IpAddr,
        port: u16,
        reply: oneshot::Sender<Result<WgStream, u8>>,
    },
    Write {
        handle: SocketHandle,
        data: Vec<u8>,
    },
    Close {
        handle: SocketHandle,
    },
    /// A reader drained enough of its backlog to reopen its `RecvWindow`. Carries nothing: the
    /// driver pumps every socket after each command, so arriving is the whole point — it just
    /// saves waiting up to one tick before smoltcp gets drained again.
    Resume,
}

/// How a single tunnel session ended, telling the driver's outer loop what to do next.
enum SessionEnd {
    /// The command channel closed (all `WgStream`s + the tunnel dropped) — stop the driver.
    Shutdown,
    /// The session concluded the device itself is gone (not just a badly-drawn source port —
    /// see `HANDSHAKE_REBIND_AFTER`). The outer loop re-registers and starts a new session.
    Reregister,
}

/// Shared handle to a WireGuard tunnel. Cheap to clone (just the command sender).
pub struct WgTunnel {
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    #[allow(dead_code)]
    address_v4: Ipv4Addr,
    /// Hostname cache for lookups made through this tunnel. A plain mutex is fine: it is touched
    /// twice per dial at most, never by the driver task in the packet path.
    dns_cache: std::sync::Mutex<DnsCache>,
}

impl WgTunnel {
    /// Build the tunnel, start its driver task, and pre-connect it. Must be called inside a tokio
    /// runtime. `reregister` is the WARP cache path for a WARP route — enabling self-heal if the
    /// registration was culled — or `None` for a static WireGuard route (fixed keys, nothing to
    /// re-register).
    pub fn spawn(cfg: WgConfig, reregister: Option<PathBuf>) -> Arc<WgTunnel> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let address_v4 = cfg.address_v4;
        let self_tx = cmd_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = driver(cfg, cmd_rx, self_tx, reregister).await {
                tracing::warn!("wireguard tunnel driver exited: {e}");
            }
        });
        let tunnel = Arc::new(WgTunnel {
            cmd_tx,
            address_v4,
            dns_cache: std::sync::Mutex::new(DnsCache::new()),
        });

        // Pre-connect: force the WireGuard handshake now so the first real request over this route
        // isn't delayed by it (WARP/WG otherwise handshakes lazily on the first dial). Dialing
        // 1.1.1.1:53 — reachable through the tunnel, and the resolver it already uses for DNS —
        // drives boringtun's handshake to completion; the throwaway stream is dropped immediately.
        // The window covers the session's whole rebind budget (see HANDSHAKE_REBIND_AFTER), since
        // reaching an edge that answers can take several source ports; the session escalates to
        // re-registration on its own once it has exhausted them, so there is nothing to do here
        // but report. Failing this is not fatal either way: the tunnel keeps healing behind the
        // warm-up and the first real request rides whatever session it lands on.
        let warm = Arc::clone(&tunnel);
        let warm_window =
            HANDSHAKE_REBIND_AFTER * (MAX_HANDSHAKE_REBINDS + 3) + Duration::from_secs(2);
        tokio::spawn(async move {
            match warm.dial("1.1.1.1", 53, warm_window).await {
                Ok(_) => tracing::info!("wireguard route pre-connected"),
                Err(reason) => tracing::warn!(
                    "wireguard route pre-connect warm-up failed (wisp reason code {reason}); \
                     route will keep retrying and connect on first real use"
                ),
            }
        });

        tunnel
    }

    /// Dial `host:port` through the tunnel. Hostnames are resolved via 1.1.1.1 inside the
    /// tunnel (DNS over TCP), so no DNS leaves this host.
    pub async fn dial(&self, host: &str, port: u16, timeout: Duration) -> Result<WgStream, u8> {
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => self.resolve(host, timeout).await?,
        };
        self.dial_ip(ip, port, timeout).await
    }

    async fn dial_ip(&self, ip: IpAddr, port: u16, timeout: Duration) -> Result<WgStream, u8> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Dial { ip, port, reply })
            .map_err(|_| R_UNREACHABLE)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(res)) => res,
            _ => Err(R_UNREACHABLE),
        }
    }

    async fn resolve(&self, host: &str, timeout: Duration) -> Result<IpAddr, u8> {
        // A miss costs a whole TCP connection through the tunnel (and a source port), so with
        // several users hitting the same hosts this is the difference between one lookup per
        // host and one per request.
        if let Some(ip) = self.cache_get(host) {
            return Ok(IpAddr::V4(ip));
        }
        let mut s = self
            .dial_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53, timeout)
            .await?;
        let q = dns_query(host);
        let mut framed = Vec::with_capacity(q.len() + 2);
        framed.extend_from_slice(&(q.len() as u16).to_be_bytes());
        framed.extend_from_slice(&q);
        s.write_all(&framed).await.map_err(|_| R_UNREACHABLE)?;
        let mut lenb = [0u8; 2];
        s.read_exact(&mut lenb).await.map_err(|_| R_UNREACHABLE)?;
        let n = u16::from_be_bytes(lenb) as usize;
        let mut resp = vec![0u8; n];
        s.read_exact(&mut resp).await.map_err(|_| R_UNREACHABLE)?;
        let (ip, ttl) = dns_first_a(&resp).ok_or(R_UNREACHABLE)?;
        self.cache_put(host, ip, ttl);
        Ok(IpAddr::V4(ip))
    }

    fn cache_get(&self, host: &str) -> Option<Ipv4Addr> {
        let cache = self
            .dns_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.get(host, std::time::Instant::now())
    }

    fn cache_put(&self, host: &str, ip: Ipv4Addr, ttl: u32) {
        let mut cache = self
            .dns_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.insert(host, ip, ttl, std::time::Instant::now());
    }
}

/// A virtual TCP stream through the tunnel. Reads pull from a channel fed by the driver;
/// writes and close are commands to the driver.
pub struct WgStream {
    handle: SocketHandle,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    from_tunnel: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Shared with the driver: taking a chunk off `from_tunnel` frees window space, and the
    /// driver only refills smoltcp -> channel while there is room.
    window: RecvWindow,
    /// The write-side counterpart: parks this stream's writer when it runs too far ahead.
    send_window: SendWindow,
    /// Which tunnel session this stream belongs to; a re-registration invalidates it.
    mark: SessionMark,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
}

impl WgStream {
    #[allow(clippy::too_many_arguments)]
    fn new(
        handle: SocketHandle,
        cmd_tx: mpsc::UnboundedSender<Cmd>,
        from_tunnel: mpsc::UnboundedReceiver<Vec<u8>>,
        window: RecvWindow,
        send_window: SendWindow,
        mark: SessionMark,
    ) -> Self {
        WgStream {
            handle,
            cmd_tx,
            from_tunnel,
            window,
            send_window,
            mark,
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
        }
    }
}

/// The tunnel was rebuilt under this stream: its connection is gone for good.
fn tunnel_reset() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "wireguard tunnel re-registered",
    )
}

impl AsyncRead for WgStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // A rebuilt tunnel cannot carry this connection. Reporting EOF would tell the client the
        // peer closed normally; a reset says the truth, and Wisp turns it into a network close.
        if me.mark.is_stale() {
            return Poll::Ready(Err(tunnel_reset()));
        }
        if me.read_pos >= me.read_buf.len() {
            if me.eof {
                return Poll::Ready(Ok(())); // EOF: fill nothing
            }
            match me.from_tunnel.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    // These bytes have left the backlog; if that reopened a window the driver
                    // had stopped filling, nudge it rather than waiting for the next tick.
                    if me.window.consumed(data.len()) {
                        let _ = me.cmd_tx.send(Cmd::Resume);
                    }
                    me.read_buf = data;
                    me.read_pos = 0;
                }
                Poll::Ready(None) => {
                    me.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = (me.read_buf.len() - me.read_pos).min(buf.remaining());
        buf.put_slice(&me.read_buf[me.read_pos..me.read_pos + n]);
        me.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WgStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if me.mark.is_stale() {
            return Poll::Ready(Err(tunnel_reset()));
        }
        // Park until the driver has drained enough of what we already queued. This is what makes
        // Wisp's per-stream credit reflect the tunnel's real pace instead of an unbounded queue.
        if me.send_window.poll_reserve(cx).is_pending() {
            return Poll::Pending;
        }
        if me.send_window.is_closed() {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tunnel closed",
            )));
        }
        me.send_window.queued(buf.len());
        match me.cmd_tx.send(Cmd::Write {
            handle: me.handle,
            data: buf.to_vec(),
        }) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "tunnel closed",
            ))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self.cmd_tx.send(Cmd::Close {
            handle: self.handle,
        });
        Poll::Ready(Ok(()))
    }
}

impl Drop for WgStream {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Close {
            handle: self.handle,
        });
    }
}

/// smoltcp in-memory device: shuttles raw IP packets between boringtun and smoltcp.
struct TunDevice {
    /// Decrypted inbound packets waiting for smoltcp to receive.
    rx: VecDeque<Vec<u8>>,
    /// Packets smoltcp wants to send, to be encrypted and sent over UDP.
    tx: VecDeque<Vec<u8>>,
}

struct TunRxToken(Vec<u8>);
struct TunTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for TunRxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}
impl TxToken for TunTxToken<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}
impl Device for TunDevice {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((TunRxToken(pkt), TunTxToken(&mut self.tx)))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = WG_MTU;
        c
    }
}

/// Allocator for the tunnel's ephemeral source ports. A port stays reserved until the socket
/// using it is reaped, so two live sockets can never share one: smoltcp dispatches an inbound
/// packet to the first socket whose (local, remote) pair matches, so a duplicated 4-tuple would
/// silently hand one stream's bytes to another.
struct PortPool {
    next: u16,
    in_use: HashSet<u16>,
}

impl PortPool {
    fn new() -> Self {
        PortPool {
            next: PORT_LO,
            in_use: HashSet::new(),
        }
    }

    /// Reserve a free port, or `None` when every port in the range is live.
    fn alloc(&mut self) -> Option<u16> {
        // Sweep forward from the last hand-out so ports rotate (a just-closed port isn't reused
        // immediately, which would confuse a peer still sending late packets), giving up only
        // after a full pass proves every port is taken.
        for _ in 0..=(PORT_HI - PORT_LO) {
            let port = self.next;
            self.next = if port == PORT_HI { PORT_LO } else { port + 1 };
            if self.in_use.insert(port) {
                return Some(port);
            }
        }
        None
    }

    fn release(&mut self, port: u16) {
        self.in_use.remove(&port);
    }
}

/// Bytes buffered for one stream between the driver and its `WgStream`, shared by both sides.
/// The driver only drains smoltcp while the window has room; the reader reopens it as it
/// consumes.
#[derive(Clone)]
struct RecvWindow(Arc<AtomicUsize>);

impl RecvWindow {
    fn new() -> Self {
        RecvWindow(Arc::new(AtomicUsize::new(0)))
    }

    /// Whether the driver may hand more bytes to the reader.
    fn has_room(&self) -> bool {
        self.0.load(Ordering::Acquire) < RECV_HIGH_WATER
    }

    /// The driver queued `n` bytes for the reader.
    fn queued(&self, n: usize) {
        self.0.fetch_add(n, Ordering::AcqRel);
    }

    /// The reader took `n` bytes. Returns true if that reopened a *closed* window, meaning the
    /// driver must be woken to resume draining smoltcp.
    fn consumed(&self, n: usize) -> bool {
        let before = self.0.fetch_sub(n, Ordering::AcqRel);
        before >= RECV_HIGH_WATER && before - n < RECV_HIGH_WATER
    }
}

/// Per-socket state the driver keeps alongside the smoltcp socket.
struct SockState {
    /// Source port this socket holds; returned to the pool when the socket is reaped.
    local_port: u16,
    /// `None` once the stream is gone: its reader sees EOF and further bytes are dropped.
    to_stream: Option<mpsc::UnboundedSender<Vec<u8>>>,
    /// Gates draining smoltcp into `to_stream`, so a slow reader closes the TCP window instead
    /// of growing the backlog without bound.
    window: RecvWindow,
    /// The mirror image: gates how much the writer may queue ahead of the socket. Held as a
    /// guard so losing this state — however it happens — always releases the writer.
    send_window: SendGuard,
    pending_write: VecDeque<u8>,
    /// The reply + the stream to hand back, held until the socket is Established.
    pending: Option<(oneshot::Sender<Result<WgStream, u8>>, WgStream)>,
    established: bool,
    /// Set when the stream asked to close: the FIN is in flight and the socket is aborted if it
    /// has not reached `Closed` by this deadline.
    close_deadline: Option<SmolInstant>,
}

/// Open a smoltcp TCP socket connecting to `ip4:port` from the tunnel address, returning it
/// with the source port it reserved.
fn open_socket(
    sockets: &mut SocketSet<'static>,
    iface: &mut Interface,
    ip4: Ipv4Addr,
    port: u16,
    src: Ipv4Addr,
    ports: &mut PortPool,
) -> Result<(SocketHandle, u16), ()> {
    let local = ports.alloc().ok_or(())?;
    let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut sock = tcp::Socket::new(rx, tx);
    if sock
        .connect(
            iface.context(),
            (IpAddress::from(ip4), port),
            (IpAddress::from(src), local),
        )
        .is_err()
    {
        ports.release(local);
        return Err(());
    }
    Ok((sockets.add(sock), local))
}

/// Move data between smoltcp sockets and their `WgStream`s, fire dial replies once a socket is
/// established (or errors), and reap finished sockets — freeing their buffers and source ports.
/// Returns true when the reaped failures say the tunnel itself is dead (see [`SessionHealth`]).
fn pump_sockets(
    now: SmolInstant,
    sockets: &mut SocketSet<'static>,
    states: &mut HashMap<SocketHandle, SockState>,
    ports: &mut PortPool,
    health: &mut SessionHealth,
) -> bool {
    let mut remove = Vec::new();
    let mut dead = false;
    for (handle, st) in states.iter_mut() {
        let sock = sockets.get_mut::<tcp::Socket>(*handle);

        if !st.established && sock.state() == tcp::State::Established {
            st.established = true;
            health.alive();
            if let Some((reply, stream)) = st.pending.take() {
                let _ = reply.send(Ok(stream));
            }
        }

        // Push queued writes into the socket (never after the stream asked to close).
        if st.close_deadline.is_none() && sock.can_send() && !st.pending_write.is_empty() {
            let (a, b) = st.pending_write.as_slices();
            let data = if a.is_empty() { b } else { a };
            if let Ok(sent) = sock.send_slice(data) {
                st.pending_write.drain(..sent);
                // Those bytes are the socket's problem now: let the writer queue more.
                st.send_window.window().drained(sent);
            }
        }

        // Drain received bytes to the stream, but only while its window has room. Stopping here
        // leaves the bytes in smoltcp's receive buffer, which shrinks the advertised window and
        // makes the peer slow down — real backpressure rather than unbounded buffering.
        while let Some(tx) = st.to_stream.as_ref() {
            if !st.window.has_room() || !sock.can_recv() {
                break;
            }
            let mut tmp = [0u8; 8192];
            match sock.recv_slice(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    st.window.queued(n);
                    if tx.send(tmp[..n].to_vec()).is_err() {
                        st.to_stream = None; // reader vanished
                        break;
                    }
                }
            }
        }

        // A peer that never answers the FIN would pin this socket forever; force it shut.
        if st.close_deadline.is_some_and(|dl| now >= dl) && sock.state() != tcp::State::Closed {
            sock.abort();
        }

        // Connection finished or failed.
        if sock.state() == tcp::State::Closed {
            if let Some((reply, _)) = st.pending.take() {
                let _ = reply.send(Err(R_UNREACHABLE)); // never established
            }
            if !st.established {
                dead |= health.dial_failed();
            }
            remove.push(*handle);
        }
    }
    for h in remove {
        if let Some(st) = states.remove(&h) {
            ports.release(st.local_port); // dropping `st` releases any parked writer
        }
        sockets.remove(h);
    }
    dead
}

/// A fresh UDP socket for the tunnel, connected to the WireGuard endpoint. Binding to port 0
/// draws a new source port, which is what picks the anycast edge — see [`HANDSHAKE_REBIND_AFTER`].
async fn bind_endpoint(endpoint: SocketAddr) -> Result<UdpSocket, String> {
    let udp = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    udp.connect(endpoint)
        .await
        .map_err(|e| format!("udp connect: {e}"))?;
    Ok(udp)
}

/// Send one encapsulated packet, starting the rebind clock on the first handshake initiation that
/// has yet to be answered. Cleared by anything that decapsulates, so the clock only runs while a
/// handshake is genuinely outstanding — an idle tunnel sends nothing and never rebinds.
async fn send_wg(udp: &UdpSocket, packet: &[u8], init_sent_at: &mut Option<std::time::Instant>) {
    if packet.first() == Some(&HANDSHAKE_INITIATION) && init_sent_at.is_none() {
        *init_sent_at = Some(std::time::Instant::now());
    }
    let _ = udp.send(packet).await;
}

/// Encrypt everything smoltcp queued and send it over UDP.
async fn drain_tx(
    device: &mut TunDevice,
    tunn: &mut Tunn,
    udp: &UdpSocket,
    scratch: &mut [u8],
    init_sent_at: &mut Option<std::time::Instant>,
) {
    while let Some(pkt) = device.tx.pop_front() {
        if let TunnResult::WriteToNetwork(b) = tunn.encapsulate(&pkt, scratch) {
            send_wg(udp, b, init_sent_at).await;
        }
    }
}

async fn driver(
    mut cfg: WgConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    self_tx: mpsc::UnboundedSender<Cmd>,
    reregister: Option<PathBuf>,
) -> Result<(), String> {
    // Bumped once per session; streams captured under an older value report a reset instead of
    // a clean EOF, because a re-registered tunnel cannot carry their connections.
    let generation = Arc::new(AtomicU64::new(0));
    let mut gate = ReregisterGate::new();
    let can_reregister = reregister.is_some();
    loop {
        let end = run_session(
            &cfg,
            &mut cmd_rx,
            &self_tx,
            &generation,
            &mut gate,
            can_reregister,
        )
        .await?;
        match end {
            SessionEnd::Shutdown => return Ok(()),
            SessionEnd::Reregister => {
                // Only a WARP route can recover this way; a static WG route has no cache to renew.
                let Some(path) = reregister.clone() else { continue };
                // register_fresh does blocking HTTP, so run it off the async driver task. The next
                // run_session() rebuilds every session-local resource from the new cfg.
                match tokio::task::spawn_blocking(move || register_fresh(&path)).await {
                    Ok(Ok(new_cfg)) => {
                        tracing::info!(
                            "WARP re-registered (previous device culled); reconnecting tunnel"
                        );
                        cfg = new_cfg;
                    }
                    Ok(Err(e)) => tracing::warn!("WARP re-registration failed: {e}"),
                    Err(e) => tracing::warn!("WARP re-registration task failed: {e}"),
                }
            }
        }
    }
}

/// Run one tunnel session with a fixed `cfg`: bind the UDP socket, drive the boringtun handshake
/// + smoltcp interface, and service dial/read/write commands until the channel closes or a
/// re-registration is requested. All per-session state (keys, socket, sessions) is local, so the
/// outer `driver` loop gets a clean slate just by calling this again with a new `cfg`.
async fn run_session(
    cfg: &WgConfig,
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
    self_tx: &mpsc::UnboundedSender<Cmd>,
    generation: &Arc<AtomicU64>,
    gate: &mut ReregisterGate,
    can_reregister: bool,
) -> Result<SessionEnd, String> {
    // Every stream opened from here on belongs to this session.
    let my_generation = generation.fetch_add(1, Ordering::AcqRel) + 1;
    let mut udp = bind_endpoint(cfg.endpoint).await?;

    let new_tunn = || {
        Tunn::new(
            StaticSecret::from(cfg.private_key),
            PublicKey::from(cfg.peer_public_key),
            None,
            Some(25), // persistent keepalive
            0,
            None,
        )
    };
    let mut tunn = new_tunn();
    // Rebind state: when the oldest unanswered handshake went out, and how many source ports this
    // session has burned through looking for an edge that answers.
    let mut init_sent_at: Option<std::time::Instant> = None;
    let mut rebinds: u32 = 0;
    let mut handshake_ok = false;

    let mut device = TunDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut iface = Interface::new(
        IfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        SmolInstant::now(),
    );
    // Assign the tunnel address as a /24 so a default-route gateway is on-link, then route
    // every destination through the tunnel.
    let oct = cfg.address_v4.octets();
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::from(cfg.address_v4), 24));
    });
    let gateway = Ipv4Address::new(oct[0], oct[1], oct[2], 1);
    iface
        .routes_mut()
        .add_default_ipv4_route(gateway)
        .map_err(|_| "add default route".to_string())?;

    let mut sockets = SocketSet::new(Vec::new());
    let mut states: HashMap<SocketHandle, SockState> = HashMap::new();
    let mut ports = PortPool::new();
    let mut health = SessionHealth::new();

    let mut udp_buf = vec![0u8; 2048];
    let mut scratch = vec![0u8; 2048];
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            r = udp.recv(&mut udp_buf) => {
                let n = match r { Ok(n) => n, Err(_) => continue };
                // Decapsulate, flushing any handshake/cookie replies boringtun wants to send.
                let mut res = tunn.decapsulate(None, &udp_buf[..n], &mut scratch);
                // Anything the peer sends that decrypts — handshake reply, keepalive, data, even
                // a refusal — proves the device is still live. A culled one gets total silence,
                // so this, not payload alone, is the liveness signal: it keeps a run of dials to
                // blackholed hosts on an idle tunnel from being read as a dead tunnel.
                if !matches!(res, TunnResult::Err(_)) {
                    health.alive();
                    // This source port reached an edge that talks back, so it is not one of the
                    // silent draws: stop the rebind clock and forgive the ports already burned.
                    handshake_ok = true;
                    init_sent_at = None;
                    rebinds = 0;
                }
                while let TunnResult::WriteToNetwork(b) = res {
                    send_wg(&udp, b, &mut init_sent_at).await;
                    res = tunn.decapsulate(None, &[], &mut scratch);
                }
                if let TunnResult::WriteToTunnelV4(pkt, _) = res {
                    device.rx.push_back(pkt.to_vec());
                }
            }
            _ = tick.tick() => {
                // Drive boringtun timers: initial handshake, retransmits, keepalive, rekey.
                if let TunnResult::WriteToNetwork(b) = tunn.update_timers(&mut scratch) {
                    send_wg(&udp, b, &mut init_sent_at).await;
                }
                // A handshake this stale is misrouted rather than slow (see
                // HANDSHAKE_REBIND_AFTER), and boringtun would retransmit from the same silent
                // source port forever. Redraw it. Only before the session's first answer: after
                // that the edge is known good and a live session is not worth tearing down — if
                // it later goes silent, the failed-dial streak below escalates instead.
                if !handshake_ok
                    && init_sent_at.is_some_and(|t| t.elapsed() >= HANDSHAKE_REBIND_AFTER)
                {
                    if rebinds >= MAX_HANDSHAKE_REBINDS {
                        // Every edge we drew stayed silent: now the device itself is the suspect.
                        rebinds = 0;
                        if can_reregister && gate.allow(std::time::Instant::now()) {
                            tracing::warn!(
                                source_ports = MAX_HANDSHAKE_REBINDS,
                                "wireguard handshake unanswered from every source port tried; \
                                 re-registering WARP (the device looks culled)"
                            );
                            return Ok(SessionEnd::Reregister);
                        }
                    }
                    rebinds += 1;
                    // Keys and the tunnel's inner address are unchanged, so smoltcp's sockets (and
                    // any stream on them) ride through this untouched — only the outer UDP flow
                    // and the crypto handshake start over.
                    udp = bind_endpoint(cfg.endpoint).await?;
                    tunn = new_tunn();
                    init_sent_at = None;
                    tracing::debug!(
                        attempt = rebinds,
                        "wireguard handshake unanswered; redrawing the UDP source port"
                    );
                    if let TunnResult::WriteToNetwork(b) =
                        tunn.format_handshake_initiation(&mut scratch, true)
                    {
                        send_wg(&udp, b, &mut init_sent_at).await;
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    None => return Ok(SessionEnd::Shutdown),
                    Some(Cmd::Dial { ip, port, reply }) => {
                        let ip4 = match ip {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => { let _ = reply.send(Err(R_UNREACHABLE)); continue; }
                        };
                        match open_socket(&mut sockets, &mut iface, ip4, port, cfg.address_v4, &mut ports) {
                            Ok((handle, local_port)) => {
                                let (to_stream, from_tunnel) = mpsc::unbounded_channel();
                                let window = RecvWindow::new();
                                let send_window = SendWindow::new();
                                let mark = SessionMark {
                                    current: Arc::clone(generation),
                                    mine: my_generation,
                                };
                                let stream = WgStream::new(
                                    handle,
                                    self_tx.clone(),
                                    from_tunnel,
                                    window.clone(),
                                    send_window.clone(),
                                    mark,
                                );
                                states.insert(handle, SockState {
                                    local_port,
                                    to_stream: Some(to_stream),
                                    window,
                                    send_window: SendGuard::new(send_window),
                                    pending_write: VecDeque::new(),
                                    pending: Some((reply, stream)),
                                    established: false,
                                    close_deadline: None,
                                });
                            }
                            Err(_) => { let _ = reply.send(Err(R_UNREACHABLE)); }
                        }
                    }
                    Some(Cmd::Write { handle, data }) => {
                        if let Some(st) = states.get_mut(&handle) {
                            st.pending_write.extend(data);
                        }
                    }
                    Some(Cmd::Resume) => {} // the pump below is the whole response
                    Some(Cmd::Close { handle }) => {
                        // Keep the state until the socket really closes: that's what returns its
                        // source port to the pool and its buffers to the allocator.
                        if let Some(st) = states.get_mut(&handle) {
                            st.to_stream = None;
                            st.send_window.window().close();
                            if st.close_deadline.is_none() {
                                st.close_deadline =
                                    Some(SmolInstant::now() + SmolDuration::from_secs(CLOSE_GRACE));
                                sockets.get_mut::<tcp::Socket>(handle).close();
                            }
                        }
                    }
                }
            }
        }

        let now = SmolInstant::now();
        iface.poll(now, &mut device, &mut sockets);
        let presumed_dead = pump_sockets(now, &mut sockets, &mut states, &mut ports, &mut health);
        drain_tx(&mut device, &mut tunn, &udp, &mut scratch, &mut init_sent_at).await;

        // Dials keep dying with nothing at all coming back: the device has almost certainly been
        // culled. Self-heal mid-run rather than staying dead until the process restarts.
        if presumed_dead && can_reregister && gate.allow(std::time::Instant::now()) {
            tracing::warn!(
                streams = states.len(),
                failed_dials = DEAD_AFTER_FAILED_DIALS,
                "wireguard tunnel presumed dead (dials failing with no reply at all); \
                 re-registering — live streams on it will be reset"
            );
            return Ok(SessionEnd::Reregister);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT_SPAN: usize = (PORT_HI - PORT_LO) as usize + 1;

    #[test]
    fn port_pool_hands_out_every_port_exactly_once_per_cycle() {
        let mut pool = PortPool::new();
        let mut seen = HashSet::new();
        for _ in 0..PORT_SPAN {
            let p = pool.alloc().expect("port available");
            assert!(p >= PORT_LO, "port {p} below the ephemeral range");
            assert!(seen.insert(p), "port {p} handed out while still live");
        }
    }

    #[test]
    fn port_pool_exhausts_rather_than_reusing_a_live_port() {
        let mut pool = PortPool::new();
        for _ in 0..PORT_SPAN {
            pool.alloc().expect("port available");
        }
        assert_eq!(pool.alloc(), None);
    }

    #[test]
    fn port_pool_reuses_a_released_port() {
        let mut pool = PortPool::new();
        let first = pool.alloc().expect("port available");
        for _ in 1..PORT_SPAN {
            pool.alloc().expect("port available");
        }
        pool.release(first);
        assert_eq!(pool.alloc(), Some(first));
    }

    #[test]
    fn recv_window_closes_at_the_high_water_mark() {
        let w = RecvWindow::new();
        assert!(w.has_room());
        w.queued(RECV_HIGH_WATER - 1);
        assert!(w.has_room());
        w.queued(1);
        assert!(!w.has_room());
    }

    #[test]
    fn recv_window_reopens_once_the_reader_consumes() {
        let w = RecvWindow::new();
        w.queued(RECV_HIGH_WATER);
        assert!(!w.has_room());
        assert!(w.consumed(1));
        assert!(w.has_room());
    }

    #[test]
    fn recv_window_reports_a_reopen_only_on_the_crossing() {
        let w = RecvWindow::new();
        w.queued(RECV_HIGH_WATER + 10);
        // Still above the mark afterwards: no wake-up needed.
        assert!(!w.consumed(5));
        // This one crosses below the mark.
        assert!(w.consumed(10));
        // Already open: consuming more must not ask for another wake-up.
        assert!(!w.consumed(1));
    }

    /// An A-record response for `example.com` carrying `ttl`.
    fn a_response(ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut resp = dns_query("example.com");
        resp[2] = 0x81;
        resp[3] = 0x80; // QR=1, RA
        resp[6] = 0x00;
        resp[7] = 0x01; // ANCOUNT=1
        resp.extend_from_slice(&[0xc0, 0x0c]); // name pointer
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        resp.extend_from_slice(&ttl.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        resp.extend_from_slice(&ip);
        resp
    }

    #[test]
    fn dns_first_a_reports_the_record_ttl() {
        let resp = a_response(300, [93, 184, 216, 34]);
        assert_eq!(dns_first_a(&resp).unwrap().1, 300);
    }

    #[test]
    fn dns_cache_serves_an_unexpired_entry() {
        let mut c = DnsCache::new();
        let now = std::time::Instant::now();
        assert_eq!(c.get("example.com", now), None);
        c.insert("example.com", Ipv4Addr::new(1, 2, 3, 4), 300, now);
        assert_eq!(
            c.get("example.com", now + Duration::from_secs(299)),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn dns_cache_drops_an_expired_entry() {
        let mut c = DnsCache::new();
        let now = std::time::Instant::now();
        c.insert("example.com", Ipv4Addr::new(1, 2, 3, 4), 300, now);
        assert_eq!(c.get("example.com", now + Duration::from_secs(301)), None);
    }

    #[test]
    fn dns_cache_raises_a_tiny_ttl_to_the_floor() {
        let mut c = DnsCache::new();
        let now = std::time::Instant::now();
        c.insert("example.com", Ipv4Addr::new(1, 2, 3, 4), 1, now);
        assert!(c
            .get("example.com", now + Duration::from_secs(DNS_TTL_MIN - 1))
            .is_some());
    }

    #[test]
    fn dns_cache_lowers_an_absurd_ttl_to_the_ceiling() {
        let mut c = DnsCache::new();
        let now = std::time::Instant::now();
        c.insert("example.com", Ipv4Addr::new(1, 2, 3, 4), u32::MAX, now);
        assert_eq!(
            c.get("example.com", now + Duration::from_secs(DNS_TTL_MAX + 1)),
            None
        );
    }

    #[test]
    fn dns_cache_stays_within_its_cap() {
        let mut c = DnsCache::new();
        let now = std::time::Instant::now();
        for i in 0..(DNS_CACHE_MAX + 50) {
            c.insert(&format!("h{i}.example.com"), Ipv4Addr::new(1, 2, 3, 4), 300, now);
        }
        assert!(c.len() <= DNS_CACHE_MAX, "cache grew to {}", c.len());
    }

    /// A waker that records how many times it was woken.
    #[derive(Default)]
    struct CountingWaker(AtomicUsize);
    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl CountingWaker {
        fn count(&self) -> usize {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn send_window_admits_writes_below_the_high_water_mark() {
        let w = SendWindow::new();
        let waker = Arc::new(CountingWaker::default());
        let raw = std::task::Waker::from(waker);
        let mut cx = Context::from_waker(&raw);
        assert!(w.poll_reserve(&mut cx).is_ready());
        w.queued(SEND_HIGH_WATER - 1);
        assert!(w.poll_reserve(&mut cx).is_ready());
    }

    #[test]
    fn send_window_parks_the_writer_when_full() {
        let w = SendWindow::new();
        let waker = Arc::new(CountingWaker::default());
        let raw = std::task::Waker::from(waker);
        let mut cx = Context::from_waker(&raw);
        w.queued(SEND_HIGH_WATER);
        assert!(w.poll_reserve(&mut cx).is_pending());
    }

    #[test]
    fn send_window_wakes_the_writer_once_it_drains() {
        let w = SendWindow::new();
        let waker = Arc::new(CountingWaker::default());
        let raw = std::task::Waker::from(waker.clone());
        let mut cx = Context::from_waker(&raw);
        w.queued(SEND_HIGH_WATER);
        assert!(w.poll_reserve(&mut cx).is_pending());
        assert_eq!(waker.count(), 0);

        // Draining below the mark must wake the parked writer exactly once...
        w.drained(1);
        assert_eq!(waker.count(), 1);
        assert!(w.poll_reserve(&mut cx).is_ready());

        // ...and draining further, with nobody parked, must not keep waking.
        w.drained(1);
        assert_eq!(waker.count(), 1);
    }

    #[test]
    fn send_window_releases_a_parked_writer_when_the_socket_dies() {
        let w = SendWindow::new();
        let waker = Arc::new(CountingWaker::default());
        let raw = std::task::Waker::from(waker.clone());
        let mut cx = Context::from_waker(&raw);
        w.queued(SEND_HIGH_WATER);
        assert!(w.poll_reserve(&mut cx).is_pending());
        w.close();
        assert_eq!(waker.count(), 1);
        assert!(w.poll_reserve(&mut cx).is_ready());
        assert!(w.is_closed());
    }

    #[test]
    fn dropping_the_driver_side_guard_releases_a_parked_writer() {
        let w = SendWindow::new();
        let waker = Arc::new(CountingWaker::default());
        let raw = std::task::Waker::from(waker.clone());
        let mut cx = Context::from_waker(&raw);
        let guard = SendGuard::new(w.clone());
        w.queued(SEND_HIGH_WATER);
        assert!(w.poll_reserve(&mut cx).is_pending());

        // However the driver loses the socket — reap, session rebuild, panic — the writer must
        // be released rather than parked on a window nobody will ever drain again.
        drop(guard);
        assert_eq!(waker.count(), 1);
        assert!(w.poll_reserve(&mut cx).is_ready());
        assert!(w.is_closed());
    }

    #[test]
    fn session_mark_spots_a_stream_from_an_earlier_session() {
        let current = Arc::new(AtomicU64::new(1));
        let mark = SessionMark {
            current: Arc::clone(&current),
            mine: 1,
        };
        assert!(!mark.is_stale());
        current.store(2, Ordering::Release);
        assert!(mark.is_stale());
    }

    #[test]
    fn session_health_flags_a_tunnel_that_is_silent_through_repeated_dials() {
        let mut h = SessionHealth::new();
        for _ in 0..(DEAD_AFTER_FAILED_DIALS - 1) {
            assert!(!h.dial_failed());
        }
        assert!(h.dial_failed());
    }

    #[test]
    fn session_health_clears_the_streak_when_the_tunnel_answers() {
        let mut h = SessionHealth::new();
        for _ in 0..(DEAD_AFTER_FAILED_DIALS - 1) {
            assert!(!h.dial_failed());
        }
        // An inbound packet — a refusal counts — proves the tunnel is carrying traffic.
        h.alive();
        for _ in 0..(DEAD_AFTER_FAILED_DIALS - 1) {
            assert!(!h.dial_failed());
        }
    }

    #[test]
    fn reregister_gate_allows_the_first_attempt_then_holds_off() {
        let mut g = ReregisterGate::new();
        let now = std::time::Instant::now();
        assert!(g.allow(now));
        assert!(!g.allow(now + REREGISTER_COOLDOWN - Duration::from_secs(1)));
        assert!(g.allow(now + REREGISTER_COOLDOWN));
    }

    #[test]
    fn round_robin_cycles_through_every_slot() {
        let counter = AtomicUsize::new(0);
        let picks: Vec<usize> = (0..7).map(|_| rr_index(&counter, 3)).collect();
        assert_eq!(picks, vec![0, 1, 2, 0, 1, 2, 0]);
    }

    #[test]
    fn dns_query_well_formed() {
        let q = dns_query("example.com");
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD=1
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
    }

    #[test]
    fn dns_parses_first_a() {
        let q = dns_query("example.com");
        let mut resp = q.clone();
        resp[2] = 0x81;
        resp[3] = 0x80; // QR=1, RA
        resp[6] = 0x00;
        resp[7] = 0x01; // ANCOUNT=1
        resp.extend_from_slice(&[0xc0, 0x0c]); // name pointer
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // TTL
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        resp.extend_from_slice(&[93, 184, 216, 34]);
        assert_eq!(dns_first_a(&resp).unwrap().0.to_string(), "93.184.216.34");
    }

    #[test]
    fn dns_skips_cname_to_a() {
        // One CNAME answer followed by an A answer.
        let q = dns_query("example.com");
        let mut resp = q.clone();
        resp[2] = 0x81;
        resp[3] = 0x80;
        resp[6] = 0x00;
        resp[7] = 0x02; // ANCOUNT=2
        // CNAME answer
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0x00, 0x05, 0x00, 0x01]); // type CNAME, IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        resp.extend_from_slice(&[0x00, 0x02, 0xc0, 0x0c]); // RDLENGTH 2, ptr
        // A answer
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]);
        resp.extend_from_slice(&[0x00, 0x04, 1, 2, 3, 4]);
        assert_eq!(dns_first_a(&resp).unwrap().0.to_string(), "1.2.3.4");
    }

    #[test]
    fn decode_key_roundtrip() {
        let raw = [7u8; 32];
        let s = b64(&raw);
        assert_eq!(decode_key_b64(&s).unwrap(), raw);
        assert!(decode_key_b64("short").is_err());
    }

    #[test]
    fn parse_registration_extracts_fields() {
        let sample = r#"{
          "config": {
            "interface": { "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110::2" } },
            "peers": [ { "public_key": "bm90YXJlYWxrZXlfMzJieXRlc19wYWRkaW5nISE=",
                         "endpoint": { "host": "engage.cloudflareclient.com:2408" } } ]
          }
        }"#;
        let p = parse_registration(sample).unwrap();
        assert_eq!(p.address_v4.to_string(), "172.16.0.2");
        assert_eq!(p.endpoint_hostport, "engage.cloudflareclient.com:2408");
        assert!(parse_registration("{}").is_err());
    }
}
