//! Embedded WireGuard route: WARP registration + a userspace tunnel (boringtun + smoltcp) that
//! dials arbitrary TCP through the tunnel. The registration API is Cloudflare's unofficial
//! endpoint (the same shape wgcf uses) and may change without notice.
//!
//! One `WgTunnel` (one boringtun `Tunn` + one smoltcp `Interface` + one UDP socket to the WG
//! endpoint) is shared by every stream on a WireGuard route. A single background task owns all
//! of it — no locks — and shuttles packets between boringtun and smoltcp, servicing dial /
//! read / write commands from `WgStream` handles.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::pin::Pin;
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
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::wisp::R_UNREACHABLE;

/// WARP's tunnel MTU.
const WG_MTU: usize = 1280;
/// smoltcp per-socket buffer size.
const SOCK_BUF: usize = 64 * 1024;

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

/// Register a new WARP account (or load a cached one) and return full WG parameters.
/// Blocking: called once at startup.
pub fn register_warp(cache_path: &Path) -> Result<WgConfig, String> {
    if let Ok(body) = std::fs::read_to_string(cache_path) {
        if let Ok(cfg) = load_cached(&body) {
            return Ok(cfg);
        }
    }

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

    let partial = parse_registration(&text)?;
    let endpoint = partial
        .endpoint_hostport
        .to_socket_addrs()
        .map_err(|e| format!("endpoint resolve: {e}"))?
        .next()
        .ok_or("endpoint did not resolve")?;
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

/// Extract the first A record from a DNS response, skipping the question section and any
/// non-A answers (CNAME, etc.). Handles compressed names by length-skipping.
pub fn dns_first_a(resp: &[u8]) -> Option<Ipv4Addr> {
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
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > resp.len() {
            return None;
        }
        if rtype == 1 && rdlen == 4 {
            return Some(Ipv4Addr::new(resp[pos], resp[pos + 1], resp[pos + 2], resp[pos + 3]));
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
}

/// Shared handle to a WireGuard tunnel. Cheap to clone (just the command sender).
pub struct WgTunnel {
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    #[allow(dead_code)]
    address_v4: Ipv4Addr,
}

impl WgTunnel {
    /// Build the tunnel and start its driver task. Must be called inside a tokio runtime.
    pub fn spawn(cfg: WgConfig) -> Arc<WgTunnel> {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let address_v4 = cfg.address_v4;
        let self_tx = cmd_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = driver(cfg, cmd_rx, self_tx).await {
                tracing::warn!("wireguard tunnel driver exited: {e}");
            }
        });
        Arc::new(WgTunnel { cmd_tx, address_v4 })
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
        dns_first_a(&resp).map(IpAddr::V4).ok_or(R_UNREACHABLE)
    }
}

/// A virtual TCP stream through the tunnel. Reads pull from a channel fed by the driver;
/// writes and close are commands to the driver.
pub struct WgStream {
    handle: SocketHandle,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    from_tunnel: mpsc::UnboundedReceiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
}

impl WgStream {
    fn new(
        handle: SocketHandle,
        cmd_tx: mpsc::UnboundedSender<Cmd>,
        from_tunnel: mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Self {
        WgStream {
            handle,
            cmd_tx,
            from_tunnel,
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
        }
    }
}

impl AsyncRead for WgStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.read_pos >= me.read_buf.len() {
            if me.eof {
                return Poll::Ready(Ok(())); // EOF: fill nothing
            }
            match me.from_tunnel.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
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
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.cmd_tx.send(Cmd::Write {
            handle: self.handle,
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

/// Per-socket state the driver keeps alongside the smoltcp socket.
struct SockState {
    to_stream: mpsc::UnboundedSender<Vec<u8>>,
    pending_write: VecDeque<u8>,
    /// The reply + the stream to hand back, held until the socket is Established.
    pending: Option<(oneshot::Sender<Result<WgStream, u8>>, WgStream)>,
    established: bool,
}

/// Open a smoltcp TCP socket connecting to `ip4:port` from the tunnel address.
fn open_socket(
    sockets: &mut SocketSet<'static>,
    iface: &mut Interface,
    ip4: Ipv4Addr,
    port: u16,
    src: Ipv4Addr,
    next_port: &mut u16,
) -> Result<SocketHandle, ()> {
    let rx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; SOCK_BUF]);
    let mut sock = tcp::Socket::new(rx, tx);
    let local = *next_port;
    *next_port = if local == u16::MAX { 49152 } else { local + 1 };
    sock.connect(
        iface.context(),
        (IpAddress::from(ip4), port),
        (IpAddress::from(src), local),
    )
    .map_err(|_| ())?;
    Ok(sockets.add(sock))
}

/// Move data between smoltcp sockets and their `WgStream`s, and fire dial replies once a
/// socket is established (or errors).
fn pump_sockets(sockets: &mut SocketSet<'static>, states: &mut HashMap<SocketHandle, SockState>) {
    let mut remove = Vec::new();
    for (handle, st) in states.iter_mut() {
        let sock = sockets.get_mut::<tcp::Socket>(*handle);

        if !st.established && sock.state() == tcp::State::Established {
            st.established = true;
            if let Some((reply, stream)) = st.pending.take() {
                let _ = reply.send(Ok(stream));
            }
        }

        // Push queued writes into the socket.
        if sock.can_send() && !st.pending_write.is_empty() {
            let (a, b) = st.pending_write.as_slices();
            let data = if a.is_empty() { b } else { a };
            if let Ok(sent) = sock.send_slice(data) {
                st.pending_write.drain(..sent);
            }
        }

        // Drain received bytes to the stream.
        while sock.can_recv() {
            let mut tmp = [0u8; 8192];
            match sock.recv_slice(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = st.to_stream.send(tmp[..n].to_vec());
                }
            }
        }

        // Connection finished or failed.
        if sock.state() == tcp::State::Closed {
            if let Some((reply, _)) = st.pending.take() {
                let _ = reply.send(Err(R_UNREACHABLE)); // never established
            }
            remove.push(*handle);
        }
    }
    for h in remove {
        states.remove(&h);
        sockets.remove(h);
    }
}

/// Encrypt everything smoltcp queued and send it over UDP.
async fn drain_tx(device: &mut TunDevice, tunn: &mut Tunn, udp: &UdpSocket, scratch: &mut [u8]) {
    while let Some(pkt) = device.tx.pop_front() {
        if let TunnResult::WriteToNetwork(b) = tunn.encapsulate(&pkt, scratch) {
            let _ = udp.send(b).await;
        }
    }
}

async fn driver(
    cfg: WgConfig,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    self_tx: mpsc::UnboundedSender<Cmd>,
) -> Result<(), String> {
    let udp = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("udp bind: {e}"))?;
    udp.connect(cfg.endpoint)
        .await
        .map_err(|e| format!("udp connect: {e}"))?;

    let mut tunn = Tunn::new(
        StaticSecret::from(cfg.private_key),
        PublicKey::from(cfg.peer_public_key),
        None,
        Some(25), // persistent keepalive
        0,
        None,
    );

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
    let mut next_port: u16 = 49152;

    let mut udp_buf = vec![0u8; 2048];
    let mut scratch = vec![0u8; 2048];
    let mut tick = tokio::time::interval(Duration::from_millis(100));

    loop {
        tokio::select! {
            r = udp.recv(&mut udp_buf) => {
                let n = match r { Ok(n) => n, Err(_) => continue };
                // Decapsulate, flushing any handshake/cookie replies boringtun wants to send.
                let mut res = tunn.decapsulate(None, &udp_buf[..n], &mut scratch);
                while let TunnResult::WriteToNetwork(b) = res {
                    let _ = udp.send(b).await;
                    res = tunn.decapsulate(None, &[], &mut scratch);
                }
                if let TunnResult::WriteToTunnelV4(pkt, _) = res {
                    device.rx.push_back(pkt.to_vec());
                }
            }
            _ = tick.tick() => {
                if let TunnResult::WriteToNetwork(b) = tunn.update_timers(&mut scratch) {
                    let _ = udp.send(b).await;
                }
            }
            cmd = cmd_rx.recv() => {
                match cmd {
                    None => break,
                    Some(Cmd::Dial { ip, port, reply }) => {
                        let ip4 = match ip {
                            IpAddr::V4(v4) => v4,
                            IpAddr::V6(_) => { let _ = reply.send(Err(R_UNREACHABLE)); continue; }
                        };
                        match open_socket(&mut sockets, &mut iface, ip4, port, cfg.address_v4, &mut next_port) {
                            Ok(handle) => {
                                let (to_stream, from_tunnel) = mpsc::unbounded_channel();
                                let stream = WgStream::new(handle, self_tx.clone(), from_tunnel);
                                states.insert(handle, SockState {
                                    to_stream,
                                    pending_write: VecDeque::new(),
                                    pending: Some((reply, stream)),
                                    established: false,
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
                    Some(Cmd::Close { handle }) => {
                        if states.remove(&handle).is_some()
                            && sockets.iter().any(|(h, _)| h == handle)
                        {
                            sockets.get_mut::<tcp::Socket>(handle).close();
                        }
                    }
                }
            }
        }

        iface.poll(SmolInstant::now(), &mut device, &mut sockets);
        pump_sockets(&mut sockets, &mut states);
        drain_tx(&mut device, &mut tunn, &udp, &mut scratch).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(dns_first_a(&resp).unwrap().to_string(), "93.184.216.34");
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
        assert_eq!(dns_first_a(&resp).unwrap().to_string(), "1.2.3.4");
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
