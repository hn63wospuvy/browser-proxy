//! Live smoke test for the built-in Tor route. Ignored by default: it needs network access and
//! a real Tor bootstrap (several seconds), and writes arti's cache to `./arti-data`.
//!
//! Run: `cargo test --test tor_smoke -- --ignored --nocapture`
//! Verbose arti logs:  RUST_LOG=arti_client=info,tor_dirmgr=info cargo test --test tor_smoke -- --ignored --nocapture
//!
//! It builds a real in-process Tor client, bootstraps it (with a hard cap so a censored network
//! fails fast instead of hanging), then fetches this machine's public IP over plain HTTP both
//! directly and through Tor and asserts the Tor exit IP differs. It also checks that a bogus host
//! through Tor fails closed (returns an error, no panic).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use browser_proxy::config::Config;
use browser_proxy::dns::DnsResolver;
use browser_proxy::route::{Conn, Route};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Fetch `http://<host>/` and return the trimmed response body. `api.ipify.org` returns the
/// caller's public IP as the whole body in plaintext, so the body *is* the exit IP.
async fn http_get_body(conn: &mut Conn, host: &str) -> String {
    let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).await.expect("write request");
    conn.flush().await.expect("flush request");
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8_lossy(&raw);
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.trim().to_string())
        .unwrap_or_default()
}

#[tokio::test]
#[ignore]
async fn tor_route_exits_from_a_different_ip_and_fails_closed() {
    // Surface arti's own bootstrap logs (set RUST_LOG to see more).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arti_client=info,tor_dirmgr=info,tor_guardmgr=warn".into()),
        )
        .try_init();

    let host = "api.ipify.org";
    let port = 80;

    let mut cfg = Config::default();
    cfg.connect_timeout = Duration::from_secs(30);

    // The `direct` route resolves via this resolver; the Tor route ignores it (resolves at exit).
    let resolver = DnsResolver::System;

    // Direct baseline: this host's real public IP.
    let mut d = Route::Direct
        .connect(host, port, &cfg, &resolver)
        .await
        .expect("direct connect failed");
    let direct_ip = http_get_body(&mut d, host).await;
    println!("\n[smoke] direct exit IP: {direct_ip:?}");
    assert!(!direct_ip.is_empty(), "no direct IP returned");

    // Built-in Tor route — bootstrap explicitly with a hard cap so a censored/blocked network
    // fails fast with a clear message rather than hanging on the per-connect timeout.
    let client = browser_proxy::tor::build_client(&PathBuf::from("arti-data"))
        .expect("build tor client");
    println!("[smoke] bootstrapping Tor (cap 90s)...");
    let t0 = Instant::now();
    match tokio::time::timeout(Duration::from_secs(90), client.bootstrap()).await {
        Ok(Ok(())) => println!("[smoke] Tor bootstrap OK in {:?}", t0.elapsed()),
        Ok(Err(e)) => panic!("[smoke] Tor bootstrap errored after {:?}: {e}", t0.elapsed()),
        Err(_) => panic!(
            "[smoke] Tor bootstrap did not finish within 90s — this network is very likely \
             blocking direct access to the Tor network (needs bridges / pluggable transports). \
             The route code is fine; the environment can't reach Tor."
        ),
    }

    let tor = Route::Tor(client);
    let mut t = tor
        .connect(host, port, &cfg, &resolver)
        .await
        .expect("tor connect failed after bootstrap");
    let tor_ip = http_get_body(&mut t, host).await;
    println!("[smoke] tor exit IP:    {tor_ip:?}");
    assert!(!tor_ip.is_empty(), "no Tor IP returned");
    assert_ne!(
        direct_ip, tor_ip,
        "Tor route should exit from a different IP than direct"
    );

    // Fail-closed: a bogus host through Tor must error, not panic or hang.
    let bogus = tor
        .connect("this-host-does-not-exist.invalid", 80, &cfg, &resolver)
        .await;
    assert!(bogus.is_err(), "bogus host through Tor should fail closed");
    println!("[smoke] fail-closed OK: bogus host returned {:?}\n", bogus.err());
}
