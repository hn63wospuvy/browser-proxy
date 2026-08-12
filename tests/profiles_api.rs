//! HTTP-level tests for the per-browser config sync surface: `GET`/`PUT /api/profiles/:id`.
//! Offline — the endpoints only touch the local filesystem.
//!
//! **Each test gets its own store directory.** libtest runs these concurrently in one binary, so a
//! shared directory would let the `max_clients` eviction test delete another test's document while
//! that test's writes broke its count. The pid alone is shared between them; the file-level
//! `COUNTER` is what actually separates them (same convention as `src/tls.rs`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use browser_proxy::config::{Config, Storage};
use browser_proxy::server::build_router;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A valid client ID (32 lowercase hex) built from a short seed, so each test can address its own
/// documents without hand-counting hex digits.
fn client_id(seed: &str) -> String {
    format!("{seed:0>32}").replace(|c: char| !c.is_ascii_hexdigit(), "0")
}

/// Start the proxy with a private, empty store; returns its port and that directory.
async fn spawn(max_clients: usize) -> (u16, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "bp-profiles-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    // A leftover directory from a killed run would poison the eviction count.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let cfg = Config {
        storage: Storage {
            dir: dir.to_string_lossy().into_owned(),
            max_clients,
        },
        ..Config::default()
    };
    let app = build_router(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, dir)
}

/// Number of stored documents (ignoring any `.tmp` leftovers).
fn stored(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
                .count()
        })
        .unwrap_or(0)
}

/// Minimal HTTP/1.1 request over a raw socket, returning `(status, body)`. There is no HTTP client
/// in the dependency tree (see `tests/dns_endpoint.rs`), so the suite speaks the protocol itself;
/// this is that helper extended to send a body and to read the status line.
///
/// Both the write and the read are allowed to fail: the over-limit case makes the server answer
/// and hang up while the request body is still going out, which resets the connection on some
/// platforms. Whatever arrived before that is still parsed, so the assertion — not a panic in the
/// helper — reports the real problem.
async fn request(port: u16, method: &str, path: &str, body: Option<&[u8]>) -> (u16, String) {
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(b) = body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    head.push_str("\r\n");
    let mut raw = head.into_bytes();
    if let Some(b) = body {
        raw.extend_from_slice(b);
    }
    let _ = sock.write_all(&raw).await;

    let mut resp = Vec::new();
    let _ = sock.read_to_end(&mut resp).await;
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

async fn get(port: u16, id: &str) -> (u16, String) {
    request(port, "GET", &format!("/api/profiles/{id}"), None).await
}

async fn put(port: u16, id: &str, body: &str) -> (u16, String) {
    request(port, "PUT", &format!("/api/profiles/{id}"), Some(body.as_bytes())).await
}

/// A valid one-profile document.
fn doc(updated: u64) -> String {
    format!(
        r#"{{"updated":{updated},"active":"default","profiles":[{{"name":"default","route":"direct","engine":"brave","dns":"","headers":[{{"name":"User-Agent","value":"Mozilla/5.0"}}]}}]}}"#
    )
}

#[tokio::test]
async fn put_then_get_round_trips_the_document() {
    let (port, dir) = spawn(5000).await;
    let id = client_id("a1");
    let body = doc(1_786_000_000_000);

    let (status, echo) = put(port, &id, &body).await;
    assert_eq!(status, 200, "PUT should be accepted: {echo}");
    assert!(echo.contains("\"updated\":1786000000000"), "PUT echo: {echo}");

    // Verbatim: the server stores what the client sent, so a field it doesn't model survives.
    let (status, got) = get(port, &id).await;
    assert_eq!(status, 200, "GET after PUT: {got}");
    assert_eq!(got, body);

    // A second PUT overwrites in place rather than adding a document.
    let (status, _) = put(port, &id, &doc(1_786_000_000_001)).await;
    assert_eq!(status, 200);
    assert_eq!(stored(&dir), 1, "an update must not create a second file");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn get_unknown_id_is_404() {
    let (port, dir) = spawn(5000).await;
    let (status, _) = get(port, &client_id("beef")).await;
    assert_eq!(status, 404);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn malformed_ids_are_400_and_create_no_file() {
    let (port, dir) = spawn(5000).await;
    let body = doc(1);
    for id in [
        "0123456789ABCDEF0123456789ABCDEF",  // uppercase hex
        "0123456789abcdef",                  // too short
        "0123456789abcdef0123456789abcdef0", // too long
        "..",                                // traversal
        "%2e%2e",                            // percent-encoded traversal
        "..%2f..%2fetc",                     // percent-encoded separator
        "0123456789abcdef0123456789abcdeg",  // right length, not hex
    ] {
        let (status, _) = get(port, id).await;
        assert_eq!(status, 400, "GET {id:?} should be 400");
        let (status, _) = put(port, id, &body).await;
        assert_eq!(status, 400, "PUT {id:?} should be 400");
    }
    assert_eq!(stored(&dir), 0, "a rejected id must not touch the store");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn validation_rules_reject_with_400() {
    let (port, dir) = spawn(5000).await;
    let id = client_id("c0de");

    let profiles = |entries: String| {
        format!(r#"{{"updated":1,"active":"default","profiles":[{entries}]}}"#)
    };
    let named = |n: usize| {
        (0..n)
            .map(|i| format!(r#"{{"name":"p{i}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
    };
    let with_headers = |headers: String| {
        profiles(format!(r#"{{"name":"default","headers":[{headers}]}}"#))
    };
    let long_value = "v".repeat(10241);
    let many_headers = (0..101)
        .map(|i| format!(r#"{{"name":"X-{i}","value":"v"}}"#))
        .collect::<Vec<_>>()
        .join(",");

    let cases = [
        ("no profiles", profiles(String::new())),
        (
            "51 profiles",
            format!(
                r#"{{"updated":1,"active":"p0","profiles":[{}]}}"#,
                named(51)
            ),
        ),
        (
            "65-char name",
            profiles(format!(r#"{{"name":"{}"}}"#, "n".repeat(65))),
        ),
        (
            "duplicate names differing only in case",
            profiles(r#"{"name":"default"},{"name":"Default"}"#.to_string()),
        ),
        (
            "over-long route",
            profiles(format!(
                r#"{{"name":"default","route":"{}"}}"#,
                "r".repeat(129)
            )),
        ),
        ("101 headers", with_headers(many_headers)),
        (
            "header value over 10240 bytes",
            with_headers(format!(r#"{{"name":"X-A","value":"{long_value}"}}"#)),
        ),
        (
            "header value with a newline",
            with_headers(r#"{"name":"X-A","value":"a\nb"}"#.to_string()),
        ),
        (
            "invalid header name",
            with_headers(r#"{"name":"X A","value":"v"}"#.to_string()),
        ),
        (
            "active names a missing profile",
            r#"{"updated":1,"active":"nope","profiles":[{"name":"default"}]}"#.to_string(),
        ),
        (
            "updated is not an epoch-ms integer",
            r#"{"updated":-1,"active":"default","profiles":[{"name":"default"}]}"#.to_string(),
        ),
        ("not json at all", "definitely not json".to_string()),
    ];

    for (label, body) in cases {
        let (status, msg) = put(port, &id, &body).await;
        assert_eq!(status, 400, "{label} should be rejected, got {status}: {msg}");
    }
    assert_eq!(stored(&dir), 0, "a rejected document must not be stored");

    // The boundary cases the client can legitimately produce are still accepted.
    let (status, msg) = put(
        port,
        &id,
        &format!(r#"{{"updated":1,"active":"p0","profiles":[{}]}}"#, named(50)),
    )
    .await;
    assert_eq!(status, 200, "50 profiles is the cap, not one over: {msg}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn oversize_body_is_rejected_without_being_parsed() {
    let (port, dir) = spawn(5000).await;
    let id = client_id("b1g");
    // Not JSON: if the body were parsed we'd see a 400 from serde, so a 413 proves the limit fired
    // first and the parser never ran.
    let body = "x".repeat(256 * 1024 + 1024);
    let (status, msg) = put(port, &id, &body).await;
    assert_eq!(status, 413, "over 256 KiB should be refused by the body limit: {msg}");
    assert_eq!(stored(&dir), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn max_clients_evicts_the_least_recently_modified() {
    let (port, dir) = spawn(2).await;
    let (a, b, c) = (client_id("aa"), client_id("bb"), client_id("cc"));

    // Written oldest-first, spaced out: a filesystem timestamp is only as fine-grained as the
    // system clock's tick (~15 ms on Windows), so back-to-back writes could share an mtime and
    // make "least recently modified" ambiguous.
    for id in [&a, &b] {
        assert_eq!(put(port, id, &doc(1)).await.0, 200);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(stored(&dir), 2);

    // The third client is over the cap, so the oldest document goes.
    assert_eq!(put(port, &c, &doc(1)).await.0, 200);
    assert_eq!(stored(&dir), 2, "the cap must hold after a new client");
    assert_eq!(get(port, &a).await.0, 404, "the oldest document should be evicted");
    assert_eq!(get(port, &b).await.0, 200);
    assert_eq!(get(port, &c).await.0, 200);

    // Updating an existing client never evicts — only a new document can push past the cap.
    assert_eq!(put(port, &c, &doc(2)).await.0, 200);
    assert_eq!(stored(&dir), 2);
    assert_eq!(get(port, &b).await.0, 200);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn concurrent_puts_leave_a_parsable_document() {
    let (port, dir) = spawn(5000).await;
    let id = client_id("cc0c");

    // Every write goes out as `<id>.json.tmp` + rename, so a reader sees one version or the other
    // — never a torn file — no matter how the writes interleave.
    let mut tasks = Vec::new();
    for i in 0..8u64 {
        let id = id.clone();
        tasks.push(tokio::spawn(async move {
            put(port, &id, &doc(1_786_000_000_000 + i)).await.0
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), 200);
    }

    let (status, body) = get(port, &id).await;
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("stored document must parse");
    assert_eq!(parsed["active"], "default");
    assert_eq!(parsed["profiles"].as_array().unwrap().len(), 1);
    assert_eq!(stored(&dir), 1, "exactly one document, not one per writer");
    // `stored()` counts only `.json`, so it can never see a stray temp file — check the temp path
    // itself, or a change that stopped renaming would slip through this test unnoticed.
    assert!(
        !dir.join(format!("{id}.json.tmp")).exists(),
        "no .tmp file should be left behind"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
