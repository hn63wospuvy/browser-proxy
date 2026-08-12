//! Per-browser configuration sync: the `/api/profiles/:id` document store.
//!
//! The frontend keeps its whole configuration — the profile list, which one is active, and each
//! profile's search engine / DNS / route / header overrides — in a single JSON document, and
//! mirrors it here so a browser that clears its `localStorage` gets it back on the next load.
//!
//! `:id` is a fingerprint the *client* computes and sends. It identifies a browser but proves
//! nothing, so this is **separation, not authentication**: anyone who learns an ID can read and
//! overwrite that document. What keeps that acceptable is the loopback-only default bind — the
//! blast radius is "whoever can already reach the proxy", who can already open Wisp tunnels.
//!
//! The server never *reads* a stored document to make a decision: routes and DNS are still chosen
//! per-connection by the Wisp URL. This is a dumb sync backend, so every field below is an opaque
//! string to it. Validation only bounds size and shape, mirroring `normalize()` in
//! `static/index.js` rule for rule — the client normalizes before every PUT, so the two can never
//! disagree about what is storable, and a 400 here means a client bug, not something a user can
//! reach by typing.

use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::config::Storage;

/// Max PUT body. Mounted as a `DefaultBodyLimit` on the PUT route only, so an oversize document is
/// refused before serde ever sees it — the parser is never handed an unbounded buffer.
///
/// This is a *tighter* bound than the per-field caps below imply: 50 profiles × 100 headers ×
/// 10 KiB is ~51 MB, so a document can satisfy every rule in `validate` and still be refused here
/// with a 413. That is deliberate — the alternative is accepting a 51 MB sync document — but it
/// means the client must enforce the same total. `MAX_DOC_BYTES` in `static/index.js` mirrors this
/// number and the header editor refuses a save that would exceed it, so a browser can never build
/// a document it is then unable to sync.
pub const MAX_BODY_BYTES: usize = 256 * 1024;
/// Profiles per document. The client's picker caps at the same number.
const MAX_PROFILES: usize = 50;
/// Profile name length, counted in `char`s. The client truncates with `String.slice`, which counts
/// UTF-16 units — always ≥ the `char` count — so anything the client produces passes here.
const MAX_NAME_CHARS: usize = 64;
/// `route` / `engine` / `dns` are opaque names to the server; the cap only stops unbounded growth.
/// (The DNS input takes a typed IP with no `maxlength`, so an over-long value is reachable.)
const MAX_OPAQUE_CHARS: usize = 128;
const MAX_HEADERS: usize = 100;
const MAX_HEADER_VALUE_BYTES: usize = 10240;
/// A client ID is a 128-bit hash rendered as lowercase hex.
const ID_LEN: usize = 32;

/// The whole client configuration — the exact body of `PUT /api/profiles/<id>`, and the exact
/// content of `localStorage["proxy-config"]`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Doc {
    /// Epoch ms from the *writing client's* clock. The only ordering key: a load compares it
    /// against the local document and the larger one wins. Clock skew is accepted (see the spec).
    pub updated: u64,
    /// Name of the active profile; must name an entry in `profiles`.
    pub active: String,
    pub profiles: Vec<Profile>,
}

/// One named configuration. Unknown fields are tolerated (and preserved — see `put_profile`) so a
/// newer frontend can add a setting without a server release.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    pub name: String,
    /// Route name; `""` or an unknown name means direct.
    #[serde(default)]
    pub route: String,
    /// Search-engine id from `static/search-engines.js`.
    #[serde(default)]
    pub engine: String,
    /// DNS preset name or IP literal; `""` means the server default.
    #[serde(default)]
    pub dns: String,
    #[serde(default)]
    pub headers: Vec<Header>,
}

/// One request-header override. The transport applies these in the browser; the server only
/// stores them (it relays raw TCP and never sees a request line).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// `^[0-9a-f]{32}$`. Checking this *before* touching the filesystem is what makes the path safe:
/// no separator, no `..`, and nothing a percent-decode can produce survives it, so
/// `<dir>/<id>.json` is always a plain file inside the store.
pub fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// RFC 7230 token — the same set `HEADER_NAME_RE` enforces in `static/index.js`: visible ASCII
/// minus the delimiters, which keeps CR / LF / space / `:` out of a name the transport will paste
/// into a real request.
fn is_header_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Bound a document. Returns the message sent back with the 400 — short, because nothing but a
/// developer ever reads it.
pub fn validate(doc: &Doc) -> Result<(), String> {
    if doc.profiles.is_empty() || doc.profiles.len() > MAX_PROFILES {
        return Err(format!("profiles must hold 1-{MAX_PROFILES} entries"));
    }
    // Case-insensitive uniqueness. The client resolves collisions by renaming (`name (2)`), so a
    // well-behaved client never trips this; rejecting keeps two profiles from becoming one after a
    // future case-insensitive lookup. Linear scan: n ≤ 50, cheaper than building a set.
    let mut seen: Vec<String> = Vec::with_capacity(doc.profiles.len());
    for p in &doc.profiles {
        let name_chars = p.name.chars().count();
        if name_chars == 0 || name_chars > MAX_NAME_CHARS {
            return Err(format!("profile name must be 1-{MAX_NAME_CHARS} chars"));
        }
        let key = p.name.to_lowercase();
        if seen.contains(&key) {
            return Err(format!("duplicate profile name: {:?}", p.name));
        }
        seen.push(key);

        for (field, value) in [("route", &p.route), ("engine", &p.engine), ("dns", &p.dns)] {
            if value.chars().count() > MAX_OPAQUE_CHARS {
                return Err(format!("{field} must be at most {MAX_OPAQUE_CHARS} chars"));
            }
        }

        if p.headers.len() > MAX_HEADERS {
            return Err(format!("at most {MAX_HEADERS} headers per profile"));
        }
        for h in &p.headers {
            if !is_header_token(&h.name) {
                return Err(format!("invalid header name: {:?}", h.name));
            }
            if h.value.len() > MAX_HEADER_VALUE_BYTES {
                return Err(format!(
                    "header value must be at most {MAX_HEADER_VALUE_BYTES} bytes"
                ));
            }
            // CR / LF would let a stored value inject extra headers once the transport writes it
            // out; NUL is rejected with them because nothing legitimate carries it.
            if h.value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
                return Err("header value must not contain CR, LF or NUL".to_string());
            }
        }
    }
    if !doc.profiles.iter().any(|p| p.name == doc.active) {
        return Err(format!("active {:?} names no profile", doc.active));
    }
    Ok(())
}

/// The on-disk store: one `<id>.json` per browser under `storage.dir`.
pub struct ProfileStore {
    dir: PathBuf,
    /// Cap on stored documents. A *new* document past it evicts the least-recently-written ones.
    max_clients: usize,
    /// The store's one lock. It serialises every read and write — documents are ≤ 256 KiB and a
    /// browsing session issues a handful of requests, so per-ID locking would be complexity
    /// without benefit — and it guards the cached document count, which stays `None` until the
    /// first write pays for one directory scan.
    count: Mutex<Option<usize>>,
}

impl ProfileStore {
    pub fn new(storage: &Storage) -> Self {
        ProfileStore {
            dir: PathBuf::from(&storage.dir),
            // A cap of 0 would evict on every write and still be over it; one document is the floor.
            max_clients: storage.max_clients.max(1),
            count: Mutex::new(None),
        }
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Read a document. `Ok(None)` means this browser has never synced — the client then pushes
    /// its local copy. The bytes come back exactly as they were written (see `store`).
    pub async fn load(&self, id: &str) -> std::io::Result<Option<Vec<u8>>> {
        let _guard = self.count.lock().await;
        match std::fs::read(self.path(id)) {
            Ok(body) => Ok(Some(body)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Overwrite a document atomically: write `<id>.json.tmp`, then rename it over the target.
    /// `fs::rename` replaces an existing file on both Unix and Windows, so a concurrent reader
    /// sees either the old document or the new one — never a half-written one, even if the process
    /// dies mid-write.
    pub async fn store(&self, id: &str, body: &[u8]) -> std::io::Result<()> {
        let mut count = self.count.lock().await;
        // The store directory is created on first write, not at startup: an operator who never
        // opens the frontend gets no stray directory.
        std::fs::create_dir_all(&self.dir)?;
        let path = self.path(id);

        // Only a *new* document can push the store over the cap, so updates never scan the
        // directory — the common case (a debounced PUT every few seconds) stays a write and a
        // rename. `Some(n)` is the count this write will leave behind, applied once it succeeds.
        let bumped = if path.exists() {
            None
        } else {
            let mut known = match *count {
                Some(c) => c,
                None => scan(&self.dir)?.len(),
            };
            if known >= self.max_clients {
                known -= evict(&self.dir, known + 1 - self.max_clients)?;
                // Eviction has already deleted files, so the cached count is stale as of now —
                // not as of a successful write. Bank it here: if the write below fails (disk full,
                // antivirus lock), the deletions still happened, and a cache left one too high
                // would evict a live document on every subsequent new client.
                *count = Some(known);
            }
            Some(known + 1)
        };

        let tmp = self.dir.join(format!("{id}.json.tmp"));
        std::fs::write(&tmp, body)?;
        std::fs::rename(&tmp, &path)?;
        if let Some(n) = bumped {
            *count = Some(n);
        }
        Ok(())
    }
}

/// Every stored document with its mtime. A leftover `<id>.json.tmp` (a write that died between
/// the write and the rename) fails the `.json` extension test, so it neither counts against the
/// cap nor is ever served.
fn scan(dir: &FsPath) -> std::io::Result<Vec<(PathBuf, SystemTime)>> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        // No directory yet means no documents; the first write creates it.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // An unreadable mtime sorts oldest, so a file we can't judge is the first candidate to go
        // rather than something that pins the store at its cap forever.
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        out.push((path, mtime));
    }
    Ok(out)
}

/// Delete the `n` least-recently-modified documents; returns how many actually went. mtime *is*
/// the last-sync time — the client rewrites the whole document on every change — so the oldest
/// file belongs to the browser that stopped using the proxy first.
fn evict(dir: &FsPath, n: usize) -> std::io::Result<usize> {
    let mut docs = scan(dir)?;
    docs.sort_by_key(|(_, mtime)| *mtime);
    let mut gone = 0;
    for (path, _) in docs.into_iter().take(n) {
        match std::fs::remove_file(&path) {
            Ok(()) => gone += 1,
            // A file we couldn't delete stays counted, so the cap is still respected.
            Err(e) => tracing::warn!(path = %path.display(), error = %e, "profile evict failed"),
        }
    }
    Ok(gone)
}

/// `GET /api/profiles/<id>` — the stored document, or 404 when this browser has never synced.
pub async fn get_profile(
    State(store): State<Arc<ProfileStore>>,
    Path(id): Path<String>,
) -> Response {
    if !valid_id(&id) {
        return (StatusCode::BAD_REQUEST, "invalid client id").into_response();
    }
    match store.load(&id).await {
        Ok(Some(body)) => ([(CONTENT_TYPE, "application/json")], body).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "no profile for this client").into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "profile read failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "profile read failed").into_response()
        }
    }
}

/// `PUT /api/profiles/<id>` — validate and overwrite the whole document, echoing back the
/// `updated` stamp that is now stored so the client can confirm which version won.
pub async fn put_profile(
    State(store): State<Arc<ProfileStore>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    if !valid_id(&id) {
        return (StatusCode::BAD_REQUEST, "invalid client id").into_response();
    }
    let doc: Doc = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid document: {e}")).into_response(),
    };
    if let Err(msg) = validate(&doc) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    // Stored verbatim rather than re-serialized from `doc`: this is a sync backend, so a field the
    // server doesn't model — one a newer frontend added — has to survive the round-trip untouched.
    match store.store(&id, &body).await {
        Ok(()) => (
            [(CONTENT_TYPE, "application/json")],
            format!("{{\"updated\":{}}}", doc.updated),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "profile write failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "profile write failed").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> Profile {
        Profile {
            name: name.to_string(),
            route: String::new(),
            engine: String::new(),
            dns: String::new(),
            headers: Vec::new(),
        }
    }

    fn doc(profiles: Vec<Profile>) -> Doc {
        Doc {
            updated: 1_786_000_000_000,
            active: "default".to_string(),
            profiles,
        }
    }

    #[test]
    fn id_must_be_32_lowercase_hex() {
        assert!(valid_id("0123456789abcdef0123456789abcdef"));
        assert!(!valid_id("0123456789ABCDEF0123456789ABCDEF")); // uppercase
        assert!(!valid_id("0123456789abcdef")); // too short
        assert!(!valid_id("0123456789abcdef0123456789abcdef0")); // too long
        assert!(!valid_id("..")); // traversal
        assert!(!valid_id("0123456789abcdef0123456789abcde/")); // separator
        assert!(!valid_id("0123456789abcdef0123456789abcdeg")); // non-hex
        assert!(!valid_id(""));
    }

    #[test]
    fn minimal_document_is_accepted() {
        assert!(validate(&doc(vec![profile("default")])).is_ok());
    }

    #[test]
    fn profile_count_is_bounded() {
        assert!(validate(&doc(Vec::new())).is_err());
        let mut fifty = vec![profile("default")];
        fifty.extend((1..MAX_PROFILES).map(|i| profile(&format!("p{i}"))));
        assert_eq!(fifty.len(), MAX_PROFILES);
        assert!(validate(&doc(fifty.clone())).is_ok());
        let mut over = fifty;
        over.push(profile("one-too-many"));
        assert!(validate(&doc(over)).is_err());
    }

    #[test]
    fn names_are_bounded_and_case_insensitively_unique() {
        assert!(validate(&doc(vec![profile("default"), profile("")])).is_err());
        let long = "n".repeat(MAX_NAME_CHARS + 1);
        assert!(validate(&doc(vec![profile("default"), profile(&long)])).is_err());
        assert!(validate(&doc(vec![profile("default"), profile(&long[1..])])).is_ok());
        assert!(validate(&doc(vec![profile("default"), profile("Default")])).is_err());
    }

    #[test]
    fn opaque_fields_are_length_capped() {
        for field in ["route", "engine", "dns"] {
            let mut p = profile("default");
            let long = "x".repeat(MAX_OPAQUE_CHARS + 1);
            match field {
                "route" => p.route = long,
                "engine" => p.engine = long,
                _ => p.dns = long,
            }
            assert!(validate(&doc(vec![p])).is_err(), "{field} should be capped");
        }
    }

    #[test]
    fn header_rules_match_the_client() {
        let header = |name: &str, value: &str| Header {
            name: name.to_string(),
            value: value.to_string(),
        };
        let with = |headers: Vec<Header>| {
            let mut p = profile("default");
            p.headers = headers;
            doc(vec![p])
        };

        assert!(validate(&with(vec![header("User-Agent", "Mozilla/5.0")])).is_ok());
        assert!(validate(&with(vec![header("User Agent", "x")])).is_err()); // space
        assert!(validate(&with(vec![header("", "x")])).is_err());
        assert!(validate(&with(vec![header("X-A:B", "x")])).is_err()); // delimiter
        assert!(validate(&with(vec![header("X-A", &"v".repeat(MAX_HEADER_VALUE_BYTES))])).is_ok());
        assert!(
            validate(&with(vec![header("X-A", &"v".repeat(MAX_HEADER_VALUE_BYTES + 1))])).is_err()
        );
        assert!(validate(&with(vec![header("X-A", "a\nb")])).is_err());
        assert!(validate(&with(vec![header("X-A", "a\rb")])).is_err());
        assert!(validate(&with(vec![header("X-A", "a\0b")])).is_err());

        let many: Vec<Header> = (0..=MAX_HEADERS).map(|i| header(&format!("X-{i}"), "v")).collect();
        assert!(validate(&with(many)).is_err());
    }

    #[test]
    fn active_must_name_a_profile() {
        let mut d = doc(vec![profile("work")]);
        d.active = "default".to_string();
        assert!(validate(&d).is_err());
        d.active = "work".to_string();
        assert!(validate(&d).is_ok());
    }

    #[test]
    fn unknown_fields_parse_and_defaults_fill_in() {
        // A newer frontend's extra field must not make the document unparseable, and a profile
        // written before a field existed must still load.
        let raw = r#"{"updated":7,"active":"default","future":true,
                      "profiles":[{"name":"default","future":1}]}"#;
        let d: Doc = serde_json::from_str(raw).expect("unknown fields are tolerated");
        assert_eq!(d.updated, 7);
        assert!(d.profiles[0].headers.is_empty());
        assert!(validate(&d).is_ok());
    }

    #[test]
    fn updated_must_be_an_unsigned_integer() {
        assert!(serde_json::from_str::<Doc>(r#"{"updated":-1,"active":"d","profiles":[]}"#).is_err());
        assert!(serde_json::from_str::<Doc>(r#"{"active":"d","profiles":[]}"#).is_err());
    }
}
