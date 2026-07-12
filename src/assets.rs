//! Frontend + vendored client assets, embedded into the binary at compile time.
//!
//! The whole `static/` tree is baked in by `rust-embed`, so a release binary is
//! self-contained: no `static/` directory needs to sit beside it. Sourcemaps, `.d.ts`
//! declarations, and the `types/` trees are excluded — they only bloat the binary and are
//! never fetched at runtime. In *debug* builds rust-embed reads `static/` from disk instead,
//! so frontend edits show up on reload without a rebuild.

use axum::http::header::CONTENT_TYPE;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "static/"]
#[exclude = "**/*.map"]
#[exclude = "**/*.d.ts"]
#[exclude = "**/types/**"]
struct Assets;

/// Serve an embedded asset by request path. `/` maps to `index.html`; a missing file is a 404.
/// The content type is guessed from the extension (`.wasm` → `application/wasm`, `.mjs` →
/// `text/javascript`, …) so Scramjet's WASM and ES-module loads get the MIME they require.
pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match Assets::get(path) {
        Some(asset) => {
            let mime = asset.metadata.mimetype().to_string();
            ([(CONTENT_TYPE, mime)], asset.data).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
