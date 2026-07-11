# Address-bar Settings: Search Engine, DNS, History/Autocomplete, Esc Config Flash — Design Spec

Date: 2026-07-11

Adds four user-facing conveniences to the frontend address bar, plus the one backend piece
they require (a server-side custom DNS resolver). Builds on the existing frontend
([static/index.js](../../../static/index.js), [static/search.js](../../../static/search.js))
and the `enum Route` backend ([src/route.rs](../../../src/route.rs)).

## Goals

1. **Search-engine selector** — choose which engine a non-URL query goes to (frontend-only).
2. **DNS selector** — choose which resolver resolves hostnames for the `direct` route
   (server-side DNS-over-HTTPS, from a preset list).
3. **Query history** — persist typed queries in the browser (`localStorage`).
4. **Autocomplete** — suggest from history once the input has ≥2 characters.
5. **Esc config flash** — every Esc press (already toggles the bar) also flashes the current
   Route / Search engine / DNS, dimmed, fading out over ~1s.

## Key decisions (from brainstorming)

- **DNS is server-side, DoH, fail-closed.** Resolution happens on the server
  ([route.rs `connect_direct`](../../../src/route.rs) via the OS resolver today); proxied
  routes (socks5/http/tor/wireguard) resolve at their exit and are unaffected. The DNS picker
  therefore only changes the **`direct`** route. Transport is **DNS-over-HTTPS** (encrypted,
  censorship-resistant, doesn't leak queries to the server's network) via
  **`hickory-resolver` 0.26** (`https-rustls` feature). Fail-closed to match the codebase
  ethos: an **unknown** `?dns=` name → HTTP 400 (like an unknown route); a **selected** DoH
  resolver that fails to resolve → stream close `R_UNREACHABLE`, **never** a silent fall back
  to system DNS; a **missing** `?dns=` param → system default (back-compat). The existing
  `block_private` SSRF guard and host blacklist still apply to DoH-resolved IPs.

- **Built-in DNS presets + optional config.** Ships working with no config: `system` (default,
  = today's `lookup_host`), `cloudflare`, `google`, `quad9` — the last three use hickory's
  preset `NameServerConfigGroup` constants (`CLOUDFLARE`/`GOOGLE`/`QUAD9`), which need no custom
  wiring. `config.yaml` gains an optional `dns:` section to add custom DoH entries (name +
  addresses + DoH URL + SNI) or change which name is default. AdGuard etc. are documented as a
  custom-entry example (no built-in preset constant).

- **Search engine is a pure client-side URL template.** No server involvement — the frontend
  already builds `https://…/?q=%s` in [index.js](../../../static/index.js). The selector just
  swaps the template. List: Brave (default), DuckDuckGo, DDG Lite, Bing, Startpage, Google.

- **Settings UI — layout A (inline mirrored selects).** Three labeled selects (Route, Search
  engine, DNS) mirrored in the landing block and the top bar, reusing the exact
  `fillSelect` + mirrored-change-handler pattern the Route picker already uses. Least new code,
  consistent with what exists, and there is ample bar width on desktop.

- **Esc precedence.** When the autocomplete dropdown is open, Esc closes only the dropdown (no
  bar toggle, no flash). Otherwise Esc toggles the bar and fires the config flash, as today.
  The flash is scoped to browsing mode (same as the bar toggle); on the landing the settings
  are already visible.

## Architecture

### Backend (Rust)

- **`src/dns.rs` (new).** `enum DnsResolver { System, Doh(Arc<TokioResolver>) }` with
  `async fn resolve(&self, host, port) -> io::Result<Vec<SocketAddr>>`:
  - `System` → `tokio::net::lookup_host((host, port))` (today's behavior, unchanged).
  - `Doh` → `resolver.lookup_ip(host).await`, mapped to `SocketAddr`s on `port`.
  - `build_defaults() -> HashMap<String, Arc<DnsResolver>>` builds `system`, `cloudflare`,
    `google`, `quad9`. DoH resolvers are built once at startup via
    `Resolver::builder_with_config(ResolverConfig::https(&CLOUDFLARE), TokioRuntimeProvider::default()).build()`.
  - `DEFAULT_DNS: &str = "system"` — the name used when `?dns=` is absent.
  - Config parsing for custom `dns:` entries (name + addresses + doh_url + sni).
  - Note: `https-rustls` pulls rustls; if a process-default `CryptoProvider` is required at
    runtime, install one best-effort at startup (surfaced by the smoke test).

- **`src/config.rs`.** Add `pub dns: HashMap<String, Arc<DnsResolver>>` and
  `pub default_dns: String` to `Config`; default = `dns::build_defaults()` + `"system"`. Parse
  the optional `dns:` YAML section (custom entries merged over the built-ins; a `default:` key
  may change the default name). Unknown/duplicate/reserved handled like routes.

- **`src/route.rs`.** `Route::connect` and `connect_direct` gain a `resolver: &DnsResolver`
  parameter. `connect_direct` replaces its inline `lookup_host` with `resolver.resolve(host,
  port)`, keeping the `block_private` filter and blacklist. Other route arms ignore the
  resolver.

- **`src/wisp.rs`.** `handle_connection` gains `resolver: Arc<DnsResolver>`; threads it into
  `run_stream` → `route.connect(host, port, &cfg, &resolver)`.

- **`src/server.rs`.** The `/wisp/*` upgrade handlers read the `?dns=<name>` query param, look
  up `cfg.dns.get(name)` (absent → `default_dns`; present-but-unknown → 400), and pass the
  chosen `Arc<DnsResolver>` into `handle_connection`. New `GET /dns.json` returns
  `{"dns":[…names…],"default":"system"}` (mirrors `/routes.json`, default sorted first).

### Frontend (static/)

- **`static/search-engines.js` (new).** `const SEARCH_ENGINES = [{id,label,template}…]` and a
  helper to look up a template by id. Default id = `brave`.

- **`static/autocomplete.js` (new).** A history store over `localStorage`
  (`push(query)` — dedupe move-to-front, cap 100; `match(prefix)` — case-insensitive substring,
  most-recent-first, ≤8) and a dropdown UI bound to `#proxy-address`: shows on input ≥2 chars,
  ↓/↑ highlight, Enter accepts highlight else submits, click accepts, blur/selection closes.
  Exposes `isOpen()` so the Esc handler can defer to it.

- **`static/index.js`.** (a) Replace the single `SEARCH_TEMPLATE` const with the selected
  engine's template; add `#proxy-engine` select (mirrored bar+landing) persisted to
  `localStorage`. (b) Add `#proxy-dns` select, populated from `/dns.json`, persisted, mirrored;
  include `dns` in `wispUrl()` (`?dns=<name>`) so changing it rebuilds the transport + reloads
  the frame exactly like a route switch. (c) On successful submit, push the query to history.
  (d) `#config-flash` element + Esc handler updated for the precedence + flash described above.

- **`static/index.html`.** Add the two new selects (bar + landing), the autocomplete dropdown
  container, `#config-flash`, and `<script>` tags for the two new files.

- **`static/style.css`.** Styles for the new selects, the autocomplete dropdown + highlight,
  and the config flash + ~1s opacity fade.

### Config + docs

- `config.example.yaml` / `config.yaml`: documented optional `dns:` block (built-in names +
  a custom AdGuard example).
- `README.md`: short DNS + search-engine note.

## Data flow (DNS)

```
UI #proxy-dns select ("cloudflare")
  → localStorage + wispUrl() => wss://host/wisp/direct/?dns=cloudflare
  → server upgrade handler: cfg.dns["cloudflare"] (unknown → 400)
  → handle_connection(resolver) → run_stream → route.connect(host, port, cfg, resolver)
  → connect_direct: resolver.resolve() [DoH] → block_private filter → TcpStream::connect
```

## Testing

- **Rust unit tests** (offline): DNS config parsing (built-in names present; custom entry
  parsed; `default:` override; unknown/duplicate rejected); `/dns.json` body shape;
  `?dns=` → resolver selection (missing → default; unknown → 400). `System::resolve` parity
  with `lookup_host` for an IP literal.
- **`#[ignore]`d live smoke test** mirroring the existing Tor one: build a `cloudflare` DoH
  resolver and resolve `example.com`, assert ≥1 public IP.
- **Frontend** (no build/test harness in repo): drive the real page via browser-harness —
  engine switch changes the search target; DNS switch rebuilds transport and still loads;
  typing ≥2 chars shows history matches with keyboard nav; Esc flashes the config and fades.

## Out of scope

- Per-route DNS indication/disabling in the UI when route ≠ direct (DNS is simply a no-op
  there) — may be a later polish.
- DoH over HTTP/3, DoT, or plain-UDP DNS transports.
- Server-side history/sync — history is per-browser only.
