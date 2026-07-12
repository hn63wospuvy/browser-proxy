//! Binary entry point. Serves the Scramjet client + the Rust Wisp backend.

use std::sync::Arc;
use std::time::Duration;

use browser_proxy::config::Config;
use browser_proxy::server::build_router;

/// Grace period given to in-flight connections after a shutdown signal before they're dropped.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "browser_proxy=info,tower_http=warn".into()),
        )
        .init();

    let cfg = match Config::from_env() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!("configuration error: {e}");
            std::process::exit(1);
        }
    };

    let app = build_router(cfg.clone());

    // Load the TLS config (if enabled) before binding, so a bad cert/key fails fast and loudly.
    let tls_config = match &cfg.tls {
        Some(tls) => {
            if tls.cert.is_none() {
                tracing::warn!(
                    "TLS enabled without cert/key: generating a self-signed certificate for {:?} \
                     (dev only — browsers will warn; import it as a trusted root, or set tls.cert/key)",
                    tls.hostnames
                );
            }
            match browser_proxy::tls::load_rustls_config(tls).await {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::error!("TLS setup failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => None,
    };

    // Bind up front so a port conflict is an immediate, clear error (axum-server would otherwise
    // surface it lazily from `serve`). `serve` sets the listener non-blocking itself.
    let listener = match std::net::TcpListener::bind(cfg.bind) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("failed to bind {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };

    let scheme = if tls_config.is_some() { "https" } else { "http" };
    tracing::info!("browser-proxy listening on {scheme}://{}", cfg.bind);
    tracing::info!(
        "open {scheme}://localhost:{}/ (service workers require a secure context — localhost or https)",
        cfg.bind.port()
    );

    // Drive graceful shutdown through axum-server's Handle: on Ctrl-C / SIGTERM, stop accepting
    // and give in-flight connections `SHUTDOWN_GRACE` to finish.
    let handle = axum_server::Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        async move {
            shutdown_signal().await;
            handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
        }
    });

    let result = match tls_config {
        Some(tls) => {
            axum_server::from_tcp_rustls(listener, tls)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
        None => {
            axum_server::from_tcp(listener)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
    };
    if let Err(e) = result {
        tracing::error!("server error: {e}");
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}
