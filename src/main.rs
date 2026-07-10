//! Binary entry point. Serves the Scramjet client + the Rust Wisp backend.

use std::sync::Arc;

use browser_proxy::config::Config;
use browser_proxy::server::{build_router, warn_if_assets_missing};

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
    let static_dir = cfg.static_dir.clone();

    warn_if_assets_missing(&static_dir);

    let app = build_router(cfg.clone(), &static_dir);

    let listener = match tokio::net::TcpListener::bind(cfg.bind).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("failed to bind {}: {e}", cfg.bind);
            std::process::exit(1);
        }
    };

    tracing::info!("browser-proxy listening on http://{}", cfg.bind);
    tracing::info!(
        "open http://localhost:{}/ (use localhost or https — service workers require a secure context)",
        cfg.bind.port()
    );

    let server = axum::serve(listener, app);
    if let Err(e) = server.with_graceful_shutdown(shutdown_signal()).await {
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
