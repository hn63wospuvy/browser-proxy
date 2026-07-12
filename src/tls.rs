//! TLS termination for the optional HTTPS listener.
//!
//! Builds an [`axum_server`] `RustlsConfig` from either operator-supplied PEM files or, when TLS
//! is enabled without a `cert`/`key`, a self-signed certificate generated fresh at startup with
//! [`rcgen`]. The generated cert covers `localhost`, `127.0.0.1`, `::1`, plus any hosts listed in
//! `tls.hostnames`. It is self-signed and regenerated on every start, so it provides a secure
//! context (needed for service workers) but no authentication — a browser reaching the server
//! over a generated cert must import it as a trusted root, and re-import after each restart.

use axum_server::tls_rustls::RustlsConfig;
use rcgen::{CertificateParams, DnType, KeyPair};

use crate::config::TlsSettings;

/// SAN entries always present in the auto-generated cert (localhost / dev).
const BASE_SANS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// Build the rustls server config for the HTTPS listener.
///
/// With both `cert` and `key` paths set, loads those PEM files; with neither, generates a fresh
/// self-signed cert covering the base SANs plus `tls.hostnames`. (`config` enforces the
/// both-or-neither invariant before we get here.)
pub async fn load_rustls_config(tls: &TlsSettings) -> Result<RustlsConfig, String> {
    ensure_crypto_provider();
    match (&tls.cert, &tls.key) {
        (Some(cert), Some(key)) => RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| format!("failed to load TLS cert/key ({cert}, {key}): {e}")),
        _ => {
            let (cert_pem, key_pem) = generate_self_signed(&tls.hostnames)?;
            RustlsConfig::from_pem(cert_pem.into_bytes(), key_pem.into_bytes())
                .await
                .map_err(|e| format!("failed to load generated self-signed cert: {e}"))
        }
    }
}

/// Generate a fresh self-signed cert + key (PEM) covering the base localhost SANs plus any extra
/// hostnames or IPs. rcgen classifies each SAN string as an IP address or DNS name automatically.
fn generate_self_signed(extra_hostnames: &[String]) -> Result<(String, String), String> {
    let mut sans: Vec<String> = BASE_SANS.iter().map(|s| s.to_string()).collect();
    for h in extra_hostnames {
        let h = h.trim();
        if !h.is_empty() && !sans.iter().any(|s| s == h) {
            sans.push(h.to_string());
        }
    }
    let mut params = CertificateParams::new(sans).map_err(|e| format!("cert params: {e}"))?;
    params
        .distinguished_name
        .push(DnType::CommonName, "browser-proxy self-signed");
    let key_pair = KeyPair::generate().map_err(|e| format!("key generation: {e}"))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| format!("self-sign: {e}"))?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

/// Install rustls' ring crypto provider as the process default (idempotent). ring is the only
/// provider compiled in; installing it explicitly keeps `ServerConfig::builder()` unambiguous
/// even if a future dependency also pulls in another backend.
fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode the first CERTIFICATE block of a PEM string to DER bytes.
    fn cert_pem_to_der(pem: &str) -> Vec<u8> {
        use base64::Engine;
        let b64: String = pem
            .lines()
            .skip_while(|l| !l.contains("BEGIN CERTIFICATE"))
            .skip(1)
            .take_while(|l| !l.contains("END CERTIFICATE"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .expect("valid base64 cert body")
    }

    #[tokio::test]
    async fn auto_generated_cert_loads() {
        let cfg = load_rustls_config(&TlsSettings {
            cert: None,
            key: None,
            hostnames: Vec::new(),
        })
        .await;
        assert!(cfg.is_ok(), "generated cert should load: {:?}", cfg.err());
    }

    #[test]
    fn generated_cert_san_includes_custom_dns() {
        // A DNS SAN is stored as ASCII in the DER, so the hostname bytes appear verbatim.
        let (cert_pem, key_pem) =
            generate_self_signed(&["proxy.example.test".to_string()]).expect("generate");
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
        let der = cert_pem_to_der(&cert_pem);
        let needle = b"proxy.example.test";
        assert!(
            der.windows(needle.len()).any(|w| w == needle),
            "SAN should contain the custom DNS name"
        );
    }

    #[tokio::test]
    async fn cert_from_files_loads() {
        // Generate a cert, write it to temp files, and load it back through the file path.
        let (cert_pem, key_pem) = generate_self_signed(&[]).expect("generate");
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("bp-test-cert-{}.pem", std::process::id()));
        let key_path = dir.join(format!("bp-test-key-{}.pem", std::process::id()));
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();

        let cfg = load_rustls_config(&TlsSettings {
            cert: Some(cert_path.to_string_lossy().into_owned()),
            key: Some(key_path.to_string_lossy().into_owned()),
            hostnames: Vec::new(),
        })
        .await;

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        assert!(cfg.is_ok(), "file cert should load: {:?}", cfg.err());
    }

    #[tokio::test]
    async fn missing_cert_file_errors() {
        let cfg = load_rustls_config(&TlsSettings {
            cert: Some("no-such-cert.pem".into()),
            key: Some("no-such-key.pem".into()),
            hostnames: Vec::new(),
        })
        .await;
        assert!(cfg.is_err());
    }
}
