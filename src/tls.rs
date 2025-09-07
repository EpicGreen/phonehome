use std::io::BufReader;
use std::path::Path;


use anyhow::{Context, Result};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use tracing::{info, warn};

use crate::config::TlsConfig;

/// Validate TLS certificate files exist and are readable
pub async fn validate_certificate_files(config: &TlsConfig) -> Result<()> {
    info!("Validating certificate files");
    validate_file_based_tls(config).await
}

/// Validate existing certificate files
async fn validate_file_based_tls(config: &TlsConfig) -> Result<()> {
    let cert_path = &config.cert_path;
    let key_path = &config.key_path;

    info!("Validating certificate from: {:?}", cert_path);
    info!("Validating private key from: {:?}", key_path);

    // Load certificates to validate format
    load_certs(cert_path).await
        .with_context(|| format!("Failed to load certificates from {:?}", cert_path))?;

    // Load private key to validate format
    load_private_key(key_path).await
        .with_context(|| format!("Failed to load private key from {:?}", key_path))?;

    info!("Certificate files validated successfully");
    Ok(())
}


/// Load certificates from a PEM file
async fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<Certificate>> {
    let path = path.as_ref();
    let mut file = File::open(path).await
        .with_context(|| format!("Failed to open certificate file: {:?}", path))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await
        .with_context(|| format!("Failed to read certificate file: {:?}", path))?;

    let mut reader = BufReader::new(contents.as_slice());
    let cert_chain: Vec<Certificate> = certs(&mut reader)
        .map_err(|_| anyhow::anyhow!("Failed to parse certificates"))?
        .into_iter()
        .map(Certificate)
        .collect();

    if cert_chain.is_empty() {
        anyhow::bail!("No certificates found in file: {:?}", path);
    }

    info!("Loaded {} certificate(s) from {:?}", cert_chain.len(), path);
    Ok(cert_chain)
}

/// Load private key from a PEM file
async fn load_private_key<P: AsRef<Path>>(path: P) -> Result<PrivateKey> {
    let path = path.as_ref();
    let mut file = File::open(path).await
        .with_context(|| format!("Failed to open private key file: {:?}", path))?;

    let mut contents = Vec::new();
    file.read_to_end(&mut contents).await
        .with_context(|| format!("Failed to read private key file: {:?}", path))?;

    let mut reader = BufReader::new(contents.as_slice());

    // Try PKCS#8 first
    if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
        if !keys.is_empty() {
            info!("Loaded PKCS#8 private key from {:?}", path);
            return Ok(PrivateKey(keys.remove(0)));
        }
    }

    // Reset reader for RSA attempt
    let mut reader = BufReader::new(contents.as_slice());

    // Try RSA private key format
    if let Ok(mut keys) = rsa_private_keys(&mut reader) {
        if !keys.is_empty() {
            info!("Loaded RSA private key from {:?}", path);
            return Ok(PrivateKey(keys.remove(0)));
        }
    }

    anyhow::bail!("No valid private key found in file: {:?}", path);
}

/// Validate TLS configuration
pub async fn validate_tls_config(config: &TlsConfig) -> Result<()> {
    // For file-based TLS, validate that files exist and are readable
    if !config.cert_path.exists() {
        anyhow::bail!("Certificate file does not exist: {:?}", config.cert_path);
    }
    if !config.key_path.exists() {
        anyhow::bail!("Private key file does not exist: {:?}", config.key_path);
    }

    validate_file_based_tls(config).await?;

    Ok(())
}

/// Generate self-signed certificate for testing (not recommended for production)
pub async fn generate_self_signed_cert(
    domain: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    use rcgen::{Certificate as RcgenCert, CertificateParams, DistinguishedName};

    warn!("Generating self-signed certificate for testing purposes");
    warn!("This should NOT be used in production!");

    let mut params = CertificateParams::new(vec![domain.to_string()]);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, domain);

    let cert = RcgenCert::from_params(params)
        .with_context(|| "Failed to generate self-signed certificate")?;

    let cert_pem = cert.serialize_pem()
        .with_context(|| "Failed to serialize certificate")?;
    let key_pem = cert.serialize_private_key_pem();

    // Ensure parent directories exist
    if let Some(parent) = cert_path.parent() {
        tokio::fs::create_dir_all(parent).await
            .with_context(|| format!("Failed to create certificate directory: {:?}", parent))?;
    }
    if let Some(parent) = key_path.parent() {
        tokio::fs::create_dir_all(parent).await
            .with_context(|| format!("Failed to create key directory: {:?}", parent))?;
    }

    // Write certificate and key files
    tokio::fs::write(cert_path, cert_pem).await
        .with_context(|| format!("Failed to write certificate file: {:?}", cert_path))?;

    tokio::fs::write(key_path, key_pem).await
        .with_context(|| format!("Failed to write private key file: {:?}", key_path))?;

    info!("Self-signed certificate generated successfully");
    info!("Certificate: {:?}", cert_path);
    info!("Private key: {:?}", key_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_generate_self_signed_cert() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let result = generate_self_signed_cert("test.example.com", &cert_path, &key_path).await;
        assert!(result.is_ok());

        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Verify we can load the generated certificates
        let certs = load_certs(&cert_path).await;
        assert!(certs.is_ok());
        assert!(!certs.unwrap().is_empty());

        let key = load_private_key(&key_path).await;
        assert!(key.is_ok());
    }

    #[tokio::test]
    async fn test_validate_tls_config_file_based() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Generate test certificates
        generate_self_signed_cert("test.example.com", &cert_path, &key_path).await.unwrap();

        let config = TlsConfig {
            cert_path,
            key_path,
        };

        let result = validate_tls_config(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_tls_config_letsencrypt() {
        let config = TlsConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };

        let result = validate_tls_config(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_tls_config_letsencrypt_missing_domain() {
        let config = TlsConfig {
            cert_path: PathBuf::from("/nonexistent/cert.pem"),
            key_path: PathBuf::from("/nonexistent/key.pem"),
        };

        let result = validate_tls_config(&config).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Domain is required"));
    }
}
