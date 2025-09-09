use std::io::BufReader;
use std::path::Path;

use anyhow::{Context, Result};
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use tracing::{debug, error, info, warn};

use crate::config::TlsConfig;

/// Setup TLS configuration - either validate existing certificates or generate self-signed ones
pub async fn setup_tls_config(config: &TlsConfig) -> Result<()> {
    info!("Starting TLS configuration setup");
    debug!("TLS config: {:#?}", config);

    let cert_path = &config.cert_path;
    let key_path = &config.key_path;

    debug!("Checking for existing certificate files");
    debug!("Certificate path: {:?}", cert_path);
    debug!("Private key path: {:?}", key_path);

    // Check if certificate files exist
    if cert_path.exists() && key_path.exists() {
        info!("Found existing certificate files, validating...");
        info!("Certificate: {:?}", cert_path);
        info!("Private key: {:?}", key_path);

        debug!("Loading and validating certificate file");
        // Validate existing certificates
        let certs = load_certs(cert_path)
            .await
            .with_context(|| format!("Failed to load certificates from {:?}", cert_path))?;
        info!("Successfully validated {} certificate(s)", certs.len());

        debug!("Loading and validating private key file");
        load_private_key(key_path)
            .await
            .with_context(|| format!("Failed to load private key from {:?}", key_path))?;

        info!("Certificate files validated successfully");
        debug!("TLS setup completed with existing certificates");
    } else {
        if !cert_path.exists() {
            debug!("Certificate file not found: {:?}", cert_path);
        }
        if !key_path.exists() {
            debug!("Private key file not found: {:?}", key_path);
        }

        info!("Certificate files not found, generating self-signed certificate...");
        generate_self_signed_cert("localhost", cert_path, key_path)
            .await
            .with_context(|| "Failed to generate self-signed certificate")?;
        info!("TLS setup completed with generated self-signed certificates");
    }

    info!("TLS configuration setup completed successfully");
    Ok(())
}

/// Load certificates from a PEM file
async fn load_certs<P: AsRef<Path>>(path: P) -> Result<Vec<Certificate>> {
    let path = path.as_ref();
    debug!("Loading certificates from: {:?}", path);

    let mut file = File::open(path)
        .await
        .with_context(|| format!("Failed to open certificate file: {:?}", path))?;
    debug!("Certificate file opened successfully");

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .await
        .with_context(|| format!("Failed to read certificate file: {:?}", path))?;
    debug!("Read {} bytes from certificate file", contents.len());

    let mut reader = BufReader::new(contents.as_slice());
    debug!("Parsing PEM certificates");
    let cert_chain: Vec<Certificate> = certs(&mut reader)
        .map_err(|e| {
            error!("Failed to parse certificates: {:?}", e);
            anyhow::anyhow!("Failed to parse certificates")
        })?
        .into_iter()
        .map(Certificate)
        .collect();

    if cert_chain.is_empty() {
        error!("No certificates found in file: {:?}", path);
        anyhow::bail!("No certificates found in file: {:?}", path);
    }

    info!("Loaded {} certificate(s) from {:?}", cert_chain.len(), path);
    debug!("Certificate chain loaded successfully");
    Ok(cert_chain)
}

/// Load private key from a PEM file
async fn load_private_key<P: AsRef<Path>>(path: P) -> Result<PrivateKey> {
    let path = path.as_ref();
    debug!("Loading private key from: {:?}", path);

    let mut file = File::open(path)
        .await
        .with_context(|| format!("Failed to open private key file: {:?}", path))?;
    debug!("Private key file opened successfully");

    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .await
        .with_context(|| format!("Failed to read private key file: {:?}", path))?;
    debug!("Read {} bytes from private key file", contents.len());

    let mut reader = BufReader::new(contents.as_slice());

    // Try PKCS#8 first
    debug!("Attempting to parse as PKCS#8 private key");
    if let Ok(mut keys) = pkcs8_private_keys(&mut reader) {
        if !keys.is_empty() {
            info!("Loaded PKCS#8 private key from {:?}", path);
            debug!("PKCS#8 private key loaded successfully");
            return Ok(PrivateKey(keys.remove(0)));
        }
        debug!("No PKCS#8 keys found");
    } else {
        debug!("Failed to parse as PKCS#8");
    }

    // Reset reader for RSA attempt
    let mut reader = BufReader::new(contents.as_slice());

    // Try RSA private key format
    debug!("Attempting to parse as RSA private key");
    if let Ok(mut keys) = rsa_private_keys(&mut reader) {
        if !keys.is_empty() {
            info!("Loaded RSA private key from {:?}", path);
            debug!("RSA private key loaded successfully");
            return Ok(PrivateKey(keys.remove(0)));
        }
        debug!("No RSA keys found");
    } else {
        debug!("Failed to parse as RSA");
    }

    error!("No valid private key found in file: {:?}", path);
    anyhow::bail!("No valid private key found in file: {:?}", path);
}

/// Generate self-signed certificate
pub async fn generate_self_signed_cert(
    domain: &str,
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    use rcgen::{Certificate as RcgenCert, CertificateParams, DistinguishedName};

    info!("Generating self-signed certificate for domain: {}", domain);
    warn!("Self-signed certificates should only be used for testing or internal use");
    debug!("Certificate will be saved to: {:?}", cert_path);
    debug!("Private key will be saved to: {:?}", key_path);

    debug!("Creating certificate parameters");
    let mut params = CertificateParams::new(vec![domain.to_string()]);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    debug!("Certificate parameters configured for domain: {}", domain);

    debug!("Generating certificate and private key");
    let cert = RcgenCert::from_params(params)
        .with_context(|| "Failed to generate self-signed certificate")?;
    debug!("Certificate generated successfully");

    debug!("Serializing certificate to PEM format");
    let cert_pem = cert
        .serialize_pem()
        .with_context(|| "Failed to serialize certificate")?;
    debug!("Certificate PEM size: {} bytes", cert_pem.len());

    debug!("Serializing private key to PEM format");
    let key_pem = cert.serialize_private_key_pem();
    debug!("Private key PEM size: {} bytes", key_pem.len());

    // Ensure parent directories exist
    if let Some(parent) = cert_path.parent() {
        debug!("Creating certificate directory: {:?}", parent);
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create certificate directory: {:?}", parent))?;
    }
    if let Some(parent) = key_path.parent() {
        debug!("Creating private key directory: {:?}", parent);
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create key directory: {:?}", parent))?;
    }

    // Write certificate and key files
    debug!("Writing certificate file");
    tokio::fs::write(cert_path, cert_pem)
        .await
        .with_context(|| format!("Failed to write certificate file: {:?}", cert_path))?;
    debug!("Certificate file written successfully");

    debug!("Writing private key file");
    tokio::fs::write(key_path, key_pem)
        .await
        .with_context(|| format!("Failed to write private key file: {:?}", key_path))?;
    debug!("Private key file written successfully");

    info!("Self-signed certificate generated successfully");
    info!("Certificate: {:?}", cert_path);
    info!("Private key: {:?}", key_path);
    debug!("Self-signed certificate generation completed");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
    async fn test_setup_tls_config_with_existing_certs() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        // Generate test certificates
        generate_self_signed_cert("test.example.com", &cert_path, &key_path)
            .await
            .unwrap();

        let config = TlsConfig {
            cert_path,
            key_path,
        };

        let result = setup_tls_config(&config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_setup_tls_config_generates_missing_certs() {
        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let config = TlsConfig {
            cert_path: cert_path.clone(),
            key_path: key_path.clone(),
        };

        // Certificates don't exist initially
        assert!(!cert_path.exists());
        assert!(!key_path.exists());

        let result = setup_tls_config(&config).await;
        assert!(result.is_ok());

        // Certificates should now exist
        assert!(cert_path.exists());
        assert!(key_path.exists());
    }
}
