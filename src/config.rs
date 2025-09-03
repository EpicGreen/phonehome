use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use anyhow::{Context, Result};
use tokio::fs;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: Option<TlsConfig>,
    pub external_app: ExternalAppConfig,
    pub phone_home: PhoneHomeConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub token: String,
}



#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub use_letsencrypt: bool,
    pub domain: Option<String>,
    pub email: Option<String>,
    pub acme_directory: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalAppConfig {
    pub command: String,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    pub working_directory: Option<PathBuf>,
    pub environment: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PhoneHomeConfig {
    pub fields_to_extract: Vec<String>,
    pub field_separator: String,
    pub include_timestamp: bool,
    pub include_instance_id: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8443,
                token: "your-secret-token-here".to_string(),
            },
            tls: Some(TlsConfig {
                cert_path: PathBuf::from("/etc/letsencrypt/live/your-domain.com/fullchain.pem"),
                key_path: PathBuf::from("/etc/letsencrypt/live/your-domain.com/privkey.pem"),
                use_letsencrypt: true,
                domain: Some("your-domain.com".to_string()),
                email: Some("admin@your-domain.com".to_string()),
                acme_directory: Some("https://acme-v02.api.letsencrypt.org/directory".to_string()),
            }),
            external_app: ExternalAppConfig {
                command: "/usr/local/bin/process-phone-home".to_string(),
                args: vec!["--data".to_string()],
                timeout_seconds: 30,
                working_directory: None,
                environment: None,
            },
            phone_home: PhoneHomeConfig {
                fields_to_extract: vec![
                    "instance_id".to_string(),
                    "public_keys".to_string(),
                    "hostname".to_string(),
                    "fqdn".to_string(),
                ],
                field_separator: "|".to_string(),
                include_timestamp: true,
                include_instance_id: true,
            },
        }
    }
}

impl Config {
    pub async fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        
        if !path.exists() {
            tracing::warn!("Configuration file {:?} does not exist, creating default config", path);
            let default_config = Self::default();
            default_config.save(path).await.context("Failed to save default configuration")?;
            return Ok(default_config);
        }

        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read configuration file: {:?}", path))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse configuration file: {:?}", path))?;

        config.validate().context("Configuration validation failed")?;

        Ok(config)
    }

    pub async fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        let content = toml::to_string_pretty(self)
            .context("Failed to serialize configuration to TOML")?;

        fs::write(path, content)
            .await
            .with_context(|| format!("Failed to write configuration file: {:?}", path))?;

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        // Validate server configuration
        if self.server.token.is_empty() {
            anyhow::bail!("Server token cannot be empty");
        }

        if self.server.token == "your-secret-token-here" {
            tracing::warn!("Using default token - please change this for production use");
        }

        if self.server.port == 0 {
            anyhow::bail!("Server port must be greater than 0");
        }

        // Validate TLS configuration if present
        if let Some(ref tls) = self.tls {
            if tls.use_letsencrypt {
                if tls.domain.is_none() {
                    anyhow::bail!("Domain is required when using Let's Encrypt");
                }
                if tls.email.is_none() {
                    anyhow::bail!("Email is required when using Let's Encrypt");
                }
            } else {
                if !tls.cert_path.exists() {
                    anyhow::bail!("TLS certificate file does not exist: {:?}", tls.cert_path);
                }
                if !tls.key_path.exists() {
                    anyhow::bail!("TLS private key file does not exist: {:?}", tls.key_path);
                }
            }
        }

        // Validate external app configuration
        if self.external_app.command.is_empty() {
            anyhow::bail!("External application command cannot be empty");
        }

        if self.external_app.timeout_seconds == 0 {
            anyhow::bail!("External application timeout must be greater than 0");
        }

        // Validate phone home configuration
        if self.phone_home.fields_to_extract.is_empty() {
            tracing::warn!("No fields configured for extraction - external app will receive empty data");
        }

        Ok(())
    }

    pub fn get_phone_home_url(&self, dev_mode: bool) -> String {
        let use_https = self.tls.is_some() || dev_mode;
        let scheme = if use_https { "https" } else { "http" };
        format!("{}://{}:{}/phone-home/{}", 
                scheme, 
                self.server.host, 
                self.server.port, 
                self.server.token)
    }

    pub fn is_running_under_cargo() -> bool {
        // Check for cargo environment variables that are set when running under cargo
        if std::env::var("CARGO_PKG_NAME").is_ok() {
            return true;
        }
        
        // Check if executable path indicates cargo build
        if let Ok(exe_path) = std::env::current_exe() {
            let path_str = exe_path.to_string_lossy();
            if path_str.contains("target/debug") || path_str.contains("target/release") {
                return true;
            }
        }
        
        false
    }

    pub fn get_dev_cert_paths() -> (PathBuf, PathBuf) {
        (PathBuf::from("dev_cert.pem"), PathBuf::from("dev_key.pem"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_load_and_save() {
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path();

        // Delete the temp file so load will create default config
        std::fs::remove_file(config_path).unwrap();

        // Load should create default config
        let config = Config::load(config_path).await.unwrap();
        assert_eq!(config.server.port, 8443);

        // Modify and save
        let mut modified_config = config;
        modified_config.server.port = 9443;
        modified_config.save(config_path).await.unwrap();

        // Load again and verify changes
        let loaded_config = Config::load(config_path).await.unwrap();
        assert_eq!(loaded_config.server.port, 9443);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        
        // Valid config should pass (but will warn about default token)
        config.validate().unwrap();

        // Empty token should fail
        config.server.token = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_phone_home_url_generation() {
        let config = Config::default();
        let url = config.get_phone_home_url(false);
        assert!(url.starts_with("https://"));
        assert!(url.contains(&config.server.token));
    }

    #[test]
    fn test_dev_mode_url_generation() {
        let config = Config::default();
        let url_dev = config.get_phone_home_url(true);
        let url_prod = config.get_phone_home_url(false);
        
        assert!(url_dev.starts_with("https://"));
        assert!(url_prod.starts_with("https://")); // Due to default TLS config
        assert!(url_dev.contains(&config.server.token));
    }

    #[test]
    fn test_get_dev_cert_paths() {
        let (cert_path, key_path) = Config::get_dev_cert_paths();
        assert_eq!(cert_path, PathBuf::from("dev_cert.pem"));
        assert_eq!(key_path, PathBuf::from("dev_key.pem"));
    }
}