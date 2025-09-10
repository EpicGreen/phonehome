use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub logging: LoggingConfig,
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
pub struct LoggingConfig {
    pub log_file: PathBuf,
    pub log_level: String,
    pub enable_console: bool,
    pub enable_file: bool,
    pub max_file_size_mb: u64,
    pub max_files: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalAppConfig {
    pub command: String,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    pub working_directory: Option<PathBuf>,
    pub environment: Option<std::collections::HashMap<String, String>>,
    
    // Security settings
    #[serde(default = "default_max_data_length")]
    pub max_data_length: usize,
    #[serde(default)]
    pub allow_control_chars: bool,
    #[serde(default = "default_true")]
    pub sanitize_input: bool,
    #[serde(default)]
    pub quote_data: bool,
}

fn default_max_data_length() -> usize {
    4096
}

fn default_true() -> bool {
    true
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
                host: "127.0.0.1".to_string(),
                port: 8443,
                token: "your-secret-token-here".to_string(),
            },
            logging: LoggingConfig {
                log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
                log_level: "info".to_string(),
                enable_console: true,
                enable_file: true,
                max_file_size_mb: 100,
                max_files: 10,
            },
            tls: Some(TlsConfig {
                cert_path: PathBuf::from("/var/lib/phonehome/cert.pem"),
                key_path: PathBuf::from("/var/lib/phonehome/key.pem"),
            }),
            external_app: ExternalAppConfig {
                command: "/usr/local/bin/process-phone-home".to_string(),
                args: vec!["--data".to_string()],
                timeout_seconds: 30,
                working_directory: None,
                environment: None,
                max_data_length: 4096,
                allow_control_chars: false,
                sanitize_input: true,
                quote_data: false,
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
        info!("Loading configuration from: {:?}", path);

        if !path.exists() {
            warn!(
                "Configuration file {:?} does not exist, creating default config",
                path
            );
            let default_config = Self::default();
            debug!("Generated default configuration: {:#?}", default_config);

            default_config
                .save(path)
                .await
                .context("Failed to save default configuration")?;
            info!("Default configuration saved to: {:?}", path);
            return Ok(default_config);
        }

        debug!("Reading configuration file content");
        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read configuration file: {:?}", path))?;

        debug!("Configuration file size: {} bytes", content.len());
        debug!("Raw configuration content:\n{}", content);

        debug!("Parsing TOML configuration");
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse configuration file: {:?}", path))?;

        debug!("Parsed configuration: {:#?}", config);
        info!("Configuration loaded successfully from: {:?}", path);

        debug!("Validating configuration");
        config
            .validate()
            .context("Configuration validation failed")?;
        info!("Configuration validation passed");

        Ok(config)
    }

    pub async fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        info!("Saving configuration to: {:?}", path);

        if let Some(parent) = path.parent() {
            debug!("Creating parent directory: {:?}", parent);
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        debug!("Serializing configuration to TOML");
        let content =
            toml::to_string_pretty(self).context("Failed to serialize configuration to TOML")?;

        debug!("Configuration content size: {} bytes", content.len());
        debug!("Configuration content:\n{}", content);

        debug!("Writing configuration file");
        fs::write(path, content)
            .await
            .with_context(|| format!("Failed to write configuration file: {:?}", path))?;

        info!("Configuration saved successfully to: {:?}", path);
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        debug!("Starting configuration validation");

        // Validate server configuration
        debug!("Validating server configuration");
        if self.server.token.is_empty() {
            error!("Server token cannot be empty");
            anyhow::bail!("Server token cannot be empty");
        }

        if self.server.token == "your-secret-token-here" {
            warn!("Using default token - please change this for production use");
        } else {
            debug!(
                "Server token is configured (length: {})",
                self.server.token.len()
            );
        }

        if self.server.port == 0 {
            error!("Server port must be greater than 0");
            anyhow::bail!("Server port must be greater than 0");
        }
        debug!("Server port validation passed: {}", self.server.port);

        // TLS configuration validation
        debug!("Validating TLS configuration");
        if let Some(ref tls) = self.tls {
            debug!(
                "TLS enabled - cert: {:?}, key: {:?}",
                tls.cert_path, tls.key_path
            );
        } else {
            debug!("TLS disabled - server will run in HTTP mode");
        }

        // Validate external app configuration
        debug!("Validating external application configuration");
        if self.external_app.command.is_empty() {
            error!("External application command cannot be empty");
            anyhow::bail!("External application command cannot be empty");
        }
        debug!("External app command: {}", self.external_app.command);
        debug!("External app args: {:?}", self.external_app.args);
        debug!(
            "External app timeout: {} seconds",
            self.external_app.timeout_seconds
        );

        if self.external_app.timeout_seconds == 0 {
            error!("External application timeout must be greater than 0");
            anyhow::bail!("External application timeout must be greater than 0");
        }

        if let Some(ref working_dir) = self.external_app.working_directory {
            debug!("External app working directory: {:?}", working_dir);
        }

        if let Some(ref env) = self.external_app.environment {
            debug!("External app environment variables: {:?}", env);
        }

        // Validate security settings
        debug!("Validating external app security settings");
        debug!("Max data length: {} bytes", self.external_app.max_data_length);
        debug!("Allow control chars: {}", self.external_app.allow_control_chars);
        debug!("Sanitize input: {}", self.external_app.sanitize_input);
        debug!("Quote data: {}", self.external_app.quote_data);

        if self.external_app.max_data_length == 0 {
            error!("Max data length must be greater than 0");
            anyhow::bail!("Max data length must be greater than 0");
        }

        if self.external_app.max_data_length > 1_000_000 {
            warn!("Max data length is very large: {} bytes", self.external_app.max_data_length);
        }

        // Validate logging configuration
        debug!("Validating logging configuration");
        debug!("Log file: {:?}", self.logging.log_file);
        debug!("Log level: {}", self.logging.log_level);
        debug!("Console logging: {}", self.logging.enable_console);
        debug!("File logging: {}", self.logging.enable_file);

        // Validate log level
        match self.logging.log_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {
                debug!("Log level validation passed: {}", self.logging.log_level);
            }
            _ => {
                error!(
                    "Invalid log level: {}. Must be one of: trace, debug, info, warn, error",
                    self.logging.log_level
                );
                anyhow::bail!("Invalid log level: {}", self.logging.log_level);
            }
        }

        if self.logging.enable_file {
            if let Some(parent) = self.logging.log_file.parent() {
                debug!("Log file directory: {:?}", parent);
            }
        }

        // Validate phone home configuration
        debug!("Validating phone home configuration");
        debug!("Fields to extract: {:?}", self.phone_home.fields_to_extract);
        debug!("Field separator: '{}'", self.phone_home.field_separator);
        debug!("Include timestamp: {}", self.phone_home.include_timestamp);
        debug!(
            "Include instance ID: {}",
            self.phone_home.include_instance_id
        );

        if self.phone_home.fields_to_extract.is_empty() {
            warn!("No fields configured for extraction - external app will receive empty data");
        } else {
            info!(
                "Configured to extract {} fields",
                self.phone_home.fields_to_extract.len()
            );
        }

        info!("Configuration validation completed successfully");
        Ok(())
    }

    pub fn get_phone_home_url(&self) -> String {
        let use_https = self.tls.is_some();
        let scheme = if use_https { "https" } else { "http" };
        let url = format!(
            "{}://{}:{}/phone-home/{}",
            scheme, self.server.host, self.server.port, self.server.token
        );

        debug!("Generated phone home URL: {}", url);
        info!("Phone home URL generated with {} protocol", scheme);

        url
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
        let url = config.get_phone_home_url();
        assert!(url.starts_with("https://"));
        assert!(url.contains(&config.server.token));
    }
}
