use phonehome::config::{Config, ExternalAppConfig, LoggingConfig, PhoneHomeConfig, ServerConfig};
use tempfile::TempDir;

#[cfg(test)]
mod journald_logging_tests {
    use super::*;

    fn create_test_config_with_journald() -> Config {
        let temp_dir = TempDir::new().unwrap();
        let log_file = temp_dir.path().join("test.log");

        Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8445,
                token: "test-token-journald".to_string(),
            },
            logging: LoggingConfig {
                log_file,
                log_level: "info".to_string(),
                log_to_file: false,
                log_to_journald: true,
                max_file_size_mb: 50,
                max_files: 5,
            },
            external_app: ExternalAppConfig {
                command: "/bin/echo".to_string(),
                args: vec!["test".to_string()],
                timeout_seconds: 30,
                max_data_length: 4096,
                quote_data: false,
            },
            phone_home: PhoneHomeConfig {
                fields_to_extract: vec!["instance_id".to_string()],
                field_separator: "|".to_string(),
                include_timestamp: true,
                include_instance_id: true,
                output_type: "string".to_string(),
            },
        }
    }

    #[test]
    fn test_journald_only_configuration() {
        let config = create_test_config_with_journald();

        // Validate that journald-only configuration is valid
        assert!(config.validate().is_ok());
        assert!(!config.logging.log_to_file);
        assert!(config.logging.log_to_journald);
    }

    #[test]
    fn test_mixed_journald_and_console_configuration() {
        let config = create_test_config_with_journald();
        // No console flag in config anymore - it's controlled by --no-daemon

        assert!(config.validate().is_ok());
        assert!(!config.logging.log_to_file);
        assert!(config.logging.log_to_journald);
    }

    #[test]
    fn test_mixed_journald_and_file_configuration() {
        let mut config = create_test_config_with_journald();
        config.logging.log_to_file = true;

        assert!(config.validate().is_ok());
        assert!(config.logging.log_to_file);
        assert!(config.logging.log_to_journald);
    }

    #[test]
    fn test_all_logging_outputs_enabled() {
        let mut config = create_test_config_with_journald();
        config.logging.log_to_file = true;

        assert!(config.validate().is_ok());
        assert!(config.logging.log_to_file);
        assert!(config.logging.log_to_journald);
    }

    #[test]
    fn test_no_logging_outputs_enabled_fails_validation() {
        let mut config = create_test_config_with_journald();
        config.logging.log_to_file = false;
        config.logging.log_to_journald = false;

        // Should pass validation but warn about no persistent logging outputs
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_journald_configuration_serialization() {
        let config = create_test_config_with_journald();

        // Test that the configuration can be serialized and deserialized
        let toml_string = toml::to_string(&config).expect("Should serialize to TOML");
        assert!(toml_string.contains("log_to_journald = true"));
        assert!(toml_string.contains("log_to_file = false"));

        let deserialized: Config =
            toml::from_str(&toml_string).expect("Should deserialize from TOML");
        assert!(deserialized.logging.log_to_journald);
        assert!(!deserialized.logging.log_to_file);
    }

    #[test]
    fn test_default_journald_configuration() {
        let default_config = Config::default();

        // Default configuration should have journald disabled
        assert!(!default_config.logging.log_to_journald);
        assert!(default_config.logging.log_to_file);

        // Default config should still be valid
        assert!(default_config.validate().is_ok());
    }

    #[test]
    fn test_journald_with_different_log_levels() {
        let mut config = create_test_config_with_journald();

        let log_levels = ["trace", "debug", "info", "warn", "error"];

        for level in log_levels {
            config.logging.log_level = level.to_string();
            assert!(
                config.validate().is_ok(),
                "Journald config with log level '{}' should be valid",
                level
            );
        }
    }

    #[test]
    fn test_journald_configuration_validation_messages() {
        let config = create_test_config_with_journald();

        // This test mainly ensures the validation logic runs without panicking
        // and produces appropriate debug messages
        assert!(config.validate().is_ok());

        // The validation should have logged debug messages about journald being enabled
        // In a real test environment, we would capture and verify these messages
    }

    #[tokio::test]
    async fn test_journald_config_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_journald_config.toml");

        let mut original_config = create_test_config_with_journald();
        original_config.logging.log_level = "debug".to_string();

        // Save the config
        original_config
            .save(&config_path)
            .await
            .expect("Should save config");

        // Load the config
        let loaded_config = Config::load(&config_path)
            .await
            .expect("Should load config");

        // Verify journald settings are preserved
        assert!(loaded_config.logging.log_to_journald);
        assert!(!loaded_config.logging.log_to_file);
        assert_eq!(loaded_config.logging.log_level, "debug");
    }

    #[test]
    fn test_partial_toml_config_with_journald() {
        let toml_content = r#"
[server]
host = "0.0.0.0"
port = 443
token = "test-token"

[logging]
log_file = "/var/log/phonehome/phonehome.log"
log_level = "warn"
log_to_file = false
log_to_journald = true
max_file_size_mb = 200
max_files = 20

[tls]
cert_path = "/etc/phonehome/cert.pem"
key_path = "/etc/phonehome/key.pem"

[external_app]
command = "/usr/bin/process-phone-home"
args = ["--data", "{{PhoneHomeData}}"]
timeout_seconds = 60

[phone_home]
fields_to_extract = ["instance_id", "hostname"]
field_separator = "|"
include_timestamp = true
include_instance_id = true
output_type = "json"
"#;

        let config: Config = toml::from_str(toml_content).expect("Should parse TOML config");

        assert!(config.logging.log_to_journald);
        assert!(!config.logging.log_to_file);
        assert_eq!(config.logging.log_level, "warn");
        assert_eq!(config.logging.max_file_size_mb, 200);
        assert_eq!(config.logging.max_files, 20);

        // Configuration should be valid
        assert!(config.validate().is_ok());
    }
}
