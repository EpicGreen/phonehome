use phonehome::config::{
    Config, ExternalAppConfig, LoggingConfig, PhoneHomeConfig, ServerConfig, TlsConfig,
};
use std::path::PathBuf;

fn main() {
    println!("PhoneHome Logging Configuration Demo");
    println!("====================================\n");

    // Example 1: Console-only logging
    println!("1. Console-only logging configuration:");
    println!("-------------------------------------");
    let console_config = LoggingConfig {
        log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
        log_level: "info".to_string(),
        log_to_file: false,
        log_to_journald: false,
        max_file_size_mb: 100,
        max_files: 10,
    };

    println!("log_to_file = {}", console_config.log_to_file);
    println!("log_to_journald = {}", console_config.log_to_journald);
    println!("Use case: Development and testing (use --no-daemon for console output)");
    println!("Benefits: Real-time log viewing, no disk usage\n");

    // Example 2: File-only logging
    println!("2. File-only logging configuration:");
    println!("-----------------------------------");
    let file_config = LoggingConfig {
        log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
        log_level: "info".to_string(),
        log_to_file: true,
        log_to_journald: false,
        max_file_size_mb: 100,
        max_files: 10,
    };

    println!("log_to_file = {}", file_config.log_to_file);
    println!("log_to_journald = {}", file_config.log_to_journald);
    println!("log_file = {:?}", file_config.log_file);
    println!("Use case: Traditional logging, logrotate integration");
    println!("Benefits: Persistent logs, external rotation management\n");

    // Example 3: Journald-only logging
    println!("3. Journald-only logging configuration:");
    println!("---------------------------------------");
    let journald_config = LoggingConfig {
        log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
        log_level: "info".to_string(),
        log_to_file: false,
        log_to_journald: true,
        max_file_size_mb: 100,
        max_files: 10,
    };

    println!("log_to_file = {}", journald_config.log_to_file);
    println!("log_to_journald = {}", journald_config.log_to_journald);
    println!("Use case: Systemd-based systems, centralized logging");
    println!("Benefits: Structured logging, systemd integration");
    println!("View logs with: journalctl -u phonehome -f\n");

    // Example 4: Hybrid logging (all outputs enabled)
    println!("4. Hybrid logging configuration:");
    println!("--------------------------------");
    let hybrid_config = LoggingConfig {
        log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
        log_level: "debug".to_string(),
        log_to_file: true,
        log_to_journald: true,
        max_file_size_mb: 200,
        max_files: 15,
    };

    println!("log_to_file = {}", hybrid_config.log_to_file);
    println!("log_to_journald = {}", hybrid_config.log_to_journald);
    println!("log_level = {}", hybrid_config.log_level);
    println!("Use case: Production systems with comprehensive logging");
    println!("Benefits: Console (--no-daemon) + persistent storage + systemd integration\n");

    // Example 5: Show different log levels
    println!("5. Log level examples:");
    println!("---------------------");
    let log_levels = [
        ("trace", "Most verbose - includes all debug information"),
        ("debug", "Development debugging - detailed execution flow"),
        ("info", "General information - normal operations"),
        (
            "warn",
            "Warnings - potential issues that don't stop execution",
        ),
        ("error", "Errors only - critical issues"),
    ];

    for (level, description) in log_levels {
        println!("log_level = \"{}\" - {}", level, description);
    }
    println!();

    // Example 6: TOML configuration examples
    println!("6. TOML Configuration Examples:");
    println!("-------------------------------");

    println!("For journald only (recommended for systemd services):");
    println!("[logging]");
    println!("log_file = \"/var/log/phonehome/phonehome.log\"");
    println!("log_level = \"info\"");
    println!("log_to_file = false");
    println!("log_to_journald = true");
    println!("max_file_size_mb = 100");
    println!("max_files = 10\n");

    println!("For traditional file logging:");
    println!("[logging]");
    println!("log_file = \"/var/log/phonehome/phonehome.log\"");
    println!("log_level = \"info\"");
    println!("log_to_file = true");
    println!("log_to_journald = false");
    println!("max_file_size_mb = 100");
    println!("max_files = 10\n");

    println!("For development (console via --no-daemon):");
    println!("[logging]");
    println!("log_file = \"/tmp/phonehome-dev.log\"");
    println!("log_level = \"debug\"");
    println!("log_to_file = false");
    println!("log_to_journald = false");
    println!("max_file_size_mb = 50");
    println!("max_files = 5");
    println!("# Run with: phonehome --no-daemon\n");

    // Example 7: Validation demonstration
    println!("7. Configuration Validation:");
    println!("----------------------------");

    // Create a complete config for validation testing
    let create_test_config = |logging: LoggingConfig| -> Config {
        Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8443,
                token: "demo-token".to_string(),
            },
            logging,
            tls: Some(TlsConfig {
                cert_path: PathBuf::from("/var/lib/phonehome/cert.pem"),
                key_path: PathBuf::from("/var/lib/phonehome/key.pem"),
            }),
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
    };

    // Test valid configurations
    let valid_configs = [
        ("Console only (needs --no-daemon)", console_config.clone()),
        ("File only", file_config.clone()),
        ("Journald only", journald_config.clone()),
        ("Hybrid", hybrid_config.clone()),
    ];

    for (name, logging_config) in valid_configs {
        let config = create_test_config(logging_config);
        match config.validate() {
            Ok(_) => println!("✓ {} configuration is valid", name),
            Err(e) => println!("✗ {} configuration failed: {}", name, e),
        }
    }

    // Test invalid configuration (no outputs enabled)
    let invalid_config = LoggingConfig {
        log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
        log_level: "info".to_string(),
        log_to_file: false,
        log_to_journald: false,
        max_file_size_mb: 100,
        max_files: 10,
    };

    let invalid_test_config = create_test_config(invalid_config);
    match invalid_test_config.validate() {
        Ok(_) => println!("✓ No persistent logging outputs - console available via --no-daemon"),
        Err(e) => println!("✗ Configuration failed unexpectedly: {}", e),
    }

    println!("\n8. Command Line Options:");
    println!("------------------------");
    println!("• --no-daemon: Run in foreground with console output");
    println!("• --debug: Enable debug logging (overrides config)");
    println!("• --config: Specify custom configuration file");
    println!("• --port: Override port from configuration");

    println!("\n9. Systemd Integration Tips:");
    println!("----------------------------");
    println!("• Use log_to_journald = true for systemd services");
    println!("• View logs: journalctl -u phonehome -f");
    println!("• Follow logs: journalctl -u phonehome --since today");
    println!("• Filter by priority: journalctl -u phonehome -p err");
    println!("• Export logs: journalctl -u phonehome --since '2023-01-01' -o json");

    println!("\n10. Log Rotation:");
    println!("----------------");
    println!("• File logging: Uses daily rotation automatically");
    println!("• Journald: Managed by systemd (journald.conf)");
    println!("• External tools: Configure logrotate for file-based logs");
    println!("• max_file_size_mb and max_files are for reference by external tools");

    println!("\nDemo completed successfully!");
    println!("Choose the logging configuration that best fits your deployment environment.");
    println!("Use --no-daemon for development and console output.");
}
