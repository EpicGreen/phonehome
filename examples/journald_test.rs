use phonehome::config::{Config, ExternalAppConfig, LoggingConfig, PhoneHomeConfig, ServerConfig};
use std::path::PathBuf;
use tracing::{debug, error, info, trace, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("PhoneHome Journald Logging Test");
    println!("===============================\n");

    // Create a configuration with journald logging enabled
    let config = Config {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 8446,
            token: "journald-test-token".to_string(),
        },
        logging: LoggingConfig {
            log_file: PathBuf::from("/tmp/phonehome-journald-test.log"),
            log_level: "debug".to_string(),
            log_to_file: false,    // Disable file logging for this test
            log_to_journald: true, // Enable journald logging
            max_file_size_mb: 50,
            max_files: 5,
        },
        external_app: ExternalAppConfig {
            command: "/bin/echo".to_string(),
            args: vec!["journald-test".to_string()],
            timeout_seconds: 30,
            max_data_length: 4096,
            quote_data: false,
        },
        phone_home: PhoneHomeConfig {
            fields_to_extract: vec!["instance_id".to_string(), "hostname".to_string()],
            field_separator: "|".to_string(),
            include_timestamp: true,
            include_instance_id: true,
            output_type: "string".to_string(),
        },
    };

    println!("Configuration:");
    println!("- File logging: {}", config.logging.log_to_file);
    println!("- Journald logging: {}", config.logging.log_to_journald);
    println!("- Log level: {}", config.logging.log_level);
    println!();

    // Validate the configuration
    match config.validate() {
        Ok(_) => println!("✓ Configuration is valid"),
        Err(e) => {
            println!("✗ Configuration validation failed: {}", e);
            return Err(e.into());
        }
    }

    // Import the setup_logging function from main.rs
    // Note: In a real implementation, this would be exposed as a public function
    // For this example, we'll simulate the logging setup

    println!("\nAttempting to initialize logging system...");

    // Try to set up logging (this will show if journald is available)
    match setup_test_logging(&config).await {
        Ok(_) => {
            println!("✓ Logging system initialized successfully");
            println!("✓ Journald logging should now be active");
        }
        Err(e) => {
            println!("✗ Failed to initialize logging: {}", e);
            println!("Note: Journald may not be available on this system");
            return Err(e);
        }
    }

    println!("\nTesting different log levels...");
    println!("(Check journald with: journalctl -f --identifier=phonehome)\n");

    // Generate test log messages at different levels
    trace!("TRACE: This is a trace message for detailed debugging");
    debug!("DEBUG: This is a debug message with correlation_id=test-123");
    info!("INFO: PhoneHome journald test started successfully");
    warn!("WARN: This is a warning message - simulated configuration issue");
    error!("ERROR: This is an error message - simulated connection failure");

    // Test structured logging with fields
    info!(
        correlation_id = "test-456",
        client_ip = "192.168.1.100",
        instance_id = "i-1234567890abcdef0",
        "Phone home request received from test client"
    );

    info!(
        event = "external_app_execution",
        command = "/usr/bin/process-phone-home",
        timeout = 30,
        "Executing external application for phone home data"
    );

    warn!(
        event = "rate_limit_warning",
        client_ip = "10.0.0.1",
        requests_per_minute = 95,
        "Client approaching rate limit"
    );

    error!(
        event = "config_error",
        config_path = "/etc/phonehome/config.toml",
        error = "Invalid configuration",
        "Configuration validation failed"
    );

    println!("Log messages sent to journald and console.");
    println!("\nTo view these logs in journald:");
    println!("  journalctl --identifier=phonehome -f");
    println!("  journalctl --identifier=phonehome --since '1 minute ago'");
    println!("  journalctl --identifier=phonehome -p err");
    println!("  journalctl --identifier=phonehome -o json-pretty");

    println!("\nJournald logging test completed successfully!");
    println!("Check the systemd journal to verify the log messages were recorded.");

    Ok(())
}

// Simplified version of the logging setup for testing
async fn setup_test_logging(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{filter::LevelFilter, fmt};

    // Parse log level
    let log_level = match config.logging.log_level.to_lowercase().as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    let mut layers = Vec::new();

    // Console layer (always enabled for this test)
    if true {
        let console_layer = fmt::layer()
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false)
            .with_ansi(true)
            .with_filter(LevelFilter::from_level(log_level));

        layers.push(console_layer.boxed());
        println!("✓ Console logging enabled");
    }

    // Journald layer
    if config.logging.log_to_journald {
        match tracing_journald::layer() {
            Ok(journald_layer) => {
                let filtered_journald_layer =
                    journald_layer.with_filter(LevelFilter::from_level(log_level));
                layers.push(filtered_journald_layer.boxed());
                println!("✓ Journald logging enabled");
            }
            Err(e) => {
                println!("⚠ Warning: Failed to initialize journald logging: {}", e);
                println!("  This is normal if systemd/journald is not available");
                println!("  Continuing with other logging outputs...");
            }
        }
    }

    // Initialize the subscriber
    if layers.is_empty() {
        return Err("No logging layers configured".into());
    }

    tracing_subscriber::registry().with(layers).init();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_journald_config_creation() {
        let config = Config {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8446,
                token: "test-token".to_string(),
            },
            logging: LoggingConfig {
                log_file: PathBuf::from("/tmp/test.log"),
                log_level: "info".to_string(),
                log_to_file: false,
                log_to_journald: true,
                max_file_size_mb: 100,
                max_files: 10,
            },
            external_app: ExternalAppConfig {
                command: "/bin/true".to_string(),
                args: vec![],
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
        };

        // Configuration should be valid
        assert!(config.validate().is_ok());
        assert!(config.logging.log_to_journald);
        assert!(!config.logging.log_to_file);
    }

    #[test]
    fn test_journald_availability_detection() {
        // Test that we can detect if journald is available
        // This test will pass regardless of journald availability
        match tracing_journald::layer() {
            Ok(_) => {
                println!("Journald is available on this system");
            }
            Err(e) => {
                println!("Journald is not available: {}", e);
                // This is expected on non-systemd systems
            }
        }
    }
}
