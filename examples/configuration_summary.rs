use phonehome::config::{Config, ExternalAppConfig, LoggingConfig, PhoneHomeConfig, ServerConfig};
use std::path::PathBuf;

fn main() {
    println!("PhoneHome Configuration Summary");
    println!("===============================\n");

    println!("This example demonstrates the simplified configuration structure");
    println!("and new command-line interface introduced in the latest version.\n");

    // Show the simplified configuration structure
    println!("1. Simplified Configuration Structure");
    println!("====================================\n");

    let example_config = Config {
        server: ServerConfig {
            host: "0.0.0.0".to_string(),
            port: 443,
            token: "your-secure-token-here".to_string(),
        },
        logging: LoggingConfig {
            log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
            log_level: "info".to_string(),
            log_to_file: true,
            log_to_journald: false,
            max_file_size_mb: 100,
            max_files: 10,
        },
        external_app: ExternalAppConfig {
            command: "/usr/bin/process-phone-home".to_string(),
            args: vec![
                "--source".to_string(),
                "cloud-init".to_string(),
                "--data".to_string(),
                "{{PhoneHomeData}}".to_string(),
            ],
            timeout_seconds: 30,
            max_data_length: 4096,
            quote_data: true,
        },
        phone_home: PhoneHomeConfig {
            fields_to_extract: vec![
                "instance_id".to_string(),
                "hostname".to_string(),
                "fqdn".to_string(),
                "pub_key_rsa".to_string(),
                "pub_key_ecdsa".to_string(),
                "pub_key_ed25519".to_string(),
            ],
            field_separator: ", ".to_string(),
            include_timestamp: true,
            include_instance_id: true,
            output_type: "string".to_string(),
        },
    };

    println!("Key Changes Made:");
    println!("================");
    println!("• Renamed logging fields for clarity:");
    println!("  - enable_console → removed (now --no-daemon flag)");
    println!("  - enable_file → log_to_file");
    println!("  - enable_journald → log_to_journald");
    println!();
    println!("• Simplified external app configuration:");
    println!("  - Removed working_directory (runs in default directory)");
    println!("  - Removed environment variables (no custom env vars)");
    println!("  - Removed sanitize_input (always enabled for security)");
    println!("  - Removed allow_control_chars (always disabled for security)");
    println!();
    println!("• Added --no-daemon command line flag:");
    println!("  - Console output controlled by CLI, not config");
    println!("  - Better separation of runtime vs persistent logging");
    println!();

    // Show the new TOML structure
    println!("2. Example TOML Configuration");
    println!("=============================\n");

    match toml::to_string_pretty(&example_config) {
        Ok(toml_content) => {
            println!("{}", toml_content);
        }
        Err(e) => {
            println!("Error serializing config: {}", e);
        }
    }

    println!("\n3. Command Line Usage Examples");
    println!("==============================\n");

    println!("Production deployment (daemon mode):");
    println!("  phonehome --config /etc/phonehome/config.toml");
    println!("  # Runs in background, logs to file/journald only");
    println!();

    println!("Development mode (foreground with console output):");
    println!("  phonehome --config /etc/phonehome/config.toml --no-daemon");
    println!("  # Runs in foreground, shows logs on console");
    println!();

    println!("Debug mode with custom port:");
    println!("  phonehome --config /etc/phonehome/config.toml --no-daemon --debug --port 8443");
    println!("  # Debug logging, console output, custom port");
    println!();

    println!("4. Logging Configuration Options");
    println!("================================\n");

    let logging_examples = [
        (
            "File logging only (traditional)",
            LoggingConfig {
                log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
                log_level: "info".to_string(),
                log_to_file: true,
                log_to_journald: false,
                max_file_size_mb: 100,
                max_files: 10,
            },
        ),
        (
            "Journald only (systemd services)",
            LoggingConfig {
                log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
                log_level: "info".to_string(),
                log_to_file: false,
                log_to_journald: true,
                max_file_size_mb: 100,
                max_files: 10,
            },
        ),
        (
            "Both file and journald",
            LoggingConfig {
                log_file: PathBuf::from("/var/log/phonehome/phonehome.log"),
                log_level: "info".to_string(),
                log_to_file: true,
                log_to_journald: true,
                max_file_size_mb: 100,
                max_files: 10,
            },
        ),
        (
            "No persistent logging (console only via --no-daemon)",
            LoggingConfig {
                log_file: PathBuf::from("/tmp/phonehome-dev.log"),
                log_level: "debug".to_string(),
                log_to_file: false,
                log_to_journald: false,
                max_file_size_mb: 50,
                max_files: 5,
            },
        ),
    ];

    for (name, logging_config) in logging_examples {
        println!("{}:", name);
        println!("  log_to_file = {}", logging_config.log_to_file);
        println!("  log_to_journald = {}", logging_config.log_to_journald);
        println!("  log_level = \"{}\"", logging_config.log_level);
        if name.contains("console only") {
            println!("  # Use --no-daemon flag for console output");
        }
        println!();
    }

    println!("5. Output Type Examples");
    println!("======================\n");

    let output_examples = [
        ("string", "Pipe-separated values (default)", "2023-12-01T10:00:00Z, i-123, web-01, web-01.com, ssh-rsa AAAAB3..."),
        ("json", "JSON object format", r#"{"timestamp":"2023-12-01T10:00:00Z","instance_id":"i-123","hostname":"web-01"}"#),
        ("sql", "SQL INSERT statement", "INSERT INTO phone_home_data (timestamp, instance_id, hostname) VALUES ('2023-12-01T10:00:00Z', 'i-123', 'web-01');"),
    ];

    for (format_type, description, example) in output_examples {
        println!("output_type = \"{}\" - {}", format_type, description);
        println!("  Example: {}", example);
        println!();
    }

    println!("6. Security Improvements");
    println!("========================\n");

    println!("The following security measures are now hardcoded and always enabled:");
    println!("• Input sanitization: Always removes dangerous characters");
    println!("• Control character filtering: Blocks potentially harmful control sequences");
    println!("• No working directory changes: External apps run in default directory");
    println!("• No environment variables: Clean execution environment");
    println!("• Data length limits: Configurable max_data_length prevents oversized payloads");
    println!("• SQL injection protection: Single quotes escaped in SQL output format");
    println!();

    println!("7. Migration Guide");
    println!("==================\n");

    println!("To migrate from older versions:");
    println!("1. Update configuration field names:");
    println!("   enable_console → remove (use --no-daemon flag instead)");
    println!("   enable_file → log_to_file");
    println!("   enable_journald → log_to_journald");
    println!();
    println!("2. Remove deprecated external_app fields:");
    println!("   working_directory → remove");
    println!("   environment → remove");
    println!("   sanitize_input → remove (always enabled)");
    println!("   allow_control_chars → remove (always disabled)");
    println!();
    println!("3. Update startup commands:");
    println!("   For console output: add --no-daemon flag");
    println!("   For daemon mode: no changes needed");
    println!();

    println!("8. Validation Results");
    println!("====================\n");

    // Test configuration validation
    match example_config.validate() {
        Ok(_) => {
            println!("✓ Example configuration is valid");
            println!("✓ All required fields present");
            println!("✓ Security settings properly configured");
            println!("✓ Logging outputs properly configured");
        }
        Err(e) => {
            println!("✗ Configuration validation failed: {}", e);
        }
    }

    println!("\nConfiguration summary complete!");
    println!("Use this structure as a template for your production deployment.");
}
