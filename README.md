# PhoneHome Server

A secure, lightweight HTTPS server designed to receive and process phone home data from cloud-init instances. This server provides a simple API endpoint for cloud instances to report their initialization status and system information over TLS-encrypted connections.

## Features

- **Secure HTTPS-only server** with automatic self-signed certificate generation
- **Cloud-init integration** via standard phone home module
- **External application execution** with configurable data processing
- **Rate limiting** to prevent abuse
- **Comprehensive logging** with request correlation tracking
- **Data sanitization** and security controls
- **Flexible configuration** via TOML files
- **RPM packaging** for easy deployment
- **Web interface** for status monitoring

## Quick Start

### 1. Build the Project

```bash
git clone <repository-url>
cd phonehome
cargo build --release
```

### 2. Configure the Server

Copy the example configuration and modify it for your environment:

```bash
sudo mkdir -p /etc/phonehome
sudo cp etc/phonehome/config.toml /etc/phonehome/
sudo vim /etc/phonehome/config.toml
```

### 3. Install via RPM (Recommended)

```bash
# Build RPM package
cargo install cargo-generate-rpm
cargo generate-rpm

# Install the package
sudo dnf install target/generate-rpm/phonehome-*.rpm
```

### 4. Configure Logging

```bash
sudo mkdir -p /var/log/phonehome
sudo chown phonehome:phonehome /var/log/phonehome
```

### 5. Set Up TLS Certificates

The server requires TLS certificates and will automatically generate self-signed certificates if none are provided:

```bash
# Self-signed certificates will be automatically created in:
# /var/lib/phonehome/cert.pem
# /var/lib/phonehome/key.pem

# For production, provide your own certificates by updating config.toml:
# cert_path = "/path/to/your/cert.pem"  
# key_path = "/path/to/your/key.pem"
```

**Note**: The server operates in HTTPS-only mode. Self-signed certificates are suitable for internal networks, but production deployments should use certificates from a trusted CA.

### 6. Create an External Application

Create a simple processor for the phone home data:

```bash
sudo cat > /usr/local/bin/process-phone-home << 'EOF'
#!/bin/bash
# Data is passed as the first argument via ${PhoneHomeData} placeholder
DATA="$1"
echo "$(date): Received phone home data: $DATA" >> /var/log/phonehome/phone-home.log

# Parse pipe-separated data
IFS='|' read -ra FIELDS <<< "$DATA"
echo "Instance ${FIELDS[1]} (${FIELDS[2]}) is online" >> /var/log/phonehome/phone-home.log
EOF

sudo chmod +x /usr/local/bin/process-phone-home
```

### 7. Run the Server

```bash
# Via systemd (if installed via RPM)
sudo systemctl enable phonehome
sudo systemctl start phonehome

# Or run directly (daemon mode)
sudo /usr/local/bin/phonehome --config /etc/phonehome/config.toml

# For development (foreground with console output)
sudo /usr/local/bin/phonehome --config /etc/phonehome/config.toml --no-daemon
```

### 8. Test the Setup

```bash
# Check server status
curl -k https://localhost:443/health

# Test phone home endpoint (replace YOUR_TOKEN with actual token)
curl -k -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d "instance_id=i-1234567890&hostname=test-host&fqdn=test-host.example.com" \
  https://localhost:443/phone-home/YOUR_TOKEN
```

## Web Interface

The server provides a simple web interface accessible at the root URL:

- **Status page**: Shows server information and configuration
- **Health endpoint**: `/health` - Returns server status
- **Phone home endpoint**: `/phone-home/{token}` - Receives cloud-init data

## Configuration

Configuration is managed via a TOML file (default: `/etc/phonehome/config.toml`).

### Server Configuration

```toml
[server]
host = "0.0.0.0"           # Bind address (0.0.0.0 for all interfaces)
port = 443                 # Port to listen on
token = "your-secret-token-here"  # Authentication token for phone home requests
```

### TLS Configuration

```toml
[tls]
cert_path = "/var/lib/phonehome/cert.pem"  # TLS certificate file
key_path = "/var/lib/phonehome/key.pem"    # TLS private key file
```

**Note**: The server requires TLS certificates to operate. If the specified certificate files don't exist, the server will automatically generate self-signed certificates for immediate use.

### Logging Configuration

The server supports multiple logging outputs:

```toml
[logging]
log_file = "/var/log/phonehome/phonehome.log"  # Log file path
log_level = "info"                             # Log level (trace, debug, info, warn, error)
log_to_file = true                             # Enable file logging with daily rotation
log_to_journald = false                        # Enable systemd journald logging
max_file_size_mb = 100                        # Maximum log file size before rotation
max_files = 10                                # Number of rotated log files to keep
```

#### Logging Output Options

- **Console logging**: Enabled via `--no-daemon` command line flag for development and debugging
- **File logging** (`log_to_file`): Traditional log files with daily rotation, compatible with logrotate
- **Journald logging** (`log_to_journald`): Systemd journal integration for structured logging

**Note**: Console output is controlled by the `--no-daemon` flag, not configuration. At least one persistent logging output (file or journald) should be enabled for production use.

#### Systemd Journal Integration

When `enable_journald = true`, logs are sent to the systemd journal:

```bash
# View logs in real-time
journalctl -u phonehome -f

# View logs since today
journalctl -u phonehome --since today

# Filter by log level (err, warning, info, debug)
journalctl -u phonehome -p err

# Export logs as JSON
journalctl -u phonehome --since '2023-01-01' -o json
```

#### Configuration Examples

**Production (Journald only)**:
```toml
[logging]
log_to_file = false
log_to_journald = true
log_level = "info"
```

**Development (Console with --no-daemon)**:
```toml
[logging]
log_to_file = false
log_to_journald = false
log_level = "debug"
```
Run with: `phonehome --no-daemon`

**Comprehensive (File + Journald)**:
```toml
[logging]
log_to_file = true
log_to_journald = true
log_level = "info"
```
Add `--no-daemon` for console output during development.

### External Application Configuration

The server can execute external applications when phone home data is received. Data is passed via the `${PhoneHomeData}` placeholder in arguments.

```toml
[external_app]
command = "/usr/local/bin/process-phone-home"  # Command to execute
args = ["${PhoneHomeData}"]                    # Arguments (${PhoneHomeData} will be replaced)
timeout_seconds = 30                           # Execution timeout

# Security settings
max_data_length = 4096                         # Maximum data length in bytes
quote_data = false                             # Quote data when using ${PhoneHomeData} (default: false)
```

**Security**: Input data is automatically sanitized and control characters are filtered for security. The external application runs with no special environment variables or working directory.

**Data Passing**: Phone home data is passed to your external application via the `${PhoneHomeData}` placeholder in the arguments configuration. Your application receives this data as command line arguments.

### Phone Home Data Processing

```toml
[phone_home]
# Fields to extract from cloud-init form data
fields_to_extract = [
    "instance_id",
    "hostname", 
    "fqdn",
    "pub_key_rsa",
    "pub_key_ecdsa",
    "pub_key_ed25519"
]
field_separator = "|"                          # Separator between fields (used for string output)
include_timestamp = true                       # Include timestamp as first field
include_instance_id = true                     # Include instance_id separately

# Output format type for the extracted data
# Available options:
# - "string": Pipe-separated string format (default, backward compatible)
# - "json": JSON object format
# - "sql": SQL INSERT query format
output_type = "string"
```

#### Output Format Examples

With the same input data, the different output types produce:

**String format** (`output_type = "string"`):
```
2023-12-01T10:00:00Z|i-1234567890abcdef0|web-server-01|web-server-01.example.com|ssh-rsa AAAAB3...
```

**JSON format** (`output_type = "json"`):
```json
{"timestamp":"2023-12-01T10:00:00Z","instance_id":"i-1234567890abcdef0","hostname":"web-server-01","fqdn":"web-server-01.example.com","pub_key_rsa":"ssh-rsa AAAAB3..."}
```

**SQL format** (`output_type = "sql"`):
```sql
INSERT INTO phone_home_data (timestamp, instance_id, hostname, fqdn, pub_key_rsa) VALUES ('2023-12-01T10:00:00Z', 'i-1234567890abcdef0', 'web-server-01', 'web-server-01.example.com', 'ssh-rsa AAAAB3...');
```

**Security Note**: SQL format automatically escapes single quotes to prevent injection attacks, but external applications should still use parameterized queries for maximum security.
```

## Cloud Init Integration

To integrate with cloud-init, add the phone home configuration to your cloud-init config:

### Cloud-Init Configuration

```yaml
#cloud-config
phone_home:
  url: https://your-server.com:443/phone-home/your-secret-token
  post: all
  tries: 3
```

**Important**: The URL must use `https://` as the server only accepts TLS-encrypted connections.

This configuration tells cloud-init to send phone home data to your server after instance initialization.

## Available Data Fields

The following fields can be extracted from cloud-init phone home requests:

### Standard Cloud-Init Fields

- `instance_id` - Cloud instance identifier
- `hostname` - System hostname  
- `fqdn` - Fully qualified domain name
- `pub_key_rsa` - RSA SSH public key
- `pub_key_ecdsa` - ECDSA SSH public key  
- `pub_key_ed25519` - Ed25519 SSH public key

## API Endpoints

### Phone Home Endpoint

**POST** `/phone-home/{token}`

Receives phone home data from cloud-init instances.

#### Request Format

Cloud-init sends data as `application/x-www-form-urlencoded`:

```
instance_id=i-1234567890&hostname=web-server&fqdn=web-server.example.com&pub_key_rsa=ssh-rsa+AAAA...
```

#### Response

```json
{
  "status": "success",
  "message": "Phone home data processed successfully", 
  "instance_id": "i-1234567890",
  "timestamp": "2024-01-15T10:30:00Z",
  "processed_fields": 6,
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Health Check Endpoint

**GET** `/health`

Returns server health status.

```json
{
  "status": "healthy",
  "version": "0.1.10",
  "uptime": "2h 30m 45s"
}
```

## Command Line Options

```bash
phonehome [OPTIONS]

Options:
    -c, --config <FILE>    Configuration file path [default: /etc/phonehome/config.toml]
    -d, --debug            Enable debug logging
    -p, --port <PORT>      Override port from config
    -h, --help             Print help information
    -V, --version          Print version information
```

## Security Considerations

- **Token Authentication**: All phone home requests require a valid token
- **Rate Limiting**: Built-in rate limiting prevents abuse
- **Input Sanitization**: All data is sanitized before processing
- **TLS Encryption**: All communication encrypted via HTTPS
- **Data Length Limits**: Configurable maximum data size
- **Correlation IDs**: All requests are tracked with unique correlation IDs

## External Application Examples

### Simple Logging

```bash
#!/bin/bash
# Data is passed as first argument via ${PhoneHomeData} placeholder
DATA="$1"
LOGFILE="/var/log/phonehome.log"
echo "$(date -Iseconds): $DATA" >> "$LOGFILE"
```

### Database Insert

```python
#!/usr/bin/env python3
import sys
import sqlite3
from datetime import datetime

# Data passed as first argument
data = sys.argv[1] if len(sys.argv) > 1 else ""
fields = data.split('|')

# Insert into database
conn = sqlite3.connect('/var/lib/phonehome/data.db')
cursor = conn.cursor()
cursor.execute('''
    INSERT INTO phone_home_events (timestamp, instance_id, hostname, fqdn)
    VALUES (?, ?, ?, ?)
''', (datetime.now(), fields[1], fields[2], fields[3]))
conn.commit()
conn.close()
```

### Webhook Notification

```bash
#!/bin/bash
DATA="$1"
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"New instance online: $DATA\"}" \
  "$WEBHOOK_URL"
```

## Development

### Prerequisites

- Rust 1.70+ 
- OpenSSL development libraries

```bash
# Fedora/RHEL/CentOS
sudo dnf install openssl-devel

# Ubuntu/Debian  
sudo apt install libssl-dev pkg-config
```

### Building

```bash
# Debug build
cargo build

# Release build  
cargo build --release

# Build with all features
cargo build --release --all-features
```

### Testing

```bash
# Run all tests
cargo test

# Run specific test suites
cargo test handlers::tests
cargo test config::tests  
cargo test models::tests

# Integration tests
cargo test --test integration_tests

# Load testing
cargo test load_tests
```

### Code Quality

#### Git Hooks

```bash
# Install pre-commit hooks
cp .githooks/pre-commit .git/hooks/
chmod +x .git/hooks/pre-commit
```

#### Manual Checks

```bash
# Code formatting
cargo fmt --check

# Linting
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit

# Documentation
cargo doc --no-deps --open
```

## RPM Packaging

```bash
# Install packaging tools
cargo install cargo-generate-rpm

# Generate RPM
cargo generate-rpm

# Install package
sudo dnf install target/generate-rpm/phonehome-*.rpm
```

## Troubleshooting

### Common Issues

**Permission Denied Errors**
```bash
# Fix certificate directory permissions
sudo mkdir -p /var/lib/phonehome
sudo chown phonehome:phonehome /var/lib/phonehome

# Fix log directory permissions  
sudo mkdir -p /var/log/phonehome
sudo chown phonehome:phonehome /var/log/phonehome
```

**Port Already in Use**
```bash
# Check what's using the port
sudo ss -tlnp | grep :443

# Use different port
phonehome --port 8443
```

**TLS Certificate Issues**
```bash
# Remove invalid certificates to regenerate self-signed ones
sudo rm /var/lib/phonehome/*.pem
sudo systemctl restart phonehome

# Note: Server requires TLS certificates to start
# Self-signed certificates will be automatically generated if missing
```

**External Application Not Executing**
```bash
# Check if external app is executable
ls -la /usr/local/bin/process-phone-home

# Test external app manually (data passed as argument)  
sudo -u phonehome /usr/local/bin/process-phone-home "test-data"

# Check logs
sudo tail -f /var/log/phonehome/phonehome.log
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Via command line
phonehome --debug

# Via environment variable
RUST_LOG=debug phonehome

# Via configuration file
log_level = "debug"
```

### Logging

View server logs for debugging:

```bash
# Real-time log monitoring
sudo tail -f /var/log/phonehome/phonehome.log

# Search for errors
sudo grep -i error /var/log/phonehome/phonehome.log

# Filter by correlation ID
sudo grep "correlation-id" /var/log/phonehome/phonehome.log
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes  
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Support

- **Documentation**: Check this README and inline code documentation
- **Issues**: Report bugs and feature requests via GitHub issues
- **Logs**: Check `/var/log/phonehome/phonehome.log` for debugging information

For additional help, enable debug logging and check the correlation IDs in the logs to track specific requests.