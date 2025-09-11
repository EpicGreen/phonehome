# PhoneHome Server

A HTTPS server written in Rust that handles Cloud Init phone home requests with Let's Encrypt certificate support. The server processes incoming phone home form data (application/x-www-form-urlencoded), extracts configured fields, and executes external applications with the processed data.

## Features

- **HTTPS Support**: Built-in TLS/SSL support with Let's Encrypt integration
- **Development Mode**: Self-signed certificate support with automatic generation
- **Cloud Init Integration**: Handles standard Cloud Init phone home POST requests with form data
- **Configurable Data Processing**: Extract and format specific fields from phone home data
- **External Application Execution**: Call external scripts/programs with processed data
- **Token-based Security**: URL token authentication for secure endpoints
- **TOML Configuration**: Easy-to-use configuration file format
- **Comprehensive Logging**: Detailed logging with file output and logrotate support
- **Web Interface**: Landing page and custom error pages for better user experience
- **Health Check Endpoint**: Built-in health monitoring
- **Request Correlation**: Unique IDs for tracking requests through the system

## Quick Start

### 1. Build the Project

```bash
git clone <repository-url>
cd phonehome
cargo build --release
```

### 2. Configure the Server

Copy the example configuration and modify it:

```bash
cp etc/phonehome/config.toml config.toml
# Edit config.toml with your settings
```

### 3. Install via RPM (Recommended)

For production deployment, use the RPM package:

```bash
# Install from COPR repository
sudo dnf copr enable antedebaas/phonehome
sudo dnf install phonehome

# Or build from source
cargo build --release
sudo cp target/release/phonehome /usr/local/bin/
```

### 4. Configure Logging (Optional)

The server includes comprehensive logging with both console and file output:

```bash
# Logs are written to /var/log/phonehome/phonehome.log by default
sudo mkdir -p /var/log/phonehome
sudo chown phonehome:phonehome /var/log/phonehome

# Set up log rotation
sudo cp etc/logrotate.d/phonehome /etc/logrotate.d/
```

### 5. Set Up TLS Certificates

The server will automatically generate self-signed certificates if none are provided. For production use, provide your own certificates:

```bash
# Option 1: Use Let's Encrypt with certbot
sudo dnf install certbot  # Fedora/RHEL/CentOS
# or
sudo apt install certbot  # Ubuntu/Debian

sudo certbot certonly --standalone -d your-domain.com

# Update config.toml with certificate paths:
# cert_path = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
# key_path = "/etc/letsencrypt/live/your-domain.com/privkey.pem"

# Option 2: Use your own certificates
# Simply place your certificate and private key files and update config.toml

# Option 3: Let the server generate self-signed certificates (testing only)
# Leave cert_path and key_path pointing to non-existent files
```

### 5. Create an External Application

Create a script to process the phone home data (if not using RPM package):

```bash
sudo cat > /usr/local/bin/process-phone-home << 'EOF'
#!/bin/bash
# Simple example script to process phone home data
DATA="$1"
echo "$(date): Received phone home data: $DATA" >> /var/log/phonehome/phone-home.log

# Parse pipe-separated data
IFS='|' read -ra FIELDS <<< "$DATA"
echo "Instance ${FIELDS[1]} (${FIELDS[2]}) is online" >> /var/log/phonehome/phone-home.log
EOF

sudo chmod +x /usr/local/bin/process-phone-home
```

**Note:** The RPM package includes a default external application script.

### 6. Run the Server

**Development (from source):**
```bash
# Run with default config
./target/release/phonehome

# Run with custom config and debug logging
./target/release/phonehome --config /path/to/config.toml --debug

# Run on specific port
./target/release/phonehome --port 9443
```

**Production (RPM installation):**
```bash
# Start the service
sudo systemctl start phonehome
sudo systemctl enable phonehome

# Check status
sudo systemctl status phonehome

# View logs
sudo journalctl -u phonehome -f
```

## Web Interface

The PhoneHome server includes a web interface for better user experience:

- **Landing Page** (`GET /`): Server information and usage instructions
- **Health Check** (`GET /health`): Service status for monitoring
- **Phone Home** (`POST /phone-home/{token}`): Data submission endpoint
- **Error Pages**: Custom 404, 401, 400, and 500 error pages

Visit `https://your-server.com:8443/` in a browser to see the landing page.

## Configuration

The server uses a TOML configuration file with the following sections:

### Server Configuration

```toml
[server]
host = "0.0.0.0"                    # Bind address
port = 8443                         # HTTPS port
token = "your-secret-token"         # URL authentication token
```

### TLS Configuration

```toml
[tls]
cert_path = "/path/to/cert.pem"     # Certificate file (will be auto-generated if missing)
key_path = "/path/to/key.pem"       # Private key file (will be auto-generated if missing)
```

### Logging Configuration

```toml
[logging]
log_file = "/var/log/phonehome/phonehome.log"  # Path to log file
log_level = "info"                             # Log level: trace, debug, info, warn, error
enable_console = true                          # Enable console output
enable_file = true                             # Enable file output
max_file_size_mb = 100                         # Max file size before rotation
max_files = 10                                 # Number of rotated files to keep
```

**Default Certificate Paths**: Self-signed certificates are now stored in `/var/lib/phonehome/` instead of `/etc/phonehome/` for better security and permissions.

### External Application Configuration

```toml
[external_app]
command = "/usr/local/bin/process-phone-home"  # Command to execute
args = ["--format", "pipe"]                    # Command arguments
timeout_seconds = 30                           # Execution timeout
working_directory = "/var/lib/phonehome"       # Working directory (optional)

# Security settings
max_data_length = 4096                         # Maximum data length in bytes
allow_control_chars = false                    # Allow control characters (default: false)
sanitize_input = true                          # Sanitize input data (default: true)
quote_data = false                             # Encapsulate data in quotes (default: false)

[external_app.environment]                     # Environment variables (optional)
API_KEY = "your-api-key"
LOG_LEVEL = "info"
```

### Phone Home Data Processing

```toml
[phone_home]
fields_to_extract = [               # Fields to extract from phone home data
    "instance_id",
    "hostname",
    "fqdn",
    "pub_key_rsa",
    "pub_key_ecdsa",
    "pub_key_ed25519"
]
field_separator = "|"               # Separator between fields
include_timestamp = true            # Include timestamp as first field
include_instance_id = true          # Include instance_id as second field
```
**Testing and Development:**

For testing purposes, you can run the server without providing certificate files:
```bash
cargo run -- --debug
```

Certificate behavior:
- If certificate files exist, they will be validated and used
- If certificate files don't exist, self-signed certificates are automatically generated
- Self-signed certificates should only be used for testing or internal use
- Generated certificates use "localhost" as the domain name
- The phone home URL format: `https://your-host:port/phone-home/your-token`

## Cloud Init Integration
### 4. Configure Cloud Init

Add the phone home configuration to your cloud-init user data:

```yaml
#cloud-config
phone_home:
  url: "https://your-server.com:8443/phone-home/your-secret-token"
  post: all
  tries: 10
```

Cloud-init will send form data with the following fields:
- `instance_id` - Instance identifier
- `hostname` - System hostname
- `fqdn` - Fully qualified domain name
- `pub_key_rsa` - RSA public key (if available)
- `pub_key_ecdsa` - ECDSA public key (if available)
- `pub_key_ed25519` - Ed25519 public key (if available)

The server will receive the phone home data and process it according to your configuration.

## Available Data Fields

The following fields can be extracted from Cloud Init phone home data:

### Officially Supported Fields
These are the only fields officially supported by cloud-init's phone home module:

- `instance_id` - Cloud instance identifier
- `hostname` - System hostname
- `fqdn` - Fully qualified domain name
- `pub_key_rsa` - RSA public key
- `pub_key_ecdsa` - ECDSA public key
- `pub_key_ed25519` - Ed25519 public key

**Note**: Only the above fields are guaranteed to be sent by cloud-init. Any other fields will be ignored by cloud-init and should not be used in your configuration.

## API Endpoints

### Phone Home Endpoint
- **URL**: `POST /phone-home/{token}`
- **Content-Type**: `application/x-www-form-urlencoded`
- **Description**: Receives Cloud Init phone home form data
- **Response**: JSON with processing status

#### Cloud-Init Form Fields
Cloud-init sends the following standard form fields:

| Field | Description | Example |
|-------|-------------|---------|
| `instance_id` | Instance identifier | `i-1234567890abcdef0` |
| `hostname` | System hostname | `web-server-01` |
| `fqdn` | Fully qualified domain name | `web-server-01.example.com` |
| `pub_key_rsa` | RSA public key | `ssh-rsa AAAAB3NzaC1yc2...` |
| `pub_key_ecdsa` | ECDSA public key | `ecdsa-sha2-nistp256 AAAAE2...` |
| `pub_key_ed25519` | Ed25519 public key | `ssh-ed25519 AAAAC3NzaC1...` |

#### Example Request
```http
POST /phone-home/your-token HTTP/1.1
Host: your-server.com:8443
Content-Type: application/x-www-form-urlencoded
User-Agent: Cloud-Init/25.2

instance_id=i-87018aed&hostname=myhost&fqdn=myhost.internal&pub_key_rsa=ssh-rsa%20AAAAB3...&pub_key_ed25519=ssh-ed25519%20AAAAC3...
```

### Health Check Endpoint
- **URL**: `GET /health`
- **Description**: Server health status
- **Response**: JSON with server status

## Command Line Options

```bash
phonehome [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Configuration file path [default: config.toml]
    -p, --port <PORT>      Override port from configuration
    -d, --debug            Enable debug logging
    -h, --help             Print help information
    -V, --version          Print version information
```

## Security Considerations

1. **Use Strong Tokens**: Generate cryptographically secure random tokens
2. **HTTPS Only**: Always use HTTPS in production environments
3. **Firewall Rules**: Restrict access to the server using firewall rules
4. **Token Rotation**: Regularly rotate authentication tokens
5. **External App Security**: Ensure external applications are secure and validated
6. **Log Monitoring**: Monitor logs for suspicious activity
7. **Certificate Management**: Keep TLS certificates up to date
8. **Development Mode**: Only available when running under cargo (development environment)
9. **Cargo Restriction**: Development mode automatically rejected in production builds

## Example External Applications

### Simple Logging Script

```bash
#!/bin/bash
DATA="$1"
LOGFILE="/var/log/phonehome.log"
echo "$(date -Iseconds): $DATA" >> "$LOGFILE"
```

### Database Insert Script

```bash
#!/bin/bash
DATA="$1"
IFS='|' read -ra FIELDS <<< "$DATA"

# Fields from cloud-init form data: timestamp|instance_id|hostname|fqdn|pub_key_rsa|pub_key_ecdsa|pub_key_ed25519
TIMESTAMP="${FIELDS[0]}"
INSTANCE_ID="${FIELDS[1]}"
HOSTNAME="${FIELDS[2]}"
FQDN="${FIELDS[3]}"
PUB_KEY_RSA="${FIELDS[4]}"
PUB_KEY_ECDSA="${FIELDS[5]}"
PUB_KEY_ED25519="${FIELDS[6]}"

# Insert into database
mysql -u phonehome -p"$DB_PASSWORD" phonehome_db << EOF
INSERT INTO instances (timestamp, instance_id, hostname, fqdn, pub_key_rsa, pub_key_ecdsa, pub_key_ed25519)
VALUES ('$TIMESTAMP', '$INSTANCE_ID', '$HOSTNAME', '$FQDN', '$PUB_KEY_RSA', '$PUB_KEY_ECDSA', '$PUB_KEY_ED25519');
EOF
```

### Webhook Notification

```bash
#!/bin/bash
DATA="$1"
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

curl -X POST "$WEBHOOK_URL" \
  -H 'Content-type: application/json' \
  --data "{\"text\":\"New instance phone home: $DATA\"}"
```

## Development

### Prerequisites

- Rust 1.70 or later
- OpenSSL development libraries

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run

# Run for testing (auto-generates self-signed cert if needed)
cargo run -- --debug

# Using Cargo
cargo build             # Debug build
cargo build --release  # Release build
cargo test             # Run tests
cargo run -- --debug  # Development server
```

### Testing

```bash
# Run Rust test suite
cargo test

# Run with output
cargo test -- --nocapture

# Test specific module
cargo test config_tests
cargo test integration_tests

# Load testing
cargo test load_tests

# Manual HTTP testing
./test_phone_home.sh all
```

### Cloud-Init Testing

Test the server with real cloud-init requests:

# Manual testing with curl
curl -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: Cloud-Init/25.2" \
  -d "instance_id=i-1234567890abcdef0&hostname=test-instance&fqdn=test-instance.example.com&pub_key_rsa=ssh-rsa%20AAAAB3..." \
  "https://your-server.com:8443/phone-home/your-token"

# Expected response
{
  "status": "success",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "instance_id": "i-1234567890abcdef0",
  "processed_fields": 4,
  "external_app_executed": true
}
```

### RPM Packaging

```bash
# Create source package (for RPM builds)
# Source tarballs are automatically created by GitHub Actions for releases

# Build RPM manually (if needed)
# 1. Download source tarball from GitHub release
# 2. rpmbuild -ta phonehome-*.tar.gz
# 3. sudo dnf install ~/rpmbuild/RPMS/x86_64/phonehome-*.rpm
```

## Troubleshooting

### Common Issues

1. **Development Mode Issues**
   1. **TLS Certificate Issues**
      ```bash
      # Self-signed certificate warnings in browser
      # Solution: Accept the certificate warning (testing only)
      # Or add certificate to browser's trusted certificates for testing

      # Certificate file not found
      # Solution: Provide valid certificate files or let the server auto-generate them
      ```

   2. **Permission Issues**
2. **Certificate Permission Issues**
   ```bash
   # Fix certificate permissions for phonehome user
   sudo chown phonehome:phonehome /path/to/cert.pem /path/to/key.pem
   sudo chmod 644 /path/to/cert.pem
   sudo chmod 600 /path/to/key.pem
   ```

3. **Service Issues**
3. **Service Won't Start**
   ```bash
   # Check service status
   sudo systemctl status phonehome

   # Check logs
   sudo journalctl -u phonehome -n 50

   # Check configuration
   sudo phonehome --config /etc/phonehome/config.toml --help
   ```

4. **Port Conflicts**
4. **Port Already in Use**
   ```bash
   # Check what's using the port
   sudo ss -tlnp | grep :8443

   # Change port in configuration
   sudo nano /etc/phonehome/config.toml

   # Or use --port flag for testing
   cargo run -- --port 9443
   ```

5. **External Application Issues**
   ```bash
   # Check if external app is executable
   ls -la /usr/local/bin/process-phone-home

   # Test external app manually
   sudo -u phonehome /usr/local/bin/process-phone-home "test-data"

   # Check logs
   sudo tail -f /var/log/phonehome/phone-home.log
   ```

### Logging

Enable debug logging for troubleshooting:

```bash
# Via command line
./phonehome --debug

# Via environment variable
RUST_LOG=debug ./phonehome

# Testing with custom port
cargo run -- --debug --port 9443
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review service logs: `sudo journalctl -u phonehome`
3. Run the test suite: `cargo test`
4. Search existing issues on GitHub
5. Create a new issue with detailed information

## Logging System

The PhoneHome server uses a comprehensive structured logging system built on the `tracing` ecosystem, providing:

- **Dual output**: Console and file logging with independent configuration
- **Log rotation**: Built-in daily rotation with logrotate compatibility
- **Request correlation**: Unique IDs for tracking requests through the system
- **Structured data**: Optimized format for machine parsing and analysis
- **Performance metrics**: Execution times and resource usage tracking
- **Security logging**: Authentication events and security-relevant operations

### Logging Configuration

The logging system is configured in the `[logging]` section of config.toml:

```toml
[logging]
# Path to the log file
log_file = "/var/log/phonehome/phonehome.log"

# Log level: trace, debug, info, warn, error
log_level = "info"

# Enable console logging (stdout/stderr)
enable_console = true

# Enable file logging
enable_file = true

# Maximum log file size in MB before rotation (used by tracing-appender)
max_file_size_mb = 100

# Maximum number of rotated log files to keep
max_files = 10
```

#### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_file` | Path | `/var/log/phonehome/phonehome.log` | Full path to the log file |
| `log_level` | String | `"info"` | Minimum log level to record |
| `enable_console` | Boolean | `true` | Enable console output |
| `enable_file` | Boolean | `true` | Enable file output |
| `max_file_size_mb` | Number | 100 | Max file size before rotation |
| `max_files` | Number | 10 | Number of rotated files to keep |

#### Log Levels

- **trace**: Most verbose, includes all internal operations
- **debug**: Detailed information for debugging (enabled with `--debug` flag)
- **info**: General operational information
- **warn**: Warning conditions that should be monitored
- **error**: Error conditions that need attention

### Command Line Options

#### Debug Mode

Enable debug logging regardless of configuration:

```bash
phonehome --debug
```

This overrides the `log_level` configuration and enables maximum verbosity.

#### Configuration File

Specify a custom configuration file:

```bash
phonehome --config /path/to/custom/config.toml
```

### Log Formats

#### Console Output

Console logs use a human-readable format with colors and formatting:

```
2024-01-15T10:30:45.123456Z  INFO phonehome::main: Starting phonehome server
2024-01-15T10:30:45.124567Z DEBUG phonehome::config: Loading configuration from: "/etc/phonehome/config.toml"
```

#### File Output

File logs use a structured format optimized for parsing:

```
2024-01-15T10:30:45.123456Z  INFO phonehome::handlers: [550e8400-e29b-41d4-a716-446655440000] Received phone home request with token: abc123
```

### Request Correlation

Each HTTP request receives a unique correlation ID (UUID) that appears in all related log entries:

```
INFO [550e8400-e29b-41d4-a716-446655440000] Received phone home request with token: abc123
DEBUG [550e8400-e29b-41d4-a716-446655440000] Phone home payload: {...}
INFO [550e8400-e29b-41d4-a716-446655440000] External application executed successfully
```

This allows you to trace a complete request through the system using tools like `grep`:

```bash
grep "550e8400-e29b-41d4-a716-446655440000" /var/log/phonehome/phonehome.log
```

### Log Categories

#### Startup and Configuration

```
INFO Starting phonehome server
INFO Configuration loaded successfully from: "/etc/phonehome/config.toml"
INFO Server will bind to: 0.0.0.0:8443
INFO TLS setup completed successfully
INFO Application router configured with routes:
INFO   GET  /health - Health check endpoint
INFO   POST /phone-home/:token - Phone home data endpoint
```

#### Request Processing

```
INFO [correlation-id] Received phone home request with token: abc123
DEBUG [correlation-id] Phone home payload: {"instance_id": "i-1234567890abcdef0", ...}
INFO [correlation-id] Processing phone home data for instance: "i-1234567890abcdef0"
INFO [correlation-id] Extracted data: 4 fields, formatted as: '2024-01-15T10:30:45Z|i-1234567890abcdef0|web-server|10.0.1.100'
```

#### External Application Execution

```
INFO [correlation-id] Executing external application: /usr/bin/process-phone-home
DEBUG [correlation-id] Command args: ["--source", "cloud-init"]
DEBUG [correlation-id] Data to pass: '2024-01-15T10:30:45Z|i-1234567890abcdef0|web-server|10.0.1.100'
INFO [correlation-id] External application executed successfully in 245ms
```

#### Authentication and Security

```
WARN [correlation-id] Invalid token provided: wrong-token
ERROR [correlation-id] Authentication failed - rejecting request
```

#### TLS and Certificates

```
INFO TLS configuration found - setting up certificates
INFO Certificate files validated successfully
INFO Self-signed certificate generated successfully
```

#### Health Checks

```
DEBUG Health check endpoint accessed
INFO Health check successful
```

### Log Rotation

#### Built-in Rotation

The server uses `tracing-appender` for built-in daily log rotation:

- Logs rotate automatically at midnight (UTC)
- Old files are named with date suffix: `phonehome.log.2024-01-14`
- Rotation is transparent to the running application

#### Logrotate Integration

For more advanced rotation policies, use logrotate. Install the provided configuration:

```bash
sudo cp etc/logrotate.d/phonehome /etc/logrotate.d/
```

The logrotate configuration provides:
- Daily rotation
- 30-day retention
- Compression of old logs
- Proper permissions management
- Signal handling for log file reopening

#### Manual Rotation

To manually rotate logs without stopping the service:

```bash
sudo logrotate -f /etc/logrotate.d/phonehome
```

### Monitoring and Analysis

#### Finding Errors

```bash
# Recent errors
grep "ERROR" /var/log/phonehome/phonehome.log | tail -20

# Authentication failures
grep "Authentication failed" /var/log/phonehome/phonehome.log
```

#### Performance Analysis

```bash
# External application execution times
grep "executed successfully in" /var/log/phonehome/phonehome.log

# Slow requests (over 1 second)
grep -E "executed successfully in [1-9][0-9][0-9][0-9]ms" /var/log/phonehome/phonehome.log
```

#### Request Tracking

```bash
# Follow a specific request
CORRELATION_ID="550e8400-e29b-41d4-a716-446655440000"
grep "$CORRELATION_ID" /var/log/phonehome/phonehome.log
```

#### Statistics

```bash
# Request volume per hour
grep "Received phone home request" /var/log/phonehome/phonehome.log | \
  cut -d'T' -f2 | cut -d':' -f1 | sort | uniq -c

# Most common instance IDs
grep "Processing phone home data for instance" /var/log/phonehome/phonehome.log | \
  grep -o '"[^"]*"' | sort | uniq -c | sort -nr
```

### Log Aggregation

#### Systemd Journal

When running as a systemd service, logs also go to the journal:

```bash
# Follow live logs
journalctl -u phonehome -f

# View recent logs
journalctl -u phonehome --since "1 hour ago"

# Filter by log level
journalctl -u phonehome -p err
```

#### Centralized Logging

For production deployments, consider centralized logging solutions:

##### Rsyslog

Configure rsyslog to forward logs:

```
# /etc/rsyslog.d/phonehome.conf
if $programname == 'phonehome' then @@log-server:514
& stop
```

##### Fluentd/Fluent Bit

Monitor the log file and forward to Elasticsearch, S3, etc.:

```yaml
# fluent-bit.conf
[INPUT]
    Name tail
    Path /var/log/phonehome/phonehome.log
    Tag phonehome
    Parser json

[OUTPUT]
    Name elasticsearch
    Match phonehome
    Host elasticsearch.example.com
    Port 9200
    Index phonehome
```

### Troubleshooting

#### Log File Permissions

Ensure proper permissions for log directory:

```bash
sudo mkdir -p /var/log/phonehome
sudo chown phonehome:phonehome /var/log/phonehome
sudo chmod 755 /var/log/phonehome
```

#### Disk Space

Monitor disk usage for log directory:

```bash
# Check current usage
du -sh /var/log/phonehome/

# Set up monitoring alert
df /var/log/phonehome | awk 'NR==2 {if($5+0 > 80) print "WARNING: Log partition over 80% full"}'
```

#### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Temporary debug mode
phonehome --debug --config /etc/phonehome/config.toml

# Or modify config.toml
log_level = "debug"
```

#### Common Issues

1. **Permission Denied**: Check file/directory ownership and permissions
2. **Disk Full**: Verify log rotation is working and disk space is available
3. **No Logs**: Check `enable_file` and `enable_console` settings
4. **Slow Performance**: Review log level (trace/debug can be verbose)

### Security Considerations

#### Log Sanitization

The server automatically sanitizes sensitive data in logs:
- Tokens are partially masked in error messages
- Personal data is not logged unless explicitly configured

#### Access Control

Secure log file access:

```bash
# Restrictive permissions
sudo chmod 640 /var/log/phonehome/phonehome.log
sudo chown phonehome:adm /var/log/phonehome/phonehome.log
```

#### Retention Policy

Configure appropriate retention based on compliance requirements:
- PCI DSS: 1 year minimum
- GDPR: Based on data processing purposes
- SOX: 7 years for financial data

### Best Practices

1. **Monitor Error Rates**: Set up alerts for ERROR level log entries
2. **Regular Rotation**: Ensure logrotate is configured and running
3. **Correlation IDs**: Use correlation IDs to trace issues across logs
4. **Log Levels**: Use INFO for production, DEBUG for troubleshooting
5. **Centralized Logging**: Consider log aggregation for multi-server deployments
6. **Performance Impact**: Monitor log volume impact on I/O performance
7. **Security**: Protect log files from unauthorized access
8. **Backup**: Include log files in backup strategies for compliance

### Complete Logging Setup

1. Install the service:
```bash
sudo systemctl enable phonehome
sudo systemctl start phonehome
```

2. Configure logrotate:
```bash
sudo cp etc/logrotate.d/phonehome /etc/logrotate.d/
sudo logrotate -d /etc/logrotate.d/phonehome  # Test configuration
```

3. Set up monitoring:
```bash
# Add to crontab for daily error summary
0 9 * * * grep "ERROR" /var/log/phonehome/phonehome.log.$(date -d yesterday +%Y-%m-%d) | mail -s "PhoneHome Errors" admin@example.com
```

This comprehensive logging system provides full visibility into PhoneHome server operations while maintaining performance and security.

## RPM Repository

The package is available in the COPR repository:
- Repository: `antedebaas/phonehome`
- Package name: `phonehome`
- Install: `sudo dnf copr enable antedebaas/phonehome && sudo dnf install phonehome`
