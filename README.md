# PhoneHome Server

A secure HTTPS server written in Rust that handles Cloud Init phone home requests with Let's Encrypt certificate support. The server processes incoming phone home data, extracts configured fields, and executes external applications with the processed data.

## Features

- **HTTPS Support**: Built-in TLS/SSL support with Let's Encrypt integration
- **Development Mode**: Self-signed certificate support for cargo-based development only
- **Cloud Init Integration**: Handles standard Cloud Init phone home POST requests
- **Configurable Data Processing**: Extract and format specific fields from phone home data
- **External Application Execution**: Call external scripts/programs with processed data
- **Token-based Security**: URL token authentication for secure endpoints
- **TOML Configuration**: Easy-to-use configuration file format
- **Comprehensive Logging**: Detailed logging with configurable levels
- **Health Check Endpoint**: Built-in health monitoring

## Quick Start

### 1. Build the Project

```bash
git clone <repository-url>
cd phonehome_server
cargo build --release
```

### 2. Configure the Server

Copy the example configuration and modify it:

```bash
cp config.example.toml config.toml
# Edit config.toml with your settings
```

### 3. Install via RPM (Recommended)

For production deployment, use the RPM package:

```bash
# Install from COPR repository
sudo dnf copr enable antedebaas/phonehome_server
sudo dnf install phonehome_server

# Or build from source
make package
rpmbuild -ta dist/phonehome_server-*.tar.gz
sudo dnf install ~/rpmbuild/RPMS/x86_64/phonehome_server-*.rpm
```

### 4. Set Up TLS Certificates

For Let's Encrypt certificates:

```bash
# Install certbot if not already installed
sudo dnf install certbot  # Fedora/RHEL/CentOS
# or
sudo apt install certbot  # Ubuntu/Debian

# Obtain certificates
sudo certbot certonly --standalone -d your-domain.com

# Update config.toml with certificate paths:
# cert_path = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
# key_path = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
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
./target/release/phonehome_server

# Run with custom config and debug logging
./target/release/phonehome_server --config /path/to/config.toml --debug

# Run on specific port
./target/release/phonehome_server --port 9443

# Run in development mode with self-signed certificate (cargo only)
cargo run -- --dev-mode --debug
```

**Production (RPM installation):**
```bash
# Start the service
sudo systemctl start phonehome_server
sudo systemctl enable phonehome_server

# Check status
sudo systemctl status phonehome_server

# View logs
sudo journalctl -u phonehome_server -f
```

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
cert_path = "/path/to/cert.pem"     # Certificate file
key_path = "/path/to/key.pem"       # Private key file
use_letsencrypt = false             # Enable Let's Encrypt (experimental)
domain = "your-domain.com"          # Domain for Let's Encrypt
email = "admin@your-domain.com"     # Email for Let's Encrypt
```

### External Application Configuration

```toml
[external_app]
command = "/usr/local/bin/process-phone-home"  # Command to execute
args = ["--format", "pipe"]                    # Command arguments
timeout_seconds = 30                           # Execution timeout
working_directory = "/var/lib/phonehome"       # Working directory (optional)

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
    "public_ipv4",
    "cloud_name"
]
field_separator = "|"               # Separator between fields
include_timestamp = true            # Include timestamp as first field
include_instance_id = true          # Include instance_id as second field
```

### Development Mode (Cargo-Based Development Only)

⚠️ **WARNING: Development mode is only available when running under cargo!**

Development mode provides:
- Self-signed certificate generation for localhost HTTPS testing
- Automatic localhost binding for security
- Bypasses Let's Encrypt and manual certificate configuration
- Restricted to cargo-based execution only

**Using Development Mode:**

Development mode can only be enabled via CLI flag when running under cargo:
```bash
cargo run -- --dev-mode --debug
```

Development mode restrictions:
- Only available when running via `cargo run`, `cargo test`, etc.
- Cannot be enabled in production builds or installed binaries
- Automatically rejected if not running under cargo
- Server automatically binds to localhost (127.0.0.1) only
- Self-signed certificate is generated automatically
- HTTPS is enabled with the self-signed certificate
- Development warnings are shown in logs
- The phone home URL will be: `https://127.0.0.1:8443/phone-home/your-token`

## Cloud Init Integration

Add the following to your Cloud Init user-data to enable phone home:

```yaml
#cloud-config
phone_home:
  url: "https://your-domain.com:8443/phone-home/your-secret-token"
  post: all
  tries: 10
```

The server will receive the phone home data and process it according to your configuration.

## Available Data Fields

The following fields can be extracted from Cloud Init phone home data:

### Basic Fields
- `instance_id` - Cloud instance identifier
- `hostname` - System hostname
- `fqdn` - Fully qualified domain name
- `local_hostname` - Local hostname

### Cloud Provider Information
- `cloud_name` - Cloud provider (aws, gce, azure, etc.)
- `platform` - Platform information
- `region` - Cloud region
- `availability_zone` - Availability zone
- `instance_type` - Instance type/size

### Network Information
- `local_ipv4` - Local IPv4 address
- `public_ipv4` - Public IPv4 address
- `local_ipv6` - Local IPv6 address
- `public_ipv6` - Public IPv6 address
- `mac` - MAC address

### Security
- `public_keys` - SSH public keys (comma-separated)
- `security_groups` - Security groups (comma-separated)

### Custom Fields
Any additional fields present in the phone home JSON data can be extracted by name.

## API Endpoints

### Phone Home Endpoint
- **URL**: `POST /phone-home/{token}`
- **Content-Type**: `application/json`
- **Description**: Receives Cloud Init phone home data
- **Response**: JSON with processing status

### Health Check Endpoint
- **URL**: `GET /health`
- **Description**: Server health status
- **Response**: JSON with server status

## Command Line Options

```bash
phonehome_server [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Configuration file path [default: config.toml]
    -p, --port <PORT>      Override port from configuration
    -d, --debug            Enable debug logging
        --dev-mode         Enable development mode with self-signed certificate
                          (cargo-based execution only - NEVER use in production!)
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

TIMESTAMP="${FIELDS[0]}"
INSTANCE_ID="${FIELDS[1]}"
HOSTNAME="${FIELDS[2]}"
PUBLIC_IP="${FIELDS[3]}"

# Insert into database
mysql -u phonehome -p"$DB_PASSWORD" phonehome_db << EOF
INSERT INTO instances (timestamp, instance_id, hostname, public_ip) 
VALUES ('$TIMESTAMP', '$INSTANCE_ID', '$HOSTNAME', '$PUBLIC_IP');
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

# Run in development mode (self-signed cert, cargo only)
cargo run -- --dev-mode --debug

# Using Make
make build      # Debug build
make release    # Release build
make test       # Run tests
make run-dev    # Development server
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

### RPM Packaging

```bash
# Create source package
make package

# Build RPM
rpmbuild -ta dist/phonehome_server-*.tar.gz

# Install RPM
sudo dnf install ~/rpmbuild/RPMS/x86_64/phonehome_server-*.rpm
```

## Troubleshooting

### Common Issues

1. **Development Mode Issues**
   ```bash
   # Development mode only works when running under cargo
   # Error: "Development mode is only available when running under cargo"
   # Solution: Use 'cargo run -- --dev-mode' instead of direct binary execution
   
   # Self-signed certificate warnings in browser
   # Solution: Accept the certificate warning (development only)
   # Or add certificate to browser's trusted certificates for testing
   ```

2. **Certificate Permission Issues**
   ```bash
   # Fix certificate permissions for phonehome user
   sudo usermod -a -G letsencrypt phonehome
   sudo chmod 644 /etc/letsencrypt/live/domain/*.pem
   ```

3. **Service Won't Start**
   ```bash
   # Check service status
   sudo systemctl status phonehome_server
   
   # Check logs
   sudo journalctl -u phonehome_server -n 50
   
   # Check configuration
   sudo phonehome_server --config /etc/phonehome/config.toml --help
   
   # For development mode issues
   # Make sure you're using 'cargo run -- --dev-mode'
   ```

4. **Port Already in Use**
   ```bash
   # Check what's using the port
   sudo ss -tlnp | grep :8443
   
   # Change port in configuration
   sudo nano /etc/phonehome/config.toml
   
   # Or use --port flag for development testing
   cargo run -- --dev-mode --port 9443
   ```

5. **External Application Fails**
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
./phonehome_server --debug

# Via command line with development mode (cargo only)
cargo run -- --dev-mode --debug

# Via environment variable
RUST_LOG=debug ./phonehome_server

# Development mode with custom port (cargo only)
cargo run -- --dev-mode --debug --port 9443
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
2. Review service logs: `sudo journalctl -u phonehome_server`
3. Run the test suite: `cargo test`
4. Search existing issues on GitHub
5. Create a new issue with detailed information

## RPM Repository

The package is available in the COPR repository:
- Repository: `antedebaas/phonehome_server`
- Package name: `phonehome_server`
- Install: `sudo dnf copr enable antedebaas/phonehome_server && sudo dnf install phonehome_server`