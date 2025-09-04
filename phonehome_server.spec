Name:           phonehome_server
Version:        0.1.0
Release:        1%{?dist}
Summary:        Secure HTTPS server for Cloud Init phone home requests

License:        MIT
URL:            https://github.com/epicgreen/phonehome_server
# Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.70.0
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  pkg-config
BuildRequires:  systemd-rpm-macros

Requires:       openssl
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Suggests:       bash-completion

%description
PhoneHome Server is a secure HTTPS server written in Rust that handles Cloud Init
phone home requests with Let's Encrypt certificate support. The server processes
incoming phone home data, extracts configured fields, and executes external
applications with the processed data.

Features:
- HTTPS support with Let's Encrypt integration
- Cloud Init phone home request handling
- Configurable data processing and field extraction
- External application execution with timeout handling
- Token-based security
- TOML configuration
- Comprehensive logging
- Health check endpoint

%prep
# RPM builds with Source0 tarball, use: %autosetup

%build
# Build the release version
cargo build --release

%install
# Create system directories
install -d %{buildroot}%{_bindir}                                    # /usr/bin
install -d %{buildroot}%{_sysconfdir}/phonehome                     # /etc/phonehome
install -d %{buildroot}%{_localstatedir}/lib/phonehome              # /var/lib/phonehome
install -d %{buildroot}%{_localstatedir}/log/phonehome              # /var/log/phonehome
install -d %{buildroot}%{_unitdir}                                  # /usr/lib/systemd/system
install -d %{buildroot}%{_datadir}/bash-completion/completions      # /usr/share/bash-completion/completions

# Install main binary to /usr/bin
install -m 0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

# Install configuration file to /etc/phonehome
install -m 0640 etc/phonehome_server/config.toml %{buildroot}%{_sysconfdir}/phonehome/config.toml

# Install systemd service file to /usr/lib/systemd/system
install -m 0644 usr/lib/systemd/system/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

# Install bash completion to /usr/share/bash-completion/completions
install -m 0644 etc/bash-completion/phonehome_server %{buildroot}%{_datadir}/bash-completion/completions/phonehome_server

# Install example external application
cat > %{buildroot}%{_bindir}/process-phone-home << 'EOF'
#!/bin/bash
# Default phone home processor
DATA="$1"
LOGFILE="/var/log/phonehome/phone-home.log"

# Ensure log file exists and has correct permissions
touch "$LOGFILE"
chown phonehome:phonehome "$LOGFILE" 2>/dev/null || true

# Log the received data
echo "$(date -Iseconds): Received phone home data: $DATA" >> "$LOGFILE"

# Parse pipe-separated data
IFS='|' read -ra FIELDS <<< "$DATA"

if [[ ${#FIELDS[@]} -ge 3 ]]; then
    TIMESTAMP="${FIELDS[0]}"
    INSTANCE_ID="${FIELDS[1]}"
    HOSTNAME="${FIELDS[2]}"

    echo "$(date -Iseconds): Instance $INSTANCE_ID ($HOSTNAME) checked in" >> "$LOGFILE"
else
    echo "$(date -Iseconds): Received malformed data: $DATA" >> "$LOGFILE"
fi

exit 0
EOF

chmod 0755 %{buildroot}%{_bindir}/process-phone-home

%pre
# Create phonehome user and group
getent group phonehome >/dev/null || groupadd -r phonehome
getent passwd phonehome >/dev/null || \
    useradd -r -g phonehome -d %{_localstatedir}/lib/phonehome \
    -s /sbin/nologin -c "PhoneHome Server" phonehome

%post
# Set up directories with correct permissions
chown phonehome:phonehome %{_localstatedir}/lib/phonehome
chown phonehome:phonehome %{_localstatedir}/log/phonehome
chown root:phonehome %{_sysconfdir}/phonehome
chmod 750 %{_localstatedir}/lib/phonehome
chmod 750 %{_localstatedir}/log/phonehome
chmod 750 %{_sysconfdir}/phonehome

# Generate a secure random token if using default
if grep -q "your-secret-token-here-change-me-123456" %{_sysconfdir}/phonehome/config.toml; then
    RANDOM_TOKEN=$(openssl rand -hex 32)
    sed -i "s/your-secret-token-here-change-me-123456/$RANDOM_TOKEN/" %{_sysconfdir}/phonehome/config.toml
    echo "Generated random token for phone home server"
    echo "Token: $RANDOM_TOKEN"
    echo "Please save this token and update your Cloud Init configuration"
fi

%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%license LICENSE
%doc README.md
%{_bindir}/%{name}
%{_bindir}/process-phone-home
%{_unitdir}/%{name}.service
%{_datadir}/bash-completion/completions/phonehome_server
%dir %attr(750, root, phonehome) %{_sysconfdir}/phonehome
%config(noreplace) %attr(640, root, phonehome) %{_sysconfdir}/phonehome/config.toml
%dir %attr(750, phonehome, phonehome) %{_localstatedir}/lib/phonehome
%dir %attr(750, phonehome, phonehome) %{_localstatedir}/log/phonehome

%changelog
* Wed Sep 3 2025 Ante de Baas <packages@debaas.net> - 0.1.0-1
- Initial package
- Secure HTTPS server for Cloud Init phone home requests
- TOML configuration with token-based authentication
- External application execution with configurable field extraction
- Let's Encrypt certificate support
- Systemd service integration
- Comprehensive logging and monitoring
- Basic functionality implementation
- Core features and configuration system
