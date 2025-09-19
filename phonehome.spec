%global commit %{?commitish}%{!?commitish:HEAD}
%global shortcommit %(c=%{commit}; echo ${c:0:7})
%global commit_date %(date +%%Y%%m%%d)

Name:           phonehome
Version:        0.1.12
Release:        %{commit_date}%{shortcommit}%{?dist}
Summary:        Secure HTTPS server for Cloud Init phone home requests

License:        AGPL-3.0-or-later
URL:            https://github.com/epicgreen/phonehome
Source0:        https://github.com/epicgreen/phonehome/archive/%{commit}/%{name}-%{commit}.tar.gz

BuildRequires:  rust >= 1.70
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  systemd

Requires:       openssl
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Suggests:       bash-completion

# Disable debuginfo package generation
%global debug_package %{nil}

# Don't strip the binary to preserve Rust symbols
%global __os_install_post %{nil}

%description
PhoneHome Server is a secure HTTPS server written in Rust that handles Cloud Init
phone home requests with form data (application/x-www-form-urlencoded). The server
processes incoming phone home data, extracts configured fields, and executes
external applications with the processed data.

Features:
- HTTPS support with Let's Encrypt integration
- Cloud Init phone home form data handling (application/x-www-form-urlencoded)
- Standard cloud-init field support (instance_id, hostname, fqdn, SSH keys)
- Configurable data processing and field extraction
- External application execution with timeout handling
- Token-based security
- TOML configuration
- Comprehensive logging with correlation IDs
- Health check endpoint
- Rate limiting and input sanitization

%prep
%setup -q -c
mv %{name}-* %{name}-%{version}

%build
cd %{name}-%{version}
export CARGO_HOME=$PWD/.cargo
cargo build --release --verbose

%install
cd %{name}-%{version}

# Install main binary to /usr/bin
install -d %{buildroot}%{_bindir}
install -m 0755 target/release/%{name} %{buildroot}%{_bindir}/%{name}

# Install configuration file to /etc/phonehome
install -d %{buildroot}%{_sysconfdir}/%{name}
install -m 0640 etc/phonehome/config.toml %{buildroot}%{_sysconfdir}/phonehome/config.toml

# Install systemd service file to /usr/lib/systemd/system
install -d %{buildroot}%{_unitdir}/
install -m 0644 usr/lib/systemd/system/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

# Install bash completion to /usr/share/bash-completion/completions
install -d %{buildroot}%{_datadir}/bash-completion/completions
install -m 0644 etc/bash-completion/phonehome %{buildroot}%{_datadir}/bash-completion/completions/phonehome

# Install documentation
install -d %{buildroot}%{_docdir}/%{name}
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/

install -d %{buildroot}%{_licensedir}/%{name}
install -m 644 LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE

# Install configuration directory and example config
install -d %{buildroot}%{_sysconfdir}/%{name}
install -D -m 644 etc/%{name}/config.toml %{buildroot}%{_sysconfdir}/%{name}/config.toml

# Install bash completion
install -D -m 644 etc/bash-completion/%{name} %{buildroot}%{_datadir}/bash-completion/completions/%{name}

# Create necessary directories for runtime data
install -d %{buildroot}%{_localstatedir}/lib/%{name}
install -d %{buildroot}%{_localstatedir}/log/%{name}

%pre
getent group phonehome >/dev/null || groupadd -r phonehome
getent passwd phonehome >/dev/null || \
    useradd -r -g phonehome -d %{_localstatedir}/lib/phonehome \
    -s /sbin/nologin -c "PhoneHome Server" phonehome

%post
chown phonehome:phonehome %{_localstatedir}/lib/phonehome
chown phonehome:phonehome %{_localstatedir}/log/phonehome
chown root:phonehome %{_sysconfdir}/phonehome
chmod 750 %{_localstatedir}/lib/phonehome
chmod 750 %{_localstatedir}/log/phonehome
chmod 750 %{_sysconfdir}/phonehome

if grep -q "your-secret-token-here-change-me-123456" %{_sysconfdir}/phonehome/config.toml; then
    RANDOM_TOKEN=$(openssl rand -hex 32)
    sed -i "s/your-secret-token-here-change-me-123456/$RANDOM_TOKEN/" %{_sysconfdir}/phonehome/config.toml
fi
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) %{_sysconfdir}/%{name}/config.toml
%{_datadir}/bash-completion/completions/%{name}
%dir %attr(750,phonehome,phonehome) %{_localstatedir}/lib/%{name}
%dir %attr(750,phonehome,phonehome) %{_localstatedir}/log/%{name}
%dir %attr(750,root,phonehome) %{_sysconfdir}/%{name}

%changelog
* Thu Sep 11 2025 Ante de Baas <packages@debaas.net> - 0.1.7-1
- Initial package
- HTTPS server for Cloud Init phone home requests
- TOML configuration with token-based authentication
- External application execution with configurable field extraction
- Systemd service integration
- Comprehensive logging and monitoring
- Full support for standard cloud-init phone home requests
