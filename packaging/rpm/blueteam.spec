Name:           blueteam
Version:        2.0.0
Release:        1%{?dist}
Summary:        BlueTeam Linux Enterprise - Advanced Security Monitoring Platform
License:        MIT
URL:            https://github.com/masterfrequency/blueteam-linux-app
Requires:       python3 >= 3.8, python3-pip, systemd
Recommends:     auditd, fail2ban
Suggests:       postgresql, elasticsearch

%description
BlueTeam is an enterprise-grade security monitoring and threat detection platform
for Linux systems. It provides real-time system monitoring, ML-based threat
detection, and automated incident response capabilities.

Features:
 - Real-time network monitoring with anomaly detection
 - Process monitoring and behavioral analysis
 - File integrity monitoring
 - ML-based threat classification
 - Automated incident response
 - Compliance auditing
 - Comprehensive logging and reporting

23 integrated security modules across 6 security domains:
 - Network Defense
 - Endpoint Security
 - Vulnerability Management
 - Identity & Access Control
 - Incident Response
 - Advanced AI Threat Detection

%prep
# No prep needed - binary package

%install
# Create directories
mkdir -p %{buildroot}/usr/lib/blueteam
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/etc/blueteam
mkdir -p %{buildroot}/etc/systemd/system
mkdir -p %{buildroot}/var/lib/blueteam
mkdir -p %{buildroot}/var/log/blueteam

# Install files
cp -r backend ml %{buildroot}/usr/lib/blueteam/
cp bin/blueteam-daemon %{buildroot}/usr/bin/
cp bin/blueteam %{buildroot}/usr/local/bin/
cp etc/blueteam.conf %{buildroot}/etc/blueteam/
cp systemd/blueteam.service %{buildroot}/etc/systemd/system/
cp requirements.txt %{buildroot}/usr/lib/blueteam/

# Set permissions
chmod 755 %{buildroot}/usr/bin/blueteam-daemon
chmod 755 %{buildroot}/usr/local/bin/blueteam
chmod 644 %{buildroot}/etc/blueteam/blueteam.conf
chmod 644 %{buildroot}/etc/systemd/system/blueteam.service

%pre
# Create blueteam user if it doesn't exist
if ! id -u blueteam > /dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /var/lib/blueteam -m blueteam || true
fi

%post
# Install Python dependencies
pip3 install -q -r /usr/lib/blueteam/requirements.txt || true

# Enable and start service
systemctl daemon-reload
systemctl enable blueteam || true

# Create symbolic links
ln -sf /usr/lib/blueteam/bin/blueteam /usr/local/bin/blueteam || true

echo ""
echo "✅ BlueTeam installation complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Review configuration: sudo nano /etc/blueteam/blueteam.conf"
echo "  2. Start the service: sudo systemctl start blueteam"
echo "  3. Check status: blueteam status"
echo "  4. View logs: blueteam logs"
echo ""

%preun
# Stop service before uninstall
systemctl stop blueteam || true
systemctl disable blueteam || true

%postun
# Clean up
systemctl daemon-reload

%files
/usr/bin/blueteam-daemon
/usr/local/bin/blueteam
/etc/blueteam/blueteam.conf
/etc/systemd/system/blueteam.service
/usr/lib/blueteam/
/var/lib/blueteam/
/var/log/blueteam/

%changelog
* Mon Dec 18 2024 BlueTeam Security <security@blueteam.dev> - 2.0.0-1
- Initial release of BlueTeam Enterprise
- 23 integrated security modules
- Real-time threat detection with ML
- Systemd integration
- Comprehensive CLI interface
