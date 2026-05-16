# BlueTeam Linux Enterprise 2026 Edition

**The Ultimate Production-Grade Defensive Security Platform for Linux**

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.11+-blue.svg)
![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen.svg)

---

## 🎯 Overview

**BlueTeam Linux Enterprise** is a comprehensive, production-grade security platform designed for enterprise Linux environments. It provides real-time threat detection, compliance automation, incident response, and advanced analytics across 23 integrated security modules.

### Key Highlights

- **23 Integrated Security Modules** - Complete coverage across all security domains
- **ML-Powered Threat Detection** - 5 advanced machine learning models
- **Real-Time Monitoring** - 30+ Prometheus metrics for observability
- **Cloud-Native** - Kubernetes, Docker, and multi-cloud support
- **Compliance Automation** - CIS, PCI-DSS, HIPAA, SOC 2 compliance
- **Enterprise Integration** - Slack, Teams, PagerDuty, SIEM, AWS, Azure, GCP
- **Production-Ready** - Enterprise-grade security, reliability, and performance

---

## 📦 Installation

### Option 1: Debian/Ubuntu (.deb Package)

```bash
# Download the package
wget https://github.com/masterfrequency/blueteam-linux-app/releases/download/v2.0.0/blueteam_2.0.0-1_amd64.deb

# Install
sudo dpkg -i blueteam_2.0.0-1_amd64.deb

# Start service
sudo systemctl start blueteam
sudo systemctl enable blueteam

# Verify installation
sudo systemctl status blueteam
```

### Option 2: Source Installation

```bash
# Clone repository
git clone https://github.com/masterfrequency/blueteam-linux-app.git
cd blueteam-linux-app

# Install dependencies
sudo pip3 install -r requirements.txt

# Run daemon
sudo python3 bin/blueteam-daemon

# Or run CLI
python3 bin/blueteam status
```

### Option 3: Docker

```bash
# Build image
docker build -t blueteam:2.0.0 .

# Run container
docker run -d \
  --name blueteam \
  -v /var/log/blueteam:/var/log/blueteam \
  -v /etc/blueteam:/etc/blueteam \
  -p 8000:8000 \
  -p 9090:9090 \
  blueteam:2.0.0

# Check status
docker logs blueteam
```

### Option 4: Kubernetes

```bash
# Install Helm chart
helm install blueteam ./k8s/helm/blueteam

# Or apply manifests
kubectl apply -f k8s/deployment.yaml

# Verify deployment
kubectl get pods -n blueteam
kubectl logs -n blueteam -l app=blueteam
```

---

## 🚀 Quick Start

### Start the Service

```bash
# Start BlueTeam daemon
sudo systemctl start blueteam

# Enable auto-start on boot
sudo systemctl enable blueteam

# Check status
sudo systemctl status blueteam

# View logs
sudo journalctl -u blueteam -f
```

### CLI Commands

```bash
# Show system status
blueteam status

# List active threats
blueteam threats

# Show module status
blueteam modules

# Run compliance check
blueteam compliance --framework cis

# Generate report
blueteam report --type compliance --output report.pdf

# Configure settings
blueteam config edit

# Start monitoring
blueteam monitor
```

### REST API

```bash
# Get system status
curl http://localhost:8000/api/status

# List threats
curl http://localhost:8000/api/threats

# Get module metrics
curl http://localhost:8000/api/modules

# Compliance report
curl http://localhost:8000/api/compliance/cis

# Prometheus metrics
curl http://localhost:9090/metrics
```

---

## 📊 Features

### 23 Security Modules

#### Network Defense (5 modules)
- **AI Traffic Analyzer** - Real-time packet analysis with ML
- **Zero-Trust Firewall** - Dynamic rule engine with threat correlation
- **Intrusion Detection System** - Signature and behavioral detection
- **VPN & Secure Tunneling** - Encrypted connection management
- **DNS Security Filter** - Domain blocking and query logging

#### Endpoint Security (5 modules)
- **Malware Scanner (Heuristic)** - EICAR and pattern detection
- **Process Sentinel** - Process monitoring and API call detection
- **Kernel Hardening** - Security module configuration
- **Registry/Config Guard** - Configuration file monitoring
- **USB/Hardware Blocker** - Hardware access control

#### Vulnerability Management (4 modules)
- **Auto-Patch Manager** - Patch tracking and prioritization
- **Compliance Auditor** - CIS/NIST/PCI-DSS compliance
- **Vulnerability Scanner** - Network and system assessment
- **Secret Scanner** - Credential leak detection

#### Identity & Access (3 modules)
- **Biometric/MFA Gateway** - Multi-factor authentication
- **Privilege Escalation Monitor** - Unauthorized sudo detection
- **Session Hijacking Guard** - Session anomaly detection

#### Incident Response (3 modules)
- **Log Aggregator (SIEM)** - Real-time log collection
- **Snapshot & Recovery** - Automated backup management
- **Live Forensics Toolkit** - Memory and disk imaging

#### Advanced AI (3 modules)
- **Threat Intelligence Feed** - Global threat database
- **Automated Playbook Engine** - Response automation
- **AI Security Assistant** - Natural language interface

### Advanced Capabilities

#### Machine Learning
- Isolation Forest anomaly detection
- Random Forest threat prediction
- DBSCAN clustering for threat groups
- Behavioral analysis with deviation detection
- Predictive analytics with trend forecasting

#### Monitoring & Observability
- 30+ Prometheus metrics
- Grafana dashboard integration
- Real-time threat visualization
- System resource monitoring
- API request tracking
- Integration alert monitoring

#### Cloud Integration
- AWS Security Hub
- Azure Sentinel
- GCP Security Command Center
- Multi-cloud threat correlation

#### Compliance Automation
- CIS Benchmark (10 controls)
- PCI-DSS (12 requirements)
- HIPAA (10 rules)
- SOC 2 (6 principles)
- Automated scoring and reporting

#### Integration Ecosystem
- Slack notifications
- Microsoft Teams alerts
- PagerDuty incidents
- SIEM integration
- Email alerts
- Custom webhooks

---

## ⚙️ Configuration

### Main Configuration File

```bash
sudo nano /etc/blueteam/blueteam.conf
```

### Example Configuration

```ini
[general]
log_level = INFO
database_url = postgresql://user:pass@localhost/blueteam
redis_url = redis://localhost:6379

[modules]
enabled_modules = all
threat_threshold = 7.5
response_timeout = 30

[monitoring]
prometheus_enabled = true
prometheus_port = 9090
metrics_interval = 30

[integrations]
slack_webhook = https://hooks.slack.com/...
teams_webhook = https://outlook.webhook.office.com/...
pagerduty_key = xxxxxxxxxxxx

[cloud]
aws_region = us-east-1
azure_workspace_id = xxxxxxxx
gcp_project_id = blueteam-project

[compliance]
frameworks = cis,pci-dss,hipaa,soc2
auto_audit = true
audit_interval = 86400
```

### Enable Integrations

```bash
# Slack
blueteam config set integrations.slack_webhook https://hooks.slack.com/...

# Teams
blueteam config set integrations.teams_webhook https://outlook.webhook.office.com/...

# PagerDuty
blueteam config set integrations.pagerduty_key xxxxxxxxxxxx

# AWS
blueteam config set cloud.aws_region us-east-1

# Azure
blueteam config set cloud.azure_workspace_id xxxxxxxx

# GCP
blueteam config set cloud.gcp_project_id blueteam-project
```

---

## 📈 Monitoring

### Prometheus Metrics

Access Prometheus metrics at: `http://localhost:9090/metrics`

Key metrics:
- `blueteam_threats_total` - Total threats detected
- `blueteam_threats_active` - Currently active threats
- `blueteam_threat_response_seconds` - Response time
- `blueteam_module_runs_total` - Module executions
- `blueteam_system_cpu_percent` - CPU usage
- `blueteam_system_memory_percent` - Memory usage
- `blueteam_api_requests_total` - API requests
- `blueteam_ml_predictions_total` - ML predictions

### Grafana Dashboard

```bash
# Add Prometheus data source
# URL: http://localhost:9090

# Import BlueTeam dashboard
# ID: 12345 (available in k8s/grafana/dashboard.json)
```

### View Logs

```bash
# System logs
sudo journalctl -u blueteam -f

# Application logs
sudo tail -f /var/log/blueteam/blueteam.log

# Threat logs
sudo tail -f /var/log/blueteam/threats.log

# API logs
sudo tail -f /var/log/blueteam/api.log
```

---

## 🔒 Security

### Systemd Hardening

BlueTeam runs with systemd security hardening:
- `PrivateTmp=yes` - Private /tmp
- `NoNewPrivileges=yes` - No privilege escalation
- `ProtectSystem=strict` - Read-only system
- `ProtectHome=yes` - Protected home directory
- `ProtectKernelTunables=yes` - Kernel protection
- `ProtectControlGroups=yes` - Cgroup protection

### Database Security

- PostgreSQL with SSL/TLS
- Encrypted credentials
- Role-based access control
- Audit logging

### API Security

- JWT authentication
- Rate limiting
- CORS protection
- Input validation
- SQL injection prevention

---

## 📊 Compliance Reports

### Generate Reports

```bash
# CIS Benchmark report
blueteam report --framework cis --output cis_report.pdf

# PCI-DSS report
blueteam report --framework pci-dss --output pci_report.pdf

# HIPAA report
blueteam report --framework hipaa --output hipaa_report.pdf

# SOC 2 report
blueteam report --framework soc2 --output soc2_report.pdf

# Executive summary
blueteam report --type summary --output summary.pdf
```

### API Reports

```bash
# Get compliance score
curl http://localhost:8000/api/compliance/score

# Get detailed findings
curl http://localhost:8000/api/compliance/cis/findings

# Export report
curl http://localhost:8000/api/compliance/cis/export?format=pdf > report.pdf
```

---

## 🐳 Kubernetes Deployment

### Prerequisites

- Kubernetes 1.20+
- Helm 3.0+
- PostgreSQL 12+
- Redis 6.0+

### Deploy

```bash
# Create namespace
kubectl create namespace blueteam

# Install PostgreSQL
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install postgres bitnami/postgresql -n blueteam

# Install Redis
helm install redis bitnami/redis -n blueteam

# Install BlueTeam
helm install blueteam ./k8s/helm/blueteam -n blueteam

# Verify deployment
kubectl get pods -n blueteam
kubectl get svc -n blueteam
```

### Access Services

```bash
# Port forward API
kubectl port-forward -n blueteam svc/blueteam-daemon 8000:8000

# Port forward Prometheus
kubectl port-forward -n blueteam svc/blueteam-daemon 9090:9090

# Access logs
kubectl logs -n blueteam -l app=blueteam -f
```

---

## 🔧 Troubleshooting

### Service Won't Start

```bash
# Check status
sudo systemctl status blueteam

# View logs
sudo journalctl -u blueteam -n 50

# Check database connection
blueteam db test

# Verify configuration
blueteam config validate
```

### High CPU Usage

```bash
# Check running modules
blueteam modules

# Disable heavy modules
blueteam modules disable ai-traffic-analyzer

# Check ML model status
blueteam ml status

# Reduce monitoring interval
blueteam config set monitoring.interval 60
```

### Database Connection Issues

```bash
# Test connection
blueteam db test

# Check credentials
cat /etc/blueteam/blueteam.conf | grep database_url

# Verify PostgreSQL is running
sudo systemctl status postgresql

# Reset database
blueteam db reset
```

### API Not Responding

```bash
# Check API status
curl http://localhost:8000/health

# Restart API service
sudo systemctl restart blueteam

# Check port binding
sudo netstat -tlnp | grep 8000

# View API logs
sudo tail -f /var/log/blueteam/api.log
```

---

## 📚 Documentation

- [Installation Guide](./docs/INSTALLATION.md)
- [Configuration Guide](./docs/CONFIGURATION.md)
- [API Documentation](./docs/API.md)
- [CLI Reference](./docs/CLI.md)
- [Kubernetes Guide](./docs/KUBERNETES.md)
- [Compliance Guide](./docs/COMPLIANCE.md)
- [Troubleshooting](./docs/TROUBLESHOOTING.md)

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) for details.

---

## 📝 License

BlueTeam Linux Enterprise is licensed under the MIT License. See [LICENSE](./LICENSE) for details.

---

## 🔗 Links

- **GitHub:** https://github.com/masterfrequency/blueteam-linux-app
- **Issues:** https://github.com/masterfrequency/blueteam-linux-app/issues
- **Releases:** https://github.com/masterfrequency/blueteam-linux-app/releases
- **Documentation:** https://blueteam.io/docs

---

## 📞 Support

- **Email:** support@blueteam.io
- **Slack:** [Join Community](https://blueteam-community.slack.com)
- **Issues:** [GitHub Issues](https://github.com/masterfrequency/blueteam-linux-app/issues)

---

## 🎉 Changelog

### Version 2.0.0 (Current)
- ✅ 23 security modules
- ✅ ML threat detection
- ✅ Prometheus monitoring
- ✅ Kubernetes support
- ✅ Cloud integrations (AWS, Azure, GCP)
- ✅ Compliance automation
- ✅ Integration ecosystem
- ✅ Advanced forensics
- ✅ SIEM integration

### Version 1.0.0
- Initial release with core modules

---

**BlueTeam Linux Enterprise 2026 Edition - Production-Grade Security Platform**

*Last Updated: May 16, 2026*
