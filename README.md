**Continuous Offensive Security Testing (COST) Tool**
![Cost Warden Logo](https://raw.githubusercontent.com/encrypter15/Cost-Warden/refs/heads/master/logo.png)

**Author**: Encrypter15 (encrypter15@gmail.com)  
**Version**: 1.3  
**License**: MIT  
**Codename**: SharpHammer

## Overview

COST-Warden is a containerized, modular tool built for the Continuous Offensive Security Testing (COST) framework. It’s designed for dynamic environments—DevOps pipelines, cloud-native apps, agile deployments—moving beyond snapshot pentesting to persistent, automated security testing. With 32 years of hacking experience, I’ve built this for newbies and seasoned red teamers alike.

COST-Warden runs scheduled and event-triggered scans, tracks changes (ports, vulns, services), correlates findings with CVEs, supports Kubernetes orchestration, and uses ML for anomaly detection. It integrates with CI/CD, SIEMs, and alerting systems, with a Flask dashboard for trends.

## Features

- **Scheduled Scans**: Cron-based port scanning (Nmap), web vuln scanning (OWASP ZAP), API testing.
- **Event-Triggered Scans**: Trigger on CI/CD events or system changes.
- **Change Detection**: Tracks new ports, services, or software versions.
- **CVE Correlation**: Maps scan results to NVD CVEs for actionable insights.
- **Kubernetes Orchestration**: Run scans as Kubernetes jobs for cloud-native scalability.
- **ML Anomaly Detection**: Flags unusual patterns (e.g., port spikes) using Isolation Forest.
- **Dashboard**: Flask + Chart.js UI for vuln trends, risk scores, and anomalies.
- **Integration**: SIEM (Splunk, ELK), Slack/Discord alerts, GitHub Actions hooks.
- **Containerized**: Docker and Kubernetes support.
- **Security**: RBAC, encrypted configs, audit logging.
- **CLI Interface**: Manage scans, reports, and configs via `warden.py`.
- **Error Handling**: Retries, fallbacks, detailed logging.
- **Reporting**: HTML, PDF, JSON reports with CVE details and remediation.

## Requirements

- Docker & Docker Compose
- Kubernetes (optional, for k8s orchestration)
- Python 3.9+
- Node.js (for dashboard dev)
- Bash (for setup scripts)
- kubectl (for Kubernetes)

## Installation

```bash
# Clone the repo
git clone <repo_url>
cd cost-warden

# Build and run with Docker
docker-compose up -d

# Or install locally
pip install -r requirements.txt
python src/warden.py --help

# For Kubernetes
kubectl apply -f k8s/scan-job.yaml
```

## Usage

```bash
# Run a full scan with CVE correlation
python src/warden.py scan --target 192.168.1.0/24 --type port --cve

# Schedule scans
python src/warden.py schedule --config configs/schedule.yaml

# Run scan on Kubernetes
python src/warden.py k8s --target example.com --type web

# Check for anomalies
python src/warden.py anomaly --scan-id 123

# View dashboard
# Open http://localhost:5000

# Generate report
python src/warden.py report --scan-id 123 --format pdf
```

## Directory Structure

```
cost-warden/
├── bin/                # Utility scripts
├── configs/            # Scan, schedule, SIEM configs
├── dashboard/          # Flask dashboard app
├── docs/               # Documentation
├── k8s/                # Kubernetes manifests
├── logs/               # Scan and app logs
├── models/             # ML model artifacts
├── reports/            # HTML, PDF, JSON reports
├── scans/              # Raw scan results, CVE data
├── src/                # Core Python logic
├── static/             # Dashboard CSS, JS
├── templates/          # HTML templates
└── docker-compose.yml  # Docker setup
```

## Configuration

- **scans.yaml**: Scan types (port, web, api), targets, tools.
- **schedule.yaml**: Cron schedules or event triggers.
- **siem.yaml**: SIEM API endpoints, credentials (encrypted).
- **warden.conf**: Log level, API keys, ML thresholds.
- **k8s/scan-job.yaml**: Kubernetes job template.

## Version History

- **1.3**: Added ML-based anomaly detection (Isolation Forest).
- **1.2**: Added Kubernetes orchestration for scans.
- **1.1**: Added CVE correlation with NVD API.
- **1.0**: Initial release with Docker, Flask, SIEM integration.

## Contributing

Fork, hack, PR. Bugs? Email encrypter15@gmail.com. Keep it MIT-compliant.

## License

MIT License. Use freely, give credit.

## TODO

- Add support for additional CVE databases (e.g., VulnDB).
- Enhance ML with deep learning for complex patterns.
- Integrate with cloud-native observability (e.g., Prometheus).

*Built by a hacker, for hackers.*
