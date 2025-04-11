# COST-Warden Usage Guide

## Running a Scan with CVE Correlation

```bash
python src/warden.py scan --target 192.168.1.0/24 --type port --cve
```

## Running a Scan on Kubernetes

```bash
python src/warden.py k8s --target example.com --type web
# Or manually
./bin/k8s-deploy.sh
```

## Scheduling Scans

Edit `configs/schedule.yaml`, then:

```bash
python src/warden.py schedule
```

## Checking for Anomalies

```bash
python src/warden.py anomaly --scan-id 123
```

## Viewing Dashboard

```bash
python src/warden.py run
```

Open `http://localhost:5000`.

## Generating Reports

```bash
python src/warden.py report --scan-id 123 --format pdf
```
