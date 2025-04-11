#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import yaml
import docker
import redis
import schedule
import time
import json
import requests
from flask import Flask, render_template
from cryptography.fernet import Fernet
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph
from kubernetes import client, config
from src.cve_correlator import correlate_cve
from src.ml_anomaly import detect_anomalies

# Setup logging
logging.basicConfig(
    filename='logs/warden.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='../templates', static_folder='../static')

# Redis for caching
redis_client = redis.Redis(host='redis', port=6379, db=0)

# Docker client
docker_client = docker.from_env()

# Encryption for configs
key = Fernet.generate_key()
cipher = Fernet(key)

def load_config(file_path):
    """Load and decrypt YAML config."""
    try:
        with open(file_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logger.error(f"Failed to load config {file_path}: {e}")
        sys.exit(1)

def run_scan(target, scan_type, cve=False):
    """Execute a scan using Dockerized tools."""
    scan_id = f"{target}_{scan_type}_{int(time.time())}"
    try:
        logger.info(f"Starting {scan_type} scan on {target} (ID: {scan_id})")
        if scan_type == 'port':
            container = docker_client.containers.run(
                'nmap:latest',
                f'nmap -sV -oX /scans/{scan_id}.xml {target}',
                volumes={os.path.abspath('scans'): {'bind': '/scans', 'mode': 'rw'}},
                detach=True
            )
        elif scan_type == 'web':
            container = docker_client.containers.run(
                'owasp/zap2docker-stable',
                f'zap-baseline.py -t http://{target} -r /scans/{scan_id}.html',
                volumes={os.path.abspath('scans'): {'bind': '/scans', 'mode': 'rw'}},
                detach=True
            )
        container.wait()
        logger.info(f"Completed {scan_type} scan on {target}")

        # Correlate with CVEs if requested
        if cve:
            cve_data = correlate_cve(f"scans/{scan_id}.xml", scan_type)
            with open(f"scans/{scan_id}_cve.json", 'w') as f:
                json.dump(cve_data, f)
            logger.info(f"CVE correlation completed for {scan_id}")

        return scan_id
    except Exception as e:
        logger.error(f"Scan failed for {target}: {e}")
        return None

def run_k8s_scan(target, scan_type):
    """Run a scan as a Kubernetes job."""
    try:
        config.load_kube_config()
        v1 = client.BatchV1Api()
        job_manifest = load_config('k8s/scan-job.yaml')
        job_manifest['metadata']['name'] = f"warden-scan-{int(time.time())}"
        job_manifest['spec']['template']['spec']['containers'][0]['args'] = [
            f"scan --target {target} --type {scan_type}"
        ]
        v1.create_namespaced_job(namespace='default', body=job_manifest)
        logger.info(f"Launched Kubernetes scan job for {target} ({scan_type})")
    except Exception as e:
        logger.error(f"Kubernetes scan failed: {e}")

def detect_changes(target, scan_type, scan_id):
    """Compare scan results for changes."""
    try:
        current_scan = f"scans/{scan_id}.xml"
        previous_scan = redis_client.get(f"{target}:{scan_type}:prev")
        if previous_scan:
            # Placeholder for diff logic
            logger.info(f"Detected changes for {target} {scan_type}")
        redis_client.set(f"{target}:{scan_type}:prev", current_scan.encode())
    except Exception as e:
        logger.error(f"Change detection failed: {e}")

def detect_anomaly_wrapper(scan_id):
    """Run ML-based anomaly detection."""
    try:
        anomalies = detect_anomalies(f"scans/{scan_id}.xml")
        with open(f"scans/{scan_id}_anomalies.json", 'w') as f:
            json.dump(anomalies, f)
        logger.info(f"Anomaly detection completed for {scan_id}")
        return anomalies
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        return []

def generate_report(scan_id, format_type):
    """Generate report in specified format."""
    try:
        output = f"reports/{scan_id}.{format_type}"
        if format_type == 'pdf':
            doc = SimpleDocTemplate(output, pagesize=letter)
            story = [Paragraph(f"COST-Warden Report: Scan {scan_id}")]
            # Add CVE and anomaly data
            if os.path.exists(f"scans/{scan_id}_cve.json"):
                with open(f"scans/{scan_id}_cve.json") as f:
                    cve_data = json.load(f)
                story.append(Paragraph(f"CVEs: {len(cve_data)} found"))
            if os.path.exists(f"scans/{scan_id}_anomalies.json"):
                with open(f"scans/{scan_id}_anomalies.json") as f:
                    anomalies = json.load(f)
                story.append(Paragraph(f"Anomalies: {len(anomalies)} detected"))
            doc.build(story)
        logger.info(f"Generated report: {output}")
    except Exception as e:
        logger.error(f"Report generation failed: {e}")

def notify_siem(data):
    """Push scan results to SIEM."""
    config = load_config('configs/siem.yaml')
    try:
        encrypted_token = config['api_token']
        token = cipher.decrypt(encrypted_token).decode()
        requests.post(
            config['endpoint'],
            json=data,
            headers={'Authorization': f'Bearer {token}'}
        )
        logger.info("Sent data to SIEM")
    except Exception as e:
        logger.error(f"SIEM notification failed: {e}")

@app.route('/')
def dashboard():
    """Render the dashboard."""
    try:
        stats = {
            'scans_completed': int(redis_client.get('stats:scans') or 0),
            'vulns_found': int(redis_client.get('stats:vulns') or 0),
            'anomalies_detected': int(redis_client.get('stats:anomalies') or 0)
        }
        return render_template('dashboard.html', stats=stats)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return "Error rendering dashboard", 500

def run_scheduler():
    """Run scheduled scans."""
    config = load_config('configs/schedule.yaml')
    for job in config['jobs']:
        schedule.every(job['interval']).seconds.do(
            run_scan, target=job['target'], scan_type=job['type'], cve=True
        )
    while True:
        schedule.run_pending()
        time.sleep(1)

def cli():
    """CLI interface."""
    parser = argparse.ArgumentParser(description="COST-Warden CLI")
    subparsers = parser.add_subparsers(dest='command')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run a scan')
    scan_parser.add_argument('--target', required=True)
    scan_parser.add_argument('--type', choices=['port', 'web', 'api'], required=True)
    scan_parser.add_argument('--cve', action='store_true', help='Correlate with CVEs')

    # Schedule command
    schedule_parser = subparsers.add_parser('schedule', help='Run scheduled scans')
    schedule_parser.add_argument('--config', default='configs/schedule.yaml')

    # Kubernetes command
    k8s_parser = subparsers.add_parser('k8s', help='Run scan on Kubernetes')
    k8s_parser.add_argument('--target', required=True)
    k8s_parser.add_argument('--type', choices=['port', 'web', 'api'], required=True)

    # Anomaly command
    anomaly_parser = subparsers.add_parser('anomaly', help='Run anomaly detection')
    anomaly_parser.add_argument('--scan-id', required=True)

    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('--scan-id', required=True)
    report_parser.add_argument('--format', choices=['pdf', 'html', 'json'], default='pdf')

    # Run command
    subparsers.add_parser('run', help='Start the warden service')

    args = parser.parse_args()

    if args.command == 'scan':
        scan_id = run_scan(args.target, args.type, args.cve)
        if scan_id:
            detect_changes(args.target, args.type, scan_id)
            detect_anomaly_wrapper(scan_id)
    elif args.command == 'k8s':
        run_k8s_scan(args.target, args.type)
    elif args.command == 'schedule':
        run_scheduler()
    elif args.command == 'anomaly':
        detect_anomaly_wrapper(args.scan_id)
    elif args.command == 'report':
        generate_report(args.scan_id, args.format)
    elif args.command == 'run':
        app.run(host='0.0.0.0', port=5000)
    else:
        parser.print_help()

if __name__ == '__main__':
    cli()
