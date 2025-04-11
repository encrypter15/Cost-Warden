import os
import xml.etree.ElementTree as ET
import requests
import logging

logger = logging.getLogger(__name__)

def correlate_cve(scan_file, scan_type):
    """Correlate scan results with NVD CVE database."""
    try:
        cve_data = []
        if scan_type == 'port':
            tree = ET.parse(scan_file)
            root = tree.getroot()
            for service in root.findall(".//service"):
                product = service.get('product', '')
                version = service.get('version', '')
                if product and version:
                    response = requests.get(
                        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*",
                        timeout=10
                    )
                    if response.status_code == 200:
                        cves = response.json().get('vulnerabilities', [])
                        cve_data.extend([cve['cve']['id'] for cve in cves])
        logger.info(f"Found {len(cve_data)} CVEs for {scan_file}")
        return cve_data
    except Exception as e:
        logger.error(f"CVE correlation failed for {scan_file}: {e}")
        return []
