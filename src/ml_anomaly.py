import os
import xml.etree.ElementTree as ET
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

logger = logging.getLogger(__name__)

def detect_anomalies(scan_file):
    """Detect anomalies in scan results using Isolation Forest."""
    try:
        # Parse scan data (e.g., ports, services)
        tree = ET.parse(scan_file)
        root = tree.getroot()
        ports = [int(p.get('portid', 0)) for p in root.findall(".//port")]
        services = [s.get('name', '') for s in root.findall(".//service")]

        # Create feature vector ( simplistic example)
        data = pd.DataFrame({
            'port_count': [len(ports)],
            'unique_services': [len(set(services))]
        })

        # Load or train model
        model_file = 'models/isolation_forest.pkl'
        if os.path.exists(model_file):
            import joblib
            model = joblib.load(model_file)
        else:
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(data)
            import joblib
            joblib.dump(model, model_file)

        # Predict anomalies
        prediction = model.predict(data)
        anomalies = ['port_count', 'unique_services'] if prediction[0] == -1 else []
        logger.info(f"Anomalies detected: {anomalies}")
        return anomalies
    except Exception as e:
        logger.error(f"Anomaly detection failed for {scan_file}: {e}")
        return []
