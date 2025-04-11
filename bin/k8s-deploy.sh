#!/bin/bash

# Deploy COST-Warden scan job to Kubernetes

echo "Deploying scan job to Kubernetes..."
kubectl apply -f k8s/scan-job.yaml
echo "Job deployed. Check status with: kubectl get jobs"
