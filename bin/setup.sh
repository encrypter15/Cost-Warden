#!/bin/bash

# Setup script for COST-Warden

echo "Setting up COST-Warden..."

# Install dependencies
pip install -r requirements.txt

# Create encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" > configs/encryption.key

# Initialize Redis
docker-compose up -d redis

# Build Docker image
docker build -t cost-warden:latest .

echo "Setup complete!"
