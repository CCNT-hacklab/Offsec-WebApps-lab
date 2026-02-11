#!/bin/bash

echo "=================================================="
echo "  BootCamp-Lab - Vulnerable Web Application"
echo "  Deployment Script for Ubuntu Server"
echo "=================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo " Please run as root (use sudo)"
    exit 1
fi

# Update system
echo " Updating system packages..."
apt update && apt upgrade -y

# Install Python and dependencies
echo " Installing Python and dependencies..."
apt install -y python3 python3-pip python3-venv git

# Create application directory
APP_DIR="/opt/BootCamp-Lab"
echo " Creating application directory: $APP_DIR"
mkdir -p $APP_DIR

# Copy files or clone repository
echo " Setting up application files..."
if [ -d "$(dirname $0)" ]; then
    cp -r $(dirname $0)/* $APP_DIR/
else
    echo " Source directory not found"
    exit 1
fi

cd $APP_DIR

# Create virtual environment
echo " Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python packages
echo " Installing Python packages..."
pip install --upgrade pip
pip install -r requirements.txt

# Create .env file
echo " Creating environment configuration..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
fi

# Create necessary directories
mkdir -p uploads
mkdir -p instance
chmod 755 uploads
chmod 755 instance

# Initialize database
echo "🗄️ Initializing database..."
python3 << EOF
from app import app, init_db
init_db()
print("Database initialized successfully!")
EOF

# Create systemd service
echo " Creating systemd service..."
cat > /etc/systemd/system/BootCamp-Lab.service << EOF
[Unit]
Description=BootCamp-Lab - Vulnerable Web Application
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
ExecStart=$APP_DIR/venv/bin/python3 $APP_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start service
echo " Starting BootCamp-Lab service..."
systemctl daemon-reload
systemctl enable BootCamp-Lab.service
systemctl start BootCamp-Lab.service

# Check service status
sleep 2
if systemctl is-active --quiet BootCamp-Lab.service; then
    echo ""
    echo " BootCamp-Lab deployed successfully!"
    echo ""
    echo "=================================================="
    echo "  SERVICE INFORMATION"
    echo "=================================================="
    echo "Status: $(systemctl is-active BootCamp-Lab.service)"
    echo "Port: 5000"
    echo "Access URL: http://$(hostname -I | awk '{print $1}'):5000"
    echo ""
    echo "Default Admin Credentials:"
    echo "  Username: admin"
    echo "  Password: admin123"
    echo ""
    echo "Service Commands:"
    echo "  Start:   systemctl start BootCamp-Lab"
    echo "  Stop:    systemctl stop BootCamp-Lab"
    echo "  Restart: systemctl restart BootCamp-Lab"
    echo "  Status:  systemctl status BootCamp-Lab"
    echo "  Logs:    journalctl -u BootCamp-Lab -f"
    echo ""
    echo " WARNING: This is a vulnerable application!"
    echo "    Use only in isolated lab environment!"
    echo "=================================================="
else
    echo ""
    echo " Service failed to start. Check logs:"
    echo "   journalctl -u BootCamp-Lab -n 50"
    exit 1
fi
