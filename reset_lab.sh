#!/bin/bash

echo "========================================"
echo "  BootCamp-Lab - Lab Reset Script"
echo "========================================"
echo ""

APP_DIR="/opt/BootCamp-Lab"

# Check if directory exists
if [ ! -d "$APP_DIR" ]; then
    echo "BootCamp-Lab not found at $APP_DIR"
    exit 1
fi

cd $APP_DIR

# Stop the service
echo " Stopping BootCamp-Lab service..."
systemctl stop BootCamp-Lab 2>/dev/null

# Backup old data (optional)
BACKUP_DIR="$APP_DIR/backups/$(date +%Y%m%d_%H%M%S)"
echo " Creating backup at $BACKUP_DIR..."
mkdir -p $BACKUP_DIR
[ -f instance/vulnerable_app.db ] && cp instance/vulnerable_app.db $BACKUP_DIR/
[ -d uploads ] && cp -r uploads $BACKUP_DIR/

# Remove database
echo " Removing old database..."
rm -f instance/vulnerable_app.db
rm -f instance/*.db

# Clear uploaded files
echo " Clearing uploaded files..."
rm -rf uploads/*

# Clear activity logs
echo " Clearing session data..."
rm -rf flask_session/* 2>/dev/null

# Reinitialize database
echo " Reinitializing database..."
source venv/bin/activate
python3 << EOF
from app import app, init_db
init_db()
print(" Database reinitialized!")
EOF

# Restart service
echo " Starting BootCamp-Lab service..."
systemctl start BootCamp-Lab

# Check status
sleep 2
if systemctl is-active --quiet BootCamp-Lab.service; then
    echo ""
    echo " BootCamp-Lab has been reset successfully!"
    echo ""
    echo "Default credentials restored:"
    echo "  Admin: admin / admin123"
    echo "  User:  john / password123"
    echo ""
    echo "Access: http://$(hostname -I | awk '{print $1}'):5000"
    echo "========================================"
else
    echo ""
    echo " Failed to restart service. Check logs:"
    echo "   journalctl -u BootCamp-Lab -n 50"
fi
