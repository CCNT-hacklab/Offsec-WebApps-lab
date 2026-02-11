#!/bin/bash

echo "========================================"
echo "  BootCamp-Lab - Uninstall Script"
echo "========================================"
echo ""

read -p "  This will completely remove BootCamp-Lab. Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
fi

APP_DIR="/opt/BootCamp-Lab"

# Stop and disable service
echo " Stopping and disabling service..."
systemctl stop BootCamp-Lab 2>/dev/null
systemctl disable BootCamp-Lab 2>/dev/null

# Remove systemd service file
echo " Removing systemd service..."
rm -f /etc/systemd/system/BootCamp-Lab.service
systemctl daemon-reload

# Create final backup
if [ -d "$APP_DIR" ]; then
    BACKUP_DIR="/tmp/BootCamp-Lab_backup_$(date +%Y%m%d_%H%M%S)"
    echo " Creating final backup at $BACKUP_DIR..."
    mkdir -p $BACKUP_DIR
    cp -r $APP_DIR/instance $BACKUP_DIR/ 2>/dev/null
    cp -r $APP_DIR/uploads $BACKUP_DIR/ 2>/dev/null
    echo "Backup saved to: $BACKUP_DIR"
fi

# Remove application directory
echo " Removing application files..."
rm -rf $APP_DIR

echo ""
echo " BootCamp-Lab has been uninstalled!"
echo "========================================"
