#!/bin/bash
# Script to completely remove the Clipboard Server installation

# Define Configuration (must match your install script)
INSTALL_DIR="/opt/clipboard_server"
SERVICE_NAME="clipboard.service"
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    print_error "❌ Please run the script with root access: sudo bash uninstall.sh"
    exit 1
fi

echo -e "\n${RED}=========================================${NC}"
echo -e "${RED}  ⚠️ Completely Uninstalling Clipboard Server ⚠️  ${NC}"
echo -e "${RED}=========================================${NC}"
echo "This operation will remove the service and the installation directory ${INSTALL_DIR}."

read -r -p "Are you sure? (y/N): " CONFIRMATION

if [[ "$CONFIRMATION" != "y" && "$CONFIRMATION" != "Y" ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

# --- 1. Systemd Service Removal ---
print_status "1/2: Stopping and removing Systemd service (${SERVICE_NAME})..."
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm "/etc/systemd/system/${SERVICE_NAME}" 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
print_status "    Service removed successfully."


# --- 2. Directory Removal ---
print_status "2/2: Deleting installation directory ${INSTALL_DIR} and all data..."
if [ -d "$INSTALL_DIR" ]; then
    rm -rf "$INSTALL_DIR"
    print_status "    Directory removed successfully."
else
    print_error "    Directory ${INSTALL_DIR} not found. Skipping."
fi

echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}      ✅ Uninstallation completed successfully.      ${NC}"
echo -e "${GREEN}=========================================${NC}"
