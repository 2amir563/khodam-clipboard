#!/bin/bash
# Internet Clipboard - Ultimate Manager (V51)
# Features: Smart Install, Analytics, Manual/Auto Backup Control, Restore, Port Change & Absolute Uninstall.

set -e

INSTALL_DIR="/opt/clipboard_server"
BACKUP_DIR="/opt/clipboard_backups"
ENV_FILE="${INSTALL_DIR}/.env"
DATABASE_PATH="${INSTALL_DIR}/clipboard.db"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# --- CORE FUNCTIONS ---

show_menu() {
    clear
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${YELLOW}    📋 INTERNET CLIPBOARD MANAGER (V51)   ${NC}"
    echo -e "${BLUE}==================================================${NC}"
    if [ ! -d "$INSTALL_DIR" ]; then
        echo -e "${RED}Server is NOT installed yet!${NC}"
        echo -e "1) ${GREEN}Start Initial Installation${NC}"
        echo -e "q) Exit"
    else
        echo -e "1) ${BLUE}Check Status & Analytics (24h)${NC}"
        echo -e "2) ${GREEN}Create Full Backup (Manual)${NC}"
        echo -e "3) ${GREEN}Restore from Backup${NC}"
        echo -e "4) ${YELLOW}Edit Clip Expiry / List Clips${NC}"
        echo -e "5) ${BLUE}Change Server Port${NC}"
        echo -e "6) ${BLUE}Auto-Backup Settings (Enable/Disable)${NC}"
        echo -e "7) ${RED}Uninstall Entire Server (Absolute Cleanup)${NC}"
        echo -e "q) Exit"
    fi
    echo -ne "\nSelect an option: "
    read opt
    case $opt in
        1) analytics ;;
        2) create_backup ;;
        3) restore_backup ;;
        4) list_and_edit ;;
        5) change_port ;;
        6) setup_cron ;;
        7) uninstall_server ;;
        q) exit 0 ;;
        *) echo "Invalid option"; sleep 1; show_menu ;;
    esac
}

initial_install() {
    print_status "Starting Installation via your GitHub script..."
    curl -s -o install_clipboard.sh https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/install_clipboard.sh
    chmod +x install_clipboard.sh
    sudo ./install_clipboard.sh
    mkdir -p "$BACKUP_DIR"
    print_status "Installation finished. (Auto-backup is OFF by default)"
    sleep 2; show_menu
}

analytics() {
    echo -e "${BLUE}--- Server Analytics ---${NC}"
    if [ -f "$DATABASE_PATH" ]; then
        last_24h=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM clips WHERE created_at > strftime('%s', 'now', '-1 day');")
        total_clips=$(sqlite3 "$DATABASE_PATH" "SELECT COUNT(*) FROM clips;")
        echo -e "📈 New Clips (Last 24h): ${GREEN}$last_24h${NC}"
        echo -e "📚 Total Clips in DB: ${GREEN}$total_clips${NC}"
    else
        echo -e "${RED}Database not found!${NC}"
    fi
    echo -e "------------------------"
    systemctl status clipboard.service | grep "Active:" || echo "Service not running."
    read -p "Press Enter to return..." ; show_menu
}

change_port() {
    current_port=$(grep "CLIPBOARD_PORT" "$ENV_FILE" | cut -d'=' -f2)
    echo -e "Current Port: ${YELLOW}$current_port${NC}"
    read -p "Enter NEW Port: " new_port
    if [[ "$new_port" =~ ^[0-9]+$ ]]; then
        sed -i "s/CLIPBOARD_PORT=.*/CLIPBOARD_PORT=$new_port/" "$ENV_FILE"
        sudo sed -i "s/--bind 0.0.0.0:.*/--bind 0.0.0.0:$new_port web_service:app/" /etc/systemd/system/clipboard.service
        sudo systemctl daemon-reload
        sudo systemctl restart clipboard.service
        print_status "Port changed to $new_port."
    else
        print_error "Invalid port number!"
    fi
    read -p "Press Enter to return..." ; show_menu
}

setup_cron() {
    echo -e "\n${BLUE}--- Auto-Backup Settings ---${NC}"
    echo -e "1) ${GREEN}Enable Nightly Auto-Backup (00:00)${NC}"
    echo -e "2) ${RED}Disable/Remove Auto-Backup${NC}"
    echo -e "b) Back to Menu"
    read -p "Select an option: " cron_opt

    if [ "$cron_opt" == "1" ]; then
        print_status "Setting up Nightly Auto-Backup..."
        mkdir -p "$BACKUP_DIR"
        cat > "$INSTALL_DIR/auto_backup.sh" << 'EOF'
#!/bin/bash
BDIR="/opt/clipboard_backups"; IDIR="/opt/clipboard_server"
FNAME="auto_backup_$(date +%Y%m%d).tar.gz"
tar -cvzf "$BDIR/$FNAME" -C "$IDIR" clipboard.db uploads .env
find "$BDIR" -name "auto_backup_*" -mtime +7 -delete
EOF
        chmod +x "$INSTALL_DIR/auto_backup.sh"
        (crontab -l 2>/dev/null | grep -v "auto_backup.sh" ; echo "0 0 * * * $INSTALL_DIR/auto_backup.sh") | crontab -
        print_status "Auto-backup ENABLED (7-day retention)."
    elif [ "$cron_opt" == "2" ]; then
        crontab -l 2>/dev/null | grep -v "auto_backup.sh" | crontab - || true
        print_status "Auto-backup DISABLED and removed from schedule."
    fi
    read -p "Press Enter to return..." ; show_menu
}

create_backup() {
    FNAME="manual_backup_$(date +%H%M_%Y%m%d).tar.gz"
    sudo tar -cvzf "/root/$FNAME" -C "$INSTALL_DIR" clipboard.db uploads .env
    print_status "Backup saved at /root/$FNAME"
    read -p "Press Enter to return..." ; show_menu
}

restore_backup() {
    read -p "Enter backup file path: " bpath
    if [ -f "$bpath" ]; then
        sudo systemctl stop clipboard.service || true
        sudo tar -xvzf "$bpath" -C "$INSTALL_DIR"
        sudo chmod -R 777 "$INSTALL_DIR"
        sudo systemctl restart clipboard.service
        print_status "Restore complete!"
    else
        print_error "File not found!"
    fi
    read -p "Press Enter to return..." ; show_menu
}

list_and_edit() {
    echo -e "\n${BLUE}ID | Key | Expires At${NC}"
    sqlite3 "$DATABASE_PATH" "SELECT id, key, datetime(expires_at, 'unixepoch') FROM clips ORDER BY id DESC LIMIT 10;"
    read -p "Enter Key to change expiry (or 'q' to back): " ckey
    if [ "$ckey" != "q" ]; then
        read -p "New expiry (days from now): " dnum
        new_ts=$(python3 -c "import time; print(int(time.time() + ($dnum * 86400)))")
        sqlite3 "$DATABASE_PATH" "UPDATE clips SET expires_at=$new_ts WHERE key='$ckey';"
        print_status "Expiry updated."
    fi
    show_menu
}

uninstall_server() {
    echo -e "${RED}!!! WARNING: THIS WILL DELETE EVERYTHING !!!${NC}"
    read -p "Type 'DELETE' to confirm uninstall: " confirm
    if [ "$confirm" == "DELETE" ]; then
        sudo systemctl stop clipboard.service || true
        sudo systemctl disable clipboard.service || true
        sudo rm -f /etc/systemd/system/clipboard.service
        sudo systemctl daemon-reload
        crontab -l 2>/dev/null | grep -v "auto_backup.sh" | crontab - || true
        sudo rm -rf "$INSTALL_DIR"
        sudo rm -rf "$BACKUP_DIR"
        rm -f install_clipboard.sh
        print_status "Server and all related files have been removed."
        echo -e "${YELLOW}Note: Delete this script with: rm manage_clipboard.sh${NC}"
        exit 0
    fi
    show_menu
}

if [ "$EUID" -ne 0 ]; then print_error "Run as root"; exit 1; fi
show_menu
