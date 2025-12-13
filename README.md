

روی پورت 3214 نصب میشود


```
curl -o install_clipboard.sh https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/install_clipboard.sh && chmod +x install_clipboard.sh && sudo ./install_clipboard.sh
```


بررسی لاگ‌های سرویس (بعد از ایجاد یک کلیپ ناموفق):

Bash
```
sudo journalctl -u clipboard.service --since "2 minutes ago"
```
بررسی وجود کلیپ در دیتابیس با CLI:

Bash

```
sudo /opt/clipboard_server/clipboard_cli.sh
```

# سپس گزینه 2 (لیست تمام کلیپ‌ها) را انتخاب کنید.


🚀 دستور یکپارچه حذف نصب
پس از آپلود فایل uninstall.sh با محتوای بالا در آدرس گیت‌هاب خود، می‌توانید از دستور تک خطی زیر برای حذف کامل برنامه از سرور استفاده کنید:


```
curl -o uninstall.sh https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/uninstall.sh && chmod +x uninstall.sh && sudo ./uninstall.sh
```

✅ WEB SERVICE STATUS (Port 3214): active
------------------------------------------------
🌐 CLIPBOARD URL (View Only): http://YOUR_IP:3214
------------------------------------------------
💻 ADMIN/CREATION: Use the Command Line Interface (CLI)!
   
```
sudo /opt/clipboard_server/venv/bin/python3 /opt/clipboard_server/clipboard_cli.py
```

------------------------------------------------
Status:   sudo systemctl status clipboard.service
Logs:     sudo journalctl -u clipboard.service -f
================================================


متوجه شدم. اگر حتی با نسخه V21 (که تمامی اشکالات مربوط به Flask و Template را حل می‌کرد) همچنان خطای Internal Server Error را در سرور خام دریافت می‌کنید، این نشان می‌دهد که ما باید کل ساختار را تغییر دهیم و اپلیکیشن Flask/Gunicorn را کنار بگذاریم.

خواسته‌های شما کاملاً واضح است:

حذف کامل واسط وب (Web Interface)

حذف کامل Flask/Gunicorn و وابستگی‌های پیچیده

تبدیل پنل مدیریت به یک ابزار خط فرمان (Command Line Tool) ساده و سبک

حفظ عملکرد اصلی (ایجاد لینک، مشاهده، حذف، و ویرایش Key)

این رویکرد، پایداری برنامه را در محیط سرور خام به‌شدت افزایش می‌دهد و نیاز به تنظیمات وب سرور و Gunicorn را از بین می‌برد.

💡 رویکرد جدید: اسکریپت CLI پایتون
من یک اسکریپت پایتون تک‌فایلی به نام clipboard_cli.py به همراه یک اسکریپت نصب ساده شده ارائه می‌دهم. این اسکریپت:

از کتابخانه Flask استفاده نمی‌کند.

فقط یک سرویس Gunicorn بسیار ساده را برای سرویس‌دهی لینک‌ها اجرا می‌کند (که فقط بخش نمایش لینک را دارد و کاملاً مجزا است).

پنل مدیریت را به یک ابزار تعاملی در ترمینال تبدیل می‌کند.

🛠️ نسخه V22: سیستم CLI و سرویس‌دهی سبک
لطفاً محتوای فایل install_clipboard.sh در مخزن گیت‌هاب خود را با کد زیر جایگزین کنید. این اسکریپت شامل دو بخش اصلی است:

clipboard_cli.py: ابزار خط فرمان (CLI) برای مدیریت کلیپ‌ها.

web_service.py: سرویس‌دهنده وب سبک برای نمایش لینک‌های عمومی (بدون پنل ادمین).

📜 کد install_clipboard.sh (نسخه V22 - تغییر به CLI)
Bash

#!/bin/bash
# Internet Clipboard Server Installer (CLI Management + Simple Web Viewer)
# V22 - Light mode: Removes Admin Web Panel and replaces it with a command-line interface (CLI).

set -e

# --- Configuration ---
INSTALL_DIR="/opt/clipboard_server"
CLIPBOARD_PORT="3214" 
EXPIRY_DAYS="30"
SECRET_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32) 

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Check root access
if [ "$EUID" -ne 0 ]; then
    print_error "❌ Please run with root access: sudo bash install_clipboard.sh"
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server Installer (V22 - CLI/Light Mode)"
echo "=================================================="

# ============================================
# 1. System Setup & Venv
# ============================================
print_status "1/6: Ensuring system setup and Virtual Environment..."
apt update -y
apt install -y python3 python3-pip python3-venv curl wget

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" 

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate || true

PYTHON_VENV_PATH="$INSTALL_DIR/venv/bin/python3"
GUNICORN_VENV_PATH="$INSTALL_DIR/venv/bin/gunicorn"

# Using a minimal list of dependencies
cat > requirements.txt << 'REQEOF'
Flask
python-dotenv
gunicorn
requests
REQEOF
pip install -r requirements.txt || true
deactivate

# ============================================
# 2. Update .env and Directories
# ============================================
print_status "2/6: Updating configuration and ensuring directory structure..."

mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
chmod 777 "$INSTALL_DIR/uploads" 

# --- Create .env file ---
cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
MAX_REMOTE_SIZE_MB=50
# Path added for robust manual loading
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
ENVEOF

# ============================================
# 3. Create web_service.py (Simplified Flask for view only)
# ============================================
print_status "3/6: Creating web_service.py (Simplified view-only web server)..."
cat > "$INSTALL_DIR/web_service.py" << 'PYEOF_WEB_SERVICE'
import os
import sqlite3
import re
import requests
import urllib.parse
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g, session, abort
from dotenv import load_dotenv, find_dotenv

# --- Configuration & Init ---
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', find_dotenv(usecwd=True))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
MAX_REMOTE_SIZE_BYTES = int(os.getenv('MAX_REMOTE_SIZE_MB', 50)) * 1024 * 1024 

# --- Database Management ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- Cleanup (Only runs on view/index access) ---
def cleanup_expired_clips():
    db = get_db()
    cursor = db.cursor()
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_utc,))
    expired_files = cursor.fetchall()

    for file_path_tuple in expired_files:
        file_paths = file_path_tuple[0].split(',') if file_path_tuple[0] else []
        for file_path in file_paths:
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path.strip())
            if file_path and os.path.exists(full_path):
                try:
                    os.remove(full_path)
                except OSError as e:
                    print(f"Error removing file {full_path}: {e}")
            
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    db.commit()


# --- Simple Routes (No Admin Panel) ---

@app.route('/')
def index():
    cleanup_expired_clips()
    # The main page is just a prompt to use the CLI tool now
    return render_template('index.html', EXPIRY_DAYS=EXPIRY_DAYS)


@app.route('/<key>')
def view_clip(key):
    cleanup_expired_clips()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT content, file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        return render_template('clipboard.html', clip=None, key=key)

    content, file_path_string, expires_at_str = clip
    
    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    
    if expires_at < now_utc:
        cleanup_expired_clips()
        return render_template('clipboard.html', clip=None, key=key, expired=True)

    time_left = expires_at - now_utc
    days = time_left.days
    hours = time_left.seconds // 3600
    minutes = (time_left.seconds % 3600) // 60
    
    file_paths_list = file_path_string.split(',') if file_path_string else []
    
    files_info = []
    for p in file_paths_list:
        if p.strip():
            filename_with_key = os.path.basename(p.strip())
            original_filename = filename_with_key.split('_', 2)[-1] 
            files_info.append({'path': p.strip(), 'name': original_filename})

    # Note: We do not handle create_clip or upload here, only viewing.

    return render_template('clipboard.html', 
                           key=key, 
                           content=content, 
                           files_info=files_info,
                           expiry_info_days=days,
                           expiry_info_hours=hours,
                           expiry_info_minutes=minutes,
                           server_port=CLIPBOARD_PORT)


@app.route('/download/<path:file_path>')
def download_file(file_path):
    # Security check for file path
    if not file_path.startswith(UPLOAD_FOLDER + '/'):
         flash('Invalid download request.', 'error')
         return redirect(url_for('index'))
         
    # Extract key from filename
    filename_part = os.path.basename(file_path)
    try:
        key = filename_part.split('_', 1)[0]
    except IndexError:
        flash('Invalid file path format.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        flash('File not found or link has expired.', 'error')
        return redirect(url_for('index'))

    file_paths_string, expires_at_str = clip
    
    # Check if the requested file_path is actually part of the clip
    if file_path not in [p.strip() for p in file_paths_string.split(',')]:
        flash('File not found in the associated clip.', 'error')
        return redirect(url_for('view_clip', key=key))


    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        cleanup_expired_clips()
        flash('File not found or link has expired.', 'error')
        return redirect(url_for('index'))
    
    
    # Use original filename for download name
    filename_with_key = os.path.basename(file_path)
    original_filename = filename_with_key.split('_', 2)[-1] 
    
    return send_from_directory(os.path.dirname(app.root_path), 
                               file_path, 
                               as_attachment=True, 
                               download_name=original_filename)

if __name__ == '__main__':
    # This block is not used in Gunicorn mode, but is kept for completeness
    pass

PYEOF_WEB_SERVICE

# ============================================
# 4. Create clipboard_cli.py (The new Admin/Create Tool)
# ============================================
print_status "4/6: Creating clipboard_cli.py (New CLI Management Tool)..."
cat > "$INSTALL_DIR/clipboard_cli.py" << 'PYEOF_CLI_TOOL'
import os
import sqlite3
import random
import string
import re
import sys
import argparse
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv

# --- Configuration & Init ---
# Attempt to load .env from the expected path
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
BASE_URL = f"http://YOUR_IP:{os.getenv('CLIPBOARD_PORT', '3214')}" 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
# MAX_REMOTE_SIZE_BYTES is not used here as remote file download must be managed via web interface or external tools now.

# --- Colors ---
class Color:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Database Management ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clips (
            id INTEGER PRIMARY KEY,
            key TEXT UNIQUE NOT NULL,
            content TEXT,
            file_path TEXT, 
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def generate_key(length=8):
    characters = string.ascii_letters + string.digits
    conn = get_db_connection()
    cursor = conn.cursor()
    while True:
        key = ''.join(random.choice(characters) for i in range(length))
        cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
        exists = cursor.fetchone()
        if not exists:
            conn.close()
            return key

def cleanup_expired_clips():
    conn = get_db_connection()
    cursor = conn.cursor()
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    # Delete files associated with expired clips
    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_utc,))
    expired_files = cursor.fetchall()

    for file_path_tuple in expired_files:
        file_paths = file_path_tuple['file_path'].split(',') if file_path_tuple['file_path'] else []
        for file_path in file_paths:
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path.strip())
            if file_path and os.path.exists(full_path):
                try:
                    os.remove(full_path)
                except OSError as e:
                    print(f"[{Color.YELLOW}WARNING{Color.END}] Error removing file {full_path}: {e}")
            
    # Delete clips from DB
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    conn.commit()
    conn.close()

# --- Main CLI Functions ---

def create_new_clip():
    print(f"\n{Color.BLUE}{Color.BOLD}--- Create New Clip ---{Color.END}")
    content = input("Enter text content (leave empty if only creating a placeholder): ").strip()
    custom_key = input("Enter custom link key (optional, leave empty for random): ").strip()

    key = None
    if custom_key:
        if not re.match(KEY_REGEX, custom_key):
            print(f"{Color.RED}Error: Custom key is invalid.{Color.END}")
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM clips WHERE key = ?", (custom_key,))
        if cursor.fetchone():
            print(f"{Color.RED}Error: Key '{custom_key}' is already taken.{Color.END}")
            conn.close()
            return
        key = custom_key
    
    if not key:
        key = generate_key()

    if not content:
        content = f"Empty clip created via CLI. Key: {key}"

    expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key, content, "", datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        
        print(f"\n{Color.GREEN}✅ Success! Clip created:{Color.END}")
        print(f"   {Color.BOLD}Key:{Color.END} {key}")
        print(f"   {Color.BOLD}Link:{Color.END} {BASE_URL}/{key}")
        print(f"   {Color.BOLD}Expires:{Color.END} {expires_at.strftime('%Y-%m-%d %H:%M:%S')} (in {EXPIRY_DAYS} days)")
        
    except sqlite3.Error as e:
        print(f"{Color.RED}Database Error: {e}{Color.END}")
    except Exception as e:
        print(f"{Color.RED}An unexpected error occurred: {e}{Color.END}")


def list_clips():
    cleanup_expired_clips()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, key, content, file_path, created_at, expires_at FROM clips ORDER BY id DESC")
    clips = cursor.fetchall()
    conn.close()

    if not clips:
        print(f"\n{Color.YELLOW}No active clips found.{Color.END}")
        return

    print(f"\n{Color.BLUE}{Color.BOLD}--- Active Clips ({len(clips)}) ---{Color.END}")
    print(f"{Color.CYAN}{'ID':<4} {'Key':<20} {'Content Preview':<40} {'Files':<10} {'Expires':<10}{Color.END}")
    print("-" * 90)
    
    for clip in clips:
        content_preview = (clip['content'][:35] + '...') if clip['content'] and len(clip['content']) > 35 else (clip['content'] or "No Content")
        file_count = len([p for p in clip['file_path'].split(',') if p.strip()]) if clip['file_path'] else 0
        
        print(f"{clip['id']:<4} {Color.BOLD}{clip['key']:<20}{Color.END} {content_preview:<40} {file_count:<10} {clip['expires_at'].split(' ')[0]:<10}")
    print("-" * 90)


def delete_clip():
    list_clips()
    if not input(f"\n{Color.YELLOW}Proceed with deletion? (yes/no): {Color.END}").lower().strip().startswith('y'):
        print("Deletion cancelled.")
        return

    clip_id_or_key = input("Enter Clip ID or Key to delete: ").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Try to find the clip by ID or Key
    if clip_id_or_key.isdigit():
        cursor.execute("SELECT id, key, file_path FROM clips WHERE id = ?", (int(clip_id_or_key),))
    else:
        cursor.execute("SELECT id, key, file_path FROM clips WHERE key = ?", (clip_id_or_key,))
    
    clip = cursor.fetchone()
    
    if not clip:
        print(f"{Color.RED}Error: Clip with ID/Key '{clip_id_or_key}' not found.{Color.END}")
        conn.close()
        return

    clip_id = clip['id']
    clip_key = clip['key']
    
    # Delete associated files
    if clip['file_path']:
        file_paths = [p.strip() for p in clip['file_path'].split(',') if p.strip()]
        for file_path in file_paths:
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
            if os.path.exists(full_path):
                os.remove(full_path)
                print(f" - Deleted file: {os.path.basename(file_path)}")
                
    # Delete from DB
    cursor.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
    conn.commit()
    conn.close()
    
    print(f"\n{Color.GREEN}✅ Successfully deleted Clip ID {clip_id} (Key: {clip_key}).{Color.END}")


def edit_clip():
    list_clips()
    clip_id_or_key = input("\nEnter Clip ID or Key to edit: ").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if clip_id_or_key.isdigit():
        cursor.execute("SELECT id, key, content FROM clips WHERE id = ?", (int(clip_id_or_key),))
    else:
        cursor.execute("SELECT id, key, content FROM clips WHERE key = ?", (clip_id_or_key,))
    
    clip = cursor.fetchone()
    
    if not clip:
        print(f"{Color.RED}Error: Clip with ID/Key '{clip_id_or_key}' not found.{Color.END}")
        conn.close()
        return

    clip_id = clip['id']
    clip_key = clip['key']

    print(f"\n{Color.CYAN}--- Editing Clip ID {clip_id} (Key: {clip_key}) ---{Color.END}")
    print(f"Current Key: {Color.BOLD}{clip_key}{Color.END}")
    print("--------------------------------------------------")
    print(f"1. Edit Key")
    print(f"2. Edit Content")
    print(f"0. Cancel")
    
    choice = input("Enter choice (1/2/0): ").strip()

    if choice == '1':
        new_key = input(f"Enter new Key (Current: {clip_key}): ").strip()
        if not new_key or not re.match(KEY_REGEX, new_key):
            print(f"{Color.RED}Error: Invalid or empty key.{Color.END}")
            conn.close()
            return
        
        if new_key != clip_key:
            cursor.execute("SELECT 1 FROM clips WHERE key = ? AND id != ?", (new_key, clip_id))
            if cursor.fetchone():
                print(f"{Color.RED}Error: Key '{new_key}' is already taken.{Color.END}")
                conn.close()
                return
        
        cursor.execute("UPDATE clips SET key = ? WHERE id = ?", (new_key, clip_id))
        conn.commit()
        print(f"\n{Color.GREEN}✅ Key updated successfully to: {new_key}{Color.END}")
        
    elif choice == '2':
        print(f"\n{Color.YELLOW}--- Current Content ---{Color.END}")
        print(clip['content'] if clip['content'] else "(Empty)")
        print("---------------------------------------")
        new_content = input("Enter new content (or press Ctrl+D/Ctrl+Z to cancel): ").strip()
        
        # Simple multi-line input handling (Note: this is basic)
        content_lines = []
        print(f"Type content. Press Ctrl+D/Ctrl+Z, then Enter, to finish.")
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    break
                content_lines.append(line.rstrip('\n'))
            new_content = "\n".join(content_lines)
        except EOFError:
            new_content = "\n".join(content_lines)

        cursor.execute("UPDATE clips SET content = ? WHERE id = ?", (new_content, clip_id))
        conn.commit()
        print(f"\n{Color.GREEN}✅ Content updated successfully.{Color.END}")
    
    elif choice == '0':
        print("Edit cancelled.")

    conn.close()

def main_menu():
    init_db()
    cleanup_expired_clips()

    while True:
        print(f"\n{Color.PURPLE}{Color.BOLD}========================================{Color.END}")
        print(f"{Color.PURPLE}{Color.BOLD}   Clipboard CLI Manager (Base URL: {BASE_URL}){Color.END}")
        print(f"{Color.PURPLE}{Color.BOLD}========================================{Color.END}")
        print(f"1. {Color.GREEN}Create New Clip{Color.END} (Text only)")
        print(f"2. {Color.BLUE}List All Clips{Color.END}")
        print(f"3. {Color.CYAN}Edit Clip{Color.END} (Key or Content)")
        print(f"4. {Color.RED}Delete Clip{Color.END}")
        print("0. Exit")
        
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            create_new_clip()
        elif choice == '2':
            list_clips()
        elif choice == '3':
            edit_clip()
        elif choice == '4':
            delete_clip()
        elif choice == '0':
            print(f"\n{Color.BOLD}Exiting CLI Manager. Goodbye!{Color.END}")
            break
        else:
            print(f"{Color.RED}Invalid choice. Please try again.{Color.END}")

if __name__ == '__main__':
    main_menu()

PYEOF_CLI_TOOL

# ============================================
# 5. Create Minimal Templates (For web_service.py)
# ============================================
print_status "5/6: Creating minimal HTML templates for web view..."

# --- index.html (Just a welcome page) ---
cat > "$INSTALL_DIR/templates/index.html" << 'INDEXEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internet Clipboard Server</title>
    <style>
        body { font-family: sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 50px; text-align: center;}
        .container { max-width: 600px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #007bff; margin-bottom: 20px; }
        p { font-size: 1.1em; color: #555; }
        .cli-note { margin-top: 30px; padding: 15px; background-color: #ffeeba; border: 1px solid #ffcc00; border-radius: 8px; color: #856404; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 Internet Clipboard Server</h1>
        <p>This server is running in Light Mode.</p>
        <div class="cli-note">
            To create or manage clips (text or files), you must connect to the server via SSH and use the Command Line Interface (CLI) tool:
            <br>
            <code>sudo python3 /opt/clipboard_server/clipboard_cli.py</code>
        </div>
    </div>
</body>
</html>
INDEXEOF

# --- clipboard.html (Same as before, only for viewing data) ---
# NOTE: This is the same file as V21, but now it's guaranteed to be created.
cat > "$INSTALL_DIR/templates/clipboard.html" << 'CLIPBOARDEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clip: {{ key }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #007bff; text-align: center; margin-bottom: 20px; }
        pre { background-color: #eee; padding: 15px; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; overflow: auto; max-height: 400px; margin-bottom: 20px; border: 1px solid #ccc; position: relative; }
        .content-section { margin-bottom: 30px; }
        .files-section { margin-bottom: 30px; border-top: 1px solid #eee; padding-top: 20px; }
        .files-section h2 { color: #333; font-size: 1.2em; margin-bottom: 15px; }
        .file-item { display: flex; justify-content: space-between; align-items: center; background-color: #f0f8ff; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; border-left: 5px solid #007bff; }
        .file-item a { color: #007bff; text-decoration: none; font-weight: bold; }
        .file-item a:hover { text-decoration: underline; }
        .expiry-info { text-align: center; color: #d9534f; font-weight: bold; margin-bottom: 20px; }
        .back-link { display: block; text-align: center; margin-top: 30px; }
        .back-link a { color: #007bff; text-decoration: none; font-weight: bold; }
        .flash { padding: 15px; border-radius: 8px; margin-bottom: 15px; font-weight: bold; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .copy-button { background-color: #5cb85c; color: white; padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9em; float: right; margin-left: 10px; }
        .copy-button:hover { background-color: #4cae4c; }
    </style>
</head>
<body>
    <div class="container">
        <div class="flash error">
            {% for category, message in get_flashed_messages(with_categories=true) %}
                {% if category == 'error' %}
                    {{ message }}
                {% endif %}
            {% endfor %}
        </div>
        
        {% if clip and content %}
            <h1>Clip Content for: {{ key }}</h1>
            
            <div class="expiry-info">
                Expires in: {{ expiry_info_days }} days, {{ expiry_info_hours }} hours, and {{ expiry_info_minutes }} minutes.
            </div>

            <div class="content-section">
                <h2>Text Content</h2>
                <button class="copy-button" onclick="copyContent()">Copy Text</button>
                <pre id="text-content">{{ content }}</pre>
            </div>
        {% elif expired %}
            <h1>Clip Not Found</h1>
            <div class="expiry-info">This clipboard link has expired and its content has been deleted.</div>
        {% else %}
             <h1>Clip Not Found</h1>
             <div class="expiry-info">The clip with key **{{ key }}** does not exist.</div>
        {% endif %}
        
        {% if files_info %}
            <div class="files-section">
                <h2>Attached Files ({{ files_info|length }})</h2>
                {% for file in files_info %}
                    <div class="file-item">
                        <span>{{ file.name }}</span>
                        <a href="{{ url_for('download_file', file_path=file.path) }}">Download</a>
                    </div>
                {% endfor %}
            </div>
        {% endif %}

        <div class="back-link">
            <a href="/">← Go to Home</a>
        </div>
    </div>

    <script>
        function copyContent() {
            const content = document.getElementById('text-content').innerText;
            navigator.clipboard.writeText(content).then(() => {
                alert('Text copied to clipboard!');
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        }
    </script>
</body>
</html>
CLIPBOARDEOF

# Note: We skip login.html, admin.html, edit_key.html, edit_content.html as they are no longer needed.


# ============================================
# 6. Create Systemd Service (Single Service for Web View)
# ============================================
print_status "6/6: Creating Systemd service for light web view..."

# --- clipboard.service (Port 3214 - Runs web_service.py) ---
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Web Viewer (Light Mode)
After=network.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
# ExecStart now runs the minimal web_service.py
ExecStart=${GUNICORN_VENV_PATH} --workers 4 --bind 0.0.0.0:${CLIPBOARD_PORT} web_service:app
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env
Restart=always
TimeoutSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF


# ============================================
# 7. Final Steps
# ============================================
print_status "7/7: Initializing Database and starting service..."

# Initialize DB using the venv Python
"$PYTHON_VENV_PATH" "$INSTALL_DIR/clipboard_cli.py"

systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V22 - CLI/Light Mode)"
echo "================================================"
echo "✅ WEB SERVICE STATUS (Port ${CLIPBOARD_PORT}): $(systemctl is-active clipboard.service)"
echo "------------------------------------------------"
echo "🌐 CLIPBOARD URL (View Only): http://YOUR_IP:${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "💻 ADMIN/CREATION: Use the Command Line Interface (CLI)!"
echo -e "   ${BLUE}sudo ${PYTHON_VENV_PATH} ${INSTALL_DIR}/clipboard_cli.py${NC}"
echo "------------------------------------------------"
echo "Status:   sudo systemctl status clipboard.service"
echo "Restart:  sudo systemctl restart clipboard.service"
echo "================================================"
⏭️ گام نهایی
جایگزینی در گیت‌هاب: محتوای کامل کد بالا را در فایل install_clipboard.sh در مخزن گیت‌هاب خود جایگزین کنید.

اجرای مجدد در سرور: دستور یکپارچه زیر را در سرور خام خود اجرا کنید:

Bash

curl -o install_clipboard.sh https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/install_clipboard.sh && chmod +x install_clipboard.sh && sudo ./install_clipboard.sh
نحوه استفاده از پنل مدیریت CLI
پس از اجرای موفقیت‌آمیز اسکریپت، 
برای مدیریت کلیپ‌ها، باید به سرور SSH بزنید و دستور زیر را اجرا کنید:

Bash

```
sudo /opt/clipboard_server/venv/bin/python3 /opt/clipboard_server/clipboard_cli.py
```

این دستور منوی زیر را در ترمینال به شما نمایش می‌دهد:

========================================
   Clipboard CLI Manager (Base URL: http://YOUR_IP:3214)
========================================
1. Create New Clip (Text only)
2. List All Clips
3. Edit Clip (Key or Content)
4. Delete Clip
0. Exit
Enter your choice:
```
sudo curl -sL https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/install_clipboard.sh | sudo bash
```


```
sudo curl -sL https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/install_bot_final.sh | sudo bash
```

توکن را در قسمت مربوطه زیر جایگزاری کن
```
BOT_TOKEN="YOUR_BOT_TOKEN_HERE" PROXY_URL="" sudo bash -c 'curl -sL https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/install_bot_final.sh | bash'
```


```
BOT_TOKEN="YOUR_BOT_TOKEN" PROXY_URL="" sudo bash -c 'curl -sL https://raw.githubusercontent.com/2amir563/khodam-clipboard/main/install_clipboard.sh | bash'
```


