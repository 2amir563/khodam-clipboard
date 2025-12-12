#!/bin/bash
# Internet Clipboard Server Installer (CLI Management + Full Web Submission)
# V26 - FINAL FIX: SQLite concurrency issue (Clip Not Found) using WAL mode and check_same_thread=False.

set -e

# --- Configuration (Keep these consistent) ---
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
echo "📋 Internet Clipboard Server Installer (V26 - Final Concurrency Fix)"
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

# Ensure dependencies are installed
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
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
ENVEOF

# ============================================
# 3. Create web_service.py (Full Submission + View Only)
# ============================================
print_status "3/6: Creating web_service.py (V26 - Concurrency Fix)..."
cat > "$INSTALL_DIR/web_service.py" << 'PYEOF_WEB_SERVICE'
import os
import sqlite3
import re
import requests
import urllib.parse
import string
import random
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv, find_dotenv
from werkzeug.utils import secure_filename

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
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'mp3', 'mp4', 'exe', 'bin', 'iso'}

# --- Utility Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # V26 FIX: Use check_same_thread=False and WAL mode for robust concurrency with Gunicorn workers
        db = g._database = sqlite3.connect(
            f'file:{DATABASE_PATH}?mode=rw', 
            uri=True, 
            timeout=10, 
            check_same_thread=False # Allows connections to be shared across threads/workers for better concurrency handling in Flask
        )
        db.row_factory = sqlite3.Row 
        # Enable Write-Ahead Logging (WAL) mode for better concurrency (readers don't block writers)
        db.execute('PRAGMA journal_mode=WAL') 
        db.execute('PRAGMA foreign_keys=ON') 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        # Close the connection when the application context tears down
        db.close()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key(length=8):
    characters = string.ascii_letters + string.digits
    conn = get_db()
    cursor = conn.cursor()
    while True:
        key = ''.join(random.choice(characters) for i in range(length))
        cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
        exists = cursor.fetchone()
        if not exists:
            return key

def cleanup_expired_clips():
    db = get_db()
    cursor = db.cursor()
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

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
                    print(f"[WARNING] Error removing file {full_path}: {e}")
            
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    db.commit()

# --- Main Routes (Submission is back on /) ---

@app.route('/', methods=['GET', 'POST'])
def index():
    cleanup_expired_clips()
    
    # 1. Handle form submission (POST)
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        custom_key = request.form.get('custom_key', '').strip()
        
        uploaded_files = request.files.getlist('files')
        has_content = content or any(f.filename for f in uploaded_files)
        
        if not has_content:
            flash('Please provide text content or upload at least one file.', 'error')
            return redirect(url_for('index'))

        key = custom_key or generate_key()
        
        # Validate key
        if custom_key and not re.match(KEY_REGEX, custom_key):
            flash('Invalid custom key format.', 'error')
            return redirect(url_for('index'))
            
        # Check for key existence
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
        if cursor.fetchone():
            flash(f'Key "{key}" is already in use. Please choose another.', 'error')
            return redirect(url_for('index'))
            
        # File Handling
        file_paths = []
        try:
            for file in uploaded_files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Unique filename structure: key_original-filename
                    unique_filename = f"{key}_{filename}"
                    full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
                    
                    # Save the file
                    file.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), full_path))
                    file_paths.append(full_path)
                elif file.filename and not allowed_file(file.filename):
                     flash(f'File type not allowed: {file.filename}', 'error')
                     return redirect(url_for('index'))
                     
        except Exception as e:
            flash(f'File upload error: {e}', 'error')
            # Clean up files uploaded so far if an error occurs
            for fp in file_paths:
                try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                except: pass
            return redirect(url_for('index'))
            
        # Database Insertion
        expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)
        file_path_string = ','.join(file_paths)
        
        try:
            cursor.execute(
                "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (key, content, file_path_string, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
            )
            db.commit()
            
            # Redirect to the newly created clip
            return redirect(url_for('view_clip', key=key))
            
        except sqlite3.OperationalError as e:
             print(f"SQLITE ERROR: {e}")
             flash("Database error during clip creation. Check server logs.", 'error')
             return redirect(url_for('index'))


    # 2. Handle GET request (Display form)
    return render_template('index.html', EXPIRY_DAYS=EXPIRY_DAYS)


@app.route('/<key>')
def view_clip(key):
    cleanup_expired_clips()
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT content, file_path, expires_at FROM clips WHERE key = ?", (key,))
        clip = cursor.fetchone()
    except sqlite3.OperationalError as e:
        print(f"SQLITE ERROR: {e}")
        return render_template('error.html', message="Database is not initialized or corrupted. Please run the CLI tool on the server."), 500

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
            try:
                original_filename = filename_with_key.split('_', 2)[-1] 
            except IndexError:
                 original_filename = filename_with_key
            files_info.append({'path': p.strip(), 'name': original_filename})


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
    # This remains the same as previous versions
    if not file_path.startswith(UPLOAD_FOLDER + '/'):
         flash('Invalid download request.', 'error')
         return redirect(url_for('index'))
         
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
    
    if file_path not in [p.strip() for p in file_paths_string.split(',')]:
        flash('File not found in the associated clip.', 'error')
        return redirect(url_for('view_clip', key=key))


    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        cleanup_expired_clips()
        flash('File not found or link has expired.', 'error')
        return redirect(url_for('index'))
    
    
    filename_with_key = os.path.basename(file_path)
    original_filename = filename_with_key.split('_', 2)[-1] 
    
    return send_from_directory(os.path.dirname(app.root_path), 
                               file_path, 
                               as_attachment=True, 
                               download_name=original_filename)

if __name__ == '__main__':
    pass

PYEOF_WEB_SERVICE

# ============================================
# 4. Create clipboard_cli.py (The CLI Management Tool - NO CHANGE)
# ============================================
print_status "4/6: Creating clipboard_cli.py (CLI Management Tool - No Change)..."
# The content of clipboard_cli.py remains the same as V23/V24/V25 but we ensure its existence.
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
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
CLIPBOARD_PORT = os.getenv('CLIPBOARD_PORT', '3214')
BASE_URL = f"http://YOUR_IP:{CLIPBOARD_PORT}" 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'

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
    # CLI tool is single-threaded, so standard connection is fine here
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
            
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    conn.commit()
    conn.close()

# --- Main CLI Functions ---

def create_new_clip():
    print(f"\n{Color.BLUE}{Color.BOLD}--- Create New Clip (CLI){Color.END}")
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
    
    if clip['file_path']:
        file_paths = [p.strip() for p in clip['file_path'].split(',') if p.strip()]
        for file_path in file_paths:
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
            if os.path.exists(full_path):
                os.remove(full_path)
                print(f" - Deleted file: {os.path.basename(file_path)}")
                
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
        print(f"Type new content. Press {Color.BOLD}Ctrl+D{Color.END} (or Ctrl+Z on Windows), then Enter, to save and finish.")
        
        content_lines = []
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
    
    if len(sys.argv) > 1 and sys.argv[1] == '--init-db':
        print(f"[{Color.GREEN}INFO{Color.END}] Database checked/initialized successfully.")
        return

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
# 5. Create Minimal Templates (Full Web Submission Form - NO CHANGE)
# ============================================
print_status "5/6: Creating HTML templates (Web Submission Form - No Change)..."

# --- index.html (FULL SUBMISSION FORM) ---
cat > "$INSTALL_DIR/templates/index.html" << 'INDEXEOF'
<!DOCTYPE
