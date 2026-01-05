#!/bin/bash
# Internet Clipboard Server Installer (CLI Management + Full Web Submission)
# V42 - Enhanced Stability: Added better error handling, increased workers, and timeout fixes.

set -e

# --- Configuration (Keep these consistent) ---
INSTALL_DIR="/opt/clipboard_server"
CLIPBOARD_PORT="3214" 
EXPIRY_DAYS="30" # Default value
DATABASE_PATH="${INSTALL_DIR}/clipboard.db"
# Generate a secure secret key for Flask
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
    print_error "❌ Please run the script with root access: sudo bash install_clipboard.sh"
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server Installer (V42 - Enhanced Stability)"
echo "=================================================="

# ============================================
# 1. System Setup & Venv
# ============================================
print_status "1/7: Preparing system, virtual environment, and cleaning old DB..."

# Stop service if running 
systemctl stop clipboard.service 2>/dev/null || true

apt update -y
apt install -y python3 python3-pip python3-venv curl wget sqlite3

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" 

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate || true

PYTHON_VENV_PATH="$INSTALL_DIR/venv/bin/python3"
GUNICORN_VENV_PATH="$INSTALL_DIR/venv/bin/gunicorn"

# Ensure dependencies are installed (requests added for URL download)
cat > requirements.txt << 'REQEOF'
Flask==2.3.3
python-dotenv==1.0.0
gunicorn==21.2.0
requests==2.31.0
REQEOF
pip install -r requirements.txt || true
deactivate

# ============================================
# 2. Update .env and Directories
# ============================================
print_status "2/7: Updating configuration and directory structure..."

mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
# Set ownership to root but allow others to write to uploads (if flask used another user)
chmod -R 777 "$INSTALL_DIR" 

# --- Create/Update .env file ---
if [ ! -f "$INSTALL_DIR/.env" ] || ! grep -q "SECRET_KEY" "$INSTALL_DIR/.env"; then
    echo "Creating new .env file."
    cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
FLASK_ENV=production
GUNICORN_WORKERS=2
ENVEOF
else
    # Update/Ensure keys exist
    sed -i "/^CLIPBOARD_PORT=/c\CLIPBOARD_PORT=${CLIPBOARD_PORT}" "$INSTALL_DIR/.env"
    if ! grep -q "EXPIRY_DAYS" "$INSTALL_DIR/.env"; then
        echo "EXPIRY_DAYS=${EXPIRY_DAYS}" >> "$INSTALL_DIR/.env"
    fi
    sed -i "/^DOTENV_FULL_PATH=/c\DOTENV_FULL_PATH=${INSTALL_DIR}/.env" "$INSTALL_DIR/.env"
    if ! grep -q "FLASK_ENV" "$INSTALL_DIR/.env"; then
        echo "FLASK_ENV=production" >> "$INSTALL_DIR/.env"
    fi
    if ! grep -q "GUNICORN_WORKERS" "$INSTALL_DIR/.env"; then
        echo "GUNICORN_WORKERS=2" >> "$INSTALL_DIR/.env"
    fi
fi


# ============================================
# 3. Create web_service.py (Enhanced Stability Version)
# ============================================
print_status "3/7: Creating web_service.py (Enhanced Stability)..."
cat > "$INSTALL_DIR/web_service.py" << 'PYEOF_WEB_SERVICE'
import os
import sqlite3
import re
import string
import random
import time
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv, find_dotenv
from werkzeug.utils import secure_filename
import requests 

# --- Configuration & Init ---
# Reload environment variables for Flask every time, especially EXPIRY_DAYS
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', find_dotenv(usecwd=True))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db') 
UPLOAD_FOLDER = 'uploads'
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
EXPIRY_DAYS_DEFAULT = int(os.getenv('EXPIRY_DAYS', '30')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
# Allow all file types - no restrictions
ALLOWED_EXTENSIONS = set()

# --- Utility Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        try:
            db = g._database = sqlite3.connect(
                DATABASE_PATH, 
                timeout=10, 
                check_same_thread=False,
                isolation_level=None 
            )
            db.row_factory = sqlite3.Row 
            db.execute('PRAGMA foreign_keys=ON') 
        except sqlite3.OperationalError as e:
            print(f"[FATAL] Could not connect to database at {DATABASE_PATH}: {e}")
            # Create database if doesn't exist
            try:
                os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
                db = g._database = sqlite3.connect(
                    DATABASE_PATH, 
                    timeout=10, 
                    check_same_thread=False,
                    isolation_level=None 
                )
                db.row_factory = sqlite3.Row 
                db.execute('PRAGMA foreign_keys=ON') 
                # Initialize database tables
                cursor = db.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS clips (
                        id INTEGER PRIMARY KEY,
                        key TEXT UNIQUE NOT NULL,
                        content TEXT,
                        file_path TEXT, 
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL
                    )
                """)
                db.commit()
            except Exception as e2:
                print(f"[FATAL] Could not create database: {e2}")
                raise RuntimeError("Database connection failed.")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    # Allow all file types - no restrictions
    return '.' in filename  # Only check if there's an extension

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
    try:
        db = get_db()
        cursor = db.cursor()
        now_ts = int(time.time()) 

        # Delete associated files
        cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_ts,))
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
                
        # Delete database entries
        cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_ts,))
        db.commit()
    except Exception as e:
        print(f"[ERROR] Failed to cleanup expired clips: {e}")

def download_and_save_file(url, key, file_paths):
    """
    Downloads a file from a URL, saves it, and updates file_paths list.
    Returns: (bool success, str message)
    """
    try:
        # Basic URL validation
        if not url.lower().startswith(('http://', 'https://')):
            return False, "URL must start with http:// or https://."
            
        # Increased timeout to 5000 seconds for large files
        response = requests.get(url, allow_redirects=True, stream=True, timeout=5000)
        
        if response.status_code != 200:
            return False, f"HTTP Error {response.status_code} when accessing URL."

        # Determine filename from URL or Content-Disposition
        content_disposition = response.headers.get('Content-Disposition')
        if content_disposition:
            # Try to extract filename from Content-Disposition header
            fname_match = re.search(r'filename="?([^"]+)"?', content_disposition)
            if fname_match:
                filename = fname_match.group(1)
            else:
                 filename = os.path.basename(url.split('?', 1)[0])
        else:
            filename = os.path.basename(url.split('?', 1)[0])
            
        if not filename or filename == '.':
             filename = "downloaded_file" 
        
        # No file type restrictions - allow all files
        filename = secure_filename(filename)
        unique_filename = f"{key}_{filename}"
        full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Ensure upload directory exists
        upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), UPLOAD_FOLDER)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file to disk
        local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), full_path)
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        file_paths.append(full_path)
        return True, filename

    except requests.exceptions.Timeout:
        return False, "Download failed: Connection timed out (5000 seconds limit)."
    except requests.exceptions.RequestException as e:
        return False, f"Download failed: {e}"
    except Exception as e:
        return False, f"An unexpected error occurred during download: {e}"


# --- Error Handlers ---
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', message="Page not found."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Internal server error. Please try again later."), 500

@app.errorhandler(503)
def service_unavailable(error):
    return render_template('error.html', message="Service temporarily unavailable. Please try again in a moment."), 503

# --- Main Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    
    # V39: Reload environment variables to get current EXPIRY_DAYS_DEFAULT
    load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    current_expiry_days = int(os.getenv('EXPIRY_DAYS', '30'))

    # V36: Initialize default context for GET and error POSTs
    context = {
        'EXPIRY_DAYS': current_expiry_days, # Use current value
        'old_content': '',
        'old_custom_key': '',
        'old_url_files': '' 
    }

    # 1. Handle form submission (POST)
    if request.method == 'POST':
        content = request.form.get('content', '') 
        custom_key = request.form.get('custom_key', '').strip()
        url_files_input = request.form.get('url_files', '') 
        
        uploaded_files = request.files.getlist('files')
        url_list = [u.strip() for u in url_files_input.split('\n') if u.strip()] 

        # V36/V37: Update context for re-rendering if error occurs
        context['old_content'] = content
        context['old_custom_key'] = custom_key
        context['old_url_files'] = url_files_input
        
        content_stripped = content.strip()
        has_content = content_stripped or any(f.filename for f in uploaded_files) or url_list
        
        if not has_content:
            flash('Please provide text content, upload files, or paste file URLs.', 'error')
            return render_template('index.html', **context) 

        key = custom_key or generate_key()
        
        # Validation and checks
        KEY_REGEX_STR = r'^[a-zA-Z0-9_-]{3,64}$'
        if custom_key and not re.match(KEY_REGEX_STR, custom_key):
            flash('Invalid custom key format. Key must be 3 to 64 letters, numbers, hyphens (-) or underscores (_).', 'error')
            return render_template('index.html', **context) 
            
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
            if cursor.fetchone():
                flash(f'The key "{key}" is already in use. Please choose another key.', 'error')
                return render_template('index.html', **context) 
        except Exception as e:
            print(f"[ERROR] Database connection error: {e}")
            flash("Database connection error. Please try again.", 'error')
            return render_template('index.html', **context) 
            
        # File Handling (Local & Remote)
        file_paths = []
        has_upload_error = False

        # 1. Local File Upload
        for file in uploaded_files:
            if file and file.filename:
                # Allow all file types - no restrictions
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{key}_{filename}"
                    full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
                    try:
                        upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), UPLOAD_FOLDER)
                        os.makedirs(upload_dir, exist_ok=True)
                        file.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), full_path))
                        file_paths.append(full_path)
                    except Exception as e:
                        flash(f'Error saving local file {filename}: {e}', 'error')
                        has_upload_error = True
                        break
                else:
                    flash(f'Local file type not allowed: {file.filename}', 'error')
                    has_upload_error = True
                    break
        
        # 2. Remote URL Download 
        if not has_upload_error:
            for url in url_list:
                success, msg = download_and_save_file(url, key, file_paths)
                if not success:
                    flash(f'Remote download failed for {url}: {msg}', 'error')
                    has_upload_error = True
                    break
            
        # If any error occurred during file handling (local or remote), clean up and return
        if has_upload_error:
            for fp in file_paths:
                try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                except: pass
            return render_template('index.html', **context) 
            
        # Database Insertion
        created_at_ts = int(time.time())
        # Use the current default expiry days 
        expires_at_ts = int(created_at_ts + (current_expiry_days * 24 * 3600))
        file_path_string = ','.join(file_paths)
        
        try:
            cursor.execute(
                "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (key, content_stripped, file_path_string, created_at_ts, expires_at_ts) 
            )
            db.commit() 
            
            # Redirect to the newly created clip
            return redirect(url_for('view_clip', key=key))
            
        except sqlite3.OperationalError as e:
             print(f"SQLITE ERROR: {e}")
             flash("Database error during clip creation. Check server logs.", 'error')
             for fp in file_paths: # Clean up uploaded files if DB fails
                try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                except: pass
             return render_template('index.html', **context)


    # 2. Handle GET request (Display form)
    try:
        cleanup_expired_clips()
    except Exception as e:
         print(f"[ERROR] Cleanup failed: {e}")
         flash("Database connection error during cleanup. Please run CLI tool.", 'error')
    
    return render_template('index.html', **context)


@app.route('/<key>')
def view_clip(key):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT content, file_path, expires_at FROM clips WHERE key = ?", (key,))
        clip = cursor.fetchone()
    except Exception as e:
        print(f"[ERROR] Database error: {e}")
        return render_template('error.html', message="Database error. Check the database using the CLI."), 500

    if not clip:
        return render_template('clipboard.html', clip=None, key=key)

    content = clip['content']
    file_path_string = clip['file_path']
    expires_at_ts = clip['expires_at']
    
    now_ts = int(time.time())
    
    if expires_at_ts < now_ts:
        cleanup_expired_clips()
        return render_template('clipboard.html', clip=None, key=key, expired=True)

    # Calculate time left for display
    expires_at_dt = datetime.fromtimestamp(expires_at_ts, tz=timezone.utc)
    now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)
    
    time_left = expires_at_dt - now_dt
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
                           server_port=CLIPBOARD_PORT,
                           clip=clip)


@app.route('/download/<path:file_path>')
def download_file(file_path):
    if not file_path.startswith(UPLOAD_FOLDER + '/'):
         flash('Invalid download request.', 'error')
         return redirect(url_for('index'))
         
    filename_part = os.path.basename(file_path)
    try:
        key = filename_part.split('_', 1)[0]
    except IndexError:
        flash('Invalid file path format.', 'error')
        return redirect(url_for('index'))

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
        clip = cursor.fetchone()
    except Exception as e:
        print(f"[ERROR] Database error: {e}")
        flash('Database error. Please try again.', 'error')
        return redirect(url_for('index'))

    if not clip:
        flash('File not found or link expired.', 'error')
        return redirect(url_for('index'))

    file_paths_string, expires_at_ts = clip
    
    if file_path not in [p.strip() for p in file_paths_string.split(',')]:
        flash('File not found in the associated clip.', 'error')
        return redirect(url_for('view_clip', key=key))


    if expires_at_ts < int(time.time()):
        cleanup_expired_clips()
        flash('File not found or link expired.', 'error')
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
# 4. Create clipboard_cli.py (The CLI Management Tool - Enhanced)
# ============================================
print_status "4/7: Creating clipboard_cli.py (CLI Tool - Enhanced)..."
cat > "$INSTALL_DIR/clipboard_cli.py" << 'PYEOF_CLI_TOOL'
import os
import sqlite3
import random
import string
import re
import sys
import time
import argparse
import socket 
import shutil
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv

# --- Configuration & Init ---
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'

EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
CLIPBOARD_PORT = os.getenv('CLIPBOARD_PORT', '3214')
BASE_URL = None 

def get_server_ip():
    """Tries to get the public or local IP of the server."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "YOUR_IP"

# Global setup variables
SERVER_IP = get_server_ip()
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

# --- Utility Functions ---
def update_env_file(key, value):
    """Update a specific key-value pair in the .env file."""
    try:
        if not os.path.exists(DOTENV_PATH):
            with open(DOTENV_PATH, 'w') as f:
                f.write(f"{key}={value}\n")
            return True

        temp_path = DOTENV_PATH + '.tmp'
        
        updated = False
        with open(DOTENV_PATH, 'r') as old, open(temp_path, 'w') as new:
            for line in old:
                if line.startswith(f"{key}="):
                    new.write(f"{key}={value}\n")
                    updated = True
                else:
                    new.write(line)
            
            if not updated:
                new.write(f"{key}={value}\n")

        shutil.move(temp_path, DOTENV_PATH)
        return True
    except Exception as e:
        print(f"{Color.RED}Error updating .env file: {e}{Color.END}")
        return False

def format_remaining_time(expiry_ts):
    """Calculates and formats the remaining time until expiry (e.g., 4d 10h)."""
    now_ts = int(time.time())
    time_left_sec = expiry_ts - now_ts
    
    if time_left_sec <= 0:
        return "Expired"
        
    time_left = timedelta(seconds=time_left_sec)
    
    days = time_left.days
    hours = time_left.seconds // 3600
    minutes = (time_left.seconds % 3600) // 60
    
    if days > 0:
        return f"{days}d {hours}h"
    elif hours > 0:
        return f"{hours}h {minutes}m"
    else:
        return f"{minutes}m"

# --- Database Management ---
def get_db_connection():
    try:
        conn = sqlite3.connect(DATABASE_PATH, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError as e:
        print(f"{Color.RED}Database connection error: {e}{Color.END}")
        print(f"{Color.YELLOW}Creating new database...{Color.END}")
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        conn = sqlite3.connect(DATABASE_PATH, isolation_level=None)
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
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    print(f"{Color.GREEN}Database initialized successfully.{Color.END}")

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
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        now_ts = int(time.time()) 

        cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_ts,))
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
                
        cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_ts,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[{Color.YELLOW}WARNING{Color.END}] Cleanup failed: {e}")

# --- Main CLI Functions ---

def change_expiry_days():
    global EXPIRY_DAYS
    print(f"\n{Color.CYAN}{Color.BOLD}--- Change Default Expiry Duration ---{Color.END}")
    print(f"Current default expiry is: {Color.BOLD}{EXPIRY_DAYS} days{Color.END}")
    
    new_days_str = input("Enter new default expiry in days (e.g., 5, 30, 90): ").strip()
    
    try:
        new_days = int(new_days_str)
        if new_days <= 0 or new_days > 3650:
             print(f"{Color.RED}Error: Expiry must be a positive integer, typically between 1 and 3650 days.{Color.END}")
             return
             
    except ValueError:
        print(f"{Color.RED}Error: Invalid input. Please enter a valid integer for the number of days.{Color.END}")
        return

    if update_env_file('EXPIRY_DAYS', new_days_str):
        EXPIRY_DAYS = new_days
        print(f"\n{Color.GREEN}✅ Success! Default expiry updated to {Color.BOLD}{new_days} days.{Color.END}")
        print(f"{Color.YELLOW}⚠️ NOTE: Changes apply to NEW clips only. You may need to restart the web service (sudo systemctl restart clipboard.service) for the change to take full effect on the web.{Color.END}")
    else:
        print(f"{Color.RED}Failed to update expiry duration.{Color.END}")


def create_new_clip():
    global EXPIRY_DAYS
    print(f"\n{Color.BLUE}{Color.BOLD}--- Create New Clip (Text Only) ---{Color.END}")
    print(f"Clip will expire in {EXPIRY_DAYS} days.")
    content = input("Enter text content (leave blank for placeholder): ").strip()
    custom_key = input("Enter custom link key (optional, leave blank for random): ").strip()

    key = None
    if custom_key:
        if not re.match(KEY_REGEX, custom_key):
            print(f"{Color.RED}Error: Invalid custom key.{Color.END}")
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
        content = f"Empty clip created by CLI. Key: {key}"

    created_at_ts = int(time.time())
    expires_at_ts = int(created_at_ts + (EXPIRY_DAYS * 24 * 3600))
    expires_at_dt = datetime.fromtimestamp(expires_at_ts, tz=timezone.utc)


    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key, content, "", created_at_ts, expires_at_ts)
        )
        conn.commit()
        conn.close()
        
        print(f"\n{Color.GREEN}✅ Success! Clip created:{Color.END}")
        print(f"   {Color.BOLD}Key:{Color.END} {key}")
        print(f"   {Color.BOLD}Link:{Color.END} {BASE_URL}/{key}")
        print(f"   {Color.BOLD}Expires:{Color.END} {expires_at_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} (in {EXPIRY_DAYS} days)")
        
    except sqlite3.Error as e:
        print(f"{Color.RED}Database Error: {e}{Color.END}")
    except Exception as e:
        print(f"{Color.RED}An unexpected error occurred: {e}{Color.END}")


def list_clips():
    cleanup_expired_clips()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, key, content, file_path, created_at, expires_at FROM clips ORDER BY id DESC")
        clips = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"{Color.RED}Error accessing database: {e}{Color.END}")
        return

    if not clips:
        print(f"\n{Color.YELLOW}No active clips found.{Color.END}")
        return

    print(f"\n{Color.BLUE}{Color.BOLD}--- Active Clips ({len(clips)}) ---{Color.END}")
    
    # V40/V41 Widths: ID:4, Key:10, Link:30, Content:24, Files:6, Remaining:10, Expires:20 => Total: 104
    print(f"{Color.CYAN}{'ID':<4} {'Key':<10} {'Link (IP:Port/Key)':<30} {'Content Preview':<24} {'Files':<6} {'Remaining':<10} {'Expires (UTC)':<20}{Color.END}")
    print("-" * 104)
    
    for clip in clips:
        content_preview = (clip['content'][:21] + '...') if clip['content'] and len(clip['content']) > 21 else (clip['content'] or "No content")
        file_count = len([p for p in clip['file_path'].split(',') if p.strip()]) if clip['file_path'] else 0
        
        expires_at_dt = datetime.fromtimestamp(clip['expires_at'], tz=timezone.utc)
        expiry_date_utc = expires_at_dt.strftime('%Y-%m-%d %H:%M:%S')

        # Calculate Remaining Time
        remaining_time = format_remaining_time(clip['expires_at'])

        # Prepare and display the full URL
        full_link = f"{SERVER_IP}:{CLIPBOARD_PORT}/{clip['key']}"
        
        print(f"{clip['id']:<4} {Color.BOLD}{clip['key']:<10}{Color.END} {Color.UNDERLINE}{full_link:<30}{Color.END} {content_preview:<24} {file_count:<6} {remaining_time:<10} {expiry_date_utc:<20}")
    print("-" * 104)


def delete_clip():
    list_clips()
    if not input(f"\n{Color.YELLOW}Do you want to continue with deletion? (yes/no): {Color.END}").lower().strip().startswith('y'):
        print("Deletion cancelled.")
        return

    clip_id_or_key = input("Enter the ID or Key of the clip to delete: ").strip()

    try:
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
                    print(f" - File deleted: {os.path.basename(file_path)}")
                    
        cursor.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
        conn.commit()
        conn.close()
        
        print(f"\n{Color.GREEN}✅ Clip ID {clip_id} (Key: {clip_key}) successfully deleted.{Color.END}")
    except Exception as e:
        print(f"{Color.RED}Error during deletion: {e}{Color.END}")

def get_clip_by_id_or_key(identifier):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if identifier.isdigit():
            cursor.execute("SELECT id, key, content, expires_at FROM clips WHERE id = ?", (int(identifier),))
        else:
            cursor.execute("SELECT id, key, content, expires_at FROM clips WHERE key = ?", (identifier,))
        clip = cursor.fetchone()
        conn.close()
        return clip
    except Exception as e:
        print(f"{Color.RED}Database error: {e}{Color.END}")
        return None

def edit_clip_expiry():
    list_clips()
    clip_id_or_key = input("\nEnter the ID or Key of the clip to change expiry for: ").strip()
    
    clip = get_clip_by_id_or_key(clip_id_or_key)
    
    if not clip:
        print(f"{Color.RED}Error: Clip with ID/Key '{clip_id_or_key}' not found.{Color.END}")
        return

    expires_at_dt = datetime.fromtimestamp(clip['expires_at'], tz=timezone.utc)
    remaining_time = format_remaining_time(clip['expires_at'])
    
    print(f"\n{Color.CYAN}--- Change Expiry for Clip ID {clip['id']} (Key: {clip['key']}) ---{Color.END}")
    print(f"Current Expiry: {expires_at_dt.strftime('%Y-%m-%d %H:%M:%S UTC')} (Remaining: {remaining_time})")
    
    new_days_str = input("Enter NEW total duration in days (e.g., 60) OR '+' or '-' days to adjust (e.g., +10, -5): ").strip()

    try:
        new_days = 0
        if new_days_str.startswith('+') or new_days_str.startswith('-'):
            adjustment_days = int(new_days_str)
            
            # Calculate new expiry date based on adjustment from current expiry
            current_expiry_dt = datetime.fromtimestamp(clip['expires_at'], tz=timezone.utc)
            new_expiry_dt = current_expiry_dt + timedelta(days=adjustment_days)
            
        else:
            new_days = int(new_days_str)
            if new_days <= 0:
                print(f"{Color.RED}Error: Total days must be a positive integer.{Color.END}")
                return
            
            # Calculate new expiry date based on total new days from *current time*
            new_expiry_dt = datetime.fromtimestamp(time.time(), tz=timezone.utc) + timedelta(days=new_days)

        new_expires_at_ts = int(new_expiry_dt.timestamp())

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if the new expiry time is in the past
        if new_expires_at_ts < int(time.time()):
             print(f"{Color.RED}Error: New expiry date ({new_expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}) is in the past. Use a larger number or '+' adjustment.{Color.END}")
             conn.close()
             return

        cursor.execute("UPDATE clips SET expires_at = ? WHERE id = ?", (new_expires_at_ts, clip['id']))
        conn.commit()
        conn.close()
        
        new_remaining_time = format_remaining_time(new_expires_at_ts)
        print(f"\n{Color.GREEN}✅ Success! Expiry updated.{Color.END}")
        print(f"   {Color.BOLD}New Expiry:{Color.END} {new_expiry_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"   {Color.BOLD}Remaining:{Color.END} {new_remaining_time}")
        
    except ValueError:
        print(f"{Color.RED}Error: Invalid input. Please enter a valid integer or use '+'/' adjustment (e.g., +5, -2, 60).{Color.END}")
    except Exception as e:
        print(f"{Color.RED}An unexpected error occurred: {e}{Color.END}")


def edit_clip():
    list_clips()
    
    print(f"\n{Color.CYAN}--- Select Clip Editing Option ---{Color.END}")
    print(f"1. Edit Key")
    print(f"2. Edit Content")
    print(f"3. {Color.YELLOW}Edit Expiry Duration{Color.END}")
    print(f"0. Cancel")
    
    choice = input("Enter your choice (1/2/3/0): ").strip()

    if choice == '3':
        edit_clip_expiry()
        return

    # Rest of the old logic for Key/Content editing
    clip_id_or_key = input("\nEnter the ID or Key of the clip to edit (for Key/Content): ").strip()

    try:
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

        if choice == '1':
            new_key = input(f"Enter new key (Current: {clip_key}): ").strip()
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
            print(f"\n{Color.GREEN}✅ Key successfully updated to {new_key}.{Color.END}")
            
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
            print(f"\n{Color.GREEN}✅ Content successfully updated.{Color.END}")
        
        elif choice == '0':
            print("Editing cancelled.")
        else:
             print(f"{Color.RED}Invalid choice.{Color.END}")

        conn.close()
    except Exception as e:
        print(f"{Color.RED}Error during edit operation: {e}{Color.END}")

def check_service_status():
    print(f"\n{Color.CYAN}{Color.BOLD}--- Service Status Check ---{Color.END}")
    try:
        import subprocess
        result = subprocess.run(['systemctl', 'is-active', 'clipboard.service'], 
                               capture_output=True, text=True)
        status = result.stdout.strip()
        
        if status == 'active':
            print(f"{Color.GREEN}✅ Clipboard service is ACTIVE{Color.END}")
            
            # Check if port is listening
            result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
            if f':{CLIPBOARD_PORT} ' in result.stdout:
                print(f"{Color.GREEN}✅ Port {CLIPBOARD_PORT} is LISTENING{Color.END}")
            else:
                print(f"{Color.RED}❌ Port {CLIPBOARD_PORT} is NOT LISTENING{Color.END}")
                
            # Show recent logs
            print(f"\n{Color.YELLOW}Recent logs:{Color.END}")
            subprocess.run(['journalctl', '-u', 'clipboard.service', '-n', '10', '--no-pager'])
        else:
            print(f"{Color.RED}❌ Clipboard service is {status.upper()}{Color.END}")
            
    except Exception as e:
        print(f"{Color.RED}Error checking service status: {e}{Color.END}")

def main_menu():
    global EXPIRY_DAYS, BASE_URL, SERVER_IP
    
    # Reload configuration before running the menu
    load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30'))
    CLIPBOARD_PORT = os.getenv('CLIPBOARD_PORT', '3214')
    SERVER_IP = get_server_ip()
    BASE_URL = f"http://{SERVER_IP}:{CLIPBOARD_PORT}"
    
    init_db()
    cleanup_expired_clips()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--init-db':
        print(f"[{Color.GREEN}INFO{Color.END}] Database successfully checked/initialized.")
        return

    while True:
        print(f"\n{Color.PURPLE}{Color.BOLD}========================================{Color.END}")
        print(f"{Color.PURPLE}{Color.BOLD}   Clipboard CLI Management (Base URL: {BASE_URL}){Color.END}")
        print(f"{Color.PURPLE}{Color.BOLD}========================================{Color.END}")
        print(f"1. {Color.GREEN}Create New Clip{Color.END} (Text Only)")
        print(f"2. {Color.BLUE}List All Clips{Color.END}")
        print(f"3. {Color.CYAN}Edit Clip{Color.END} (Key, Content or Expiry)")
        print(f"4. {Color.RED}Delete Clip{Color.END}")
        print(f"5. {Color.YELLOW}Change Default Expiry Days{Color.END} (Current: {EXPIRY_DAYS} Days)")
        print(f"6. {Color.BLUE}Check Service Status{Color.END}")
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
        elif choice == '5': 
            change_expiry_days()
        elif choice == '6':
            check_service_status()
        elif choice == '0':
            print(f"\n{Color.BOLD}Exiting CLI Management. Goodbye!{Color.END}")
            break
        else:
            print(f"{Color.RED}Invalid choice. Please try again.{Color.END}")

if __name__ == '__main__':
    main_menu()

PYEOF_CLI_TOOL

# ============================================
# 5. Create Minimal Templates (Enhanced)
# ============================================
print_status "5/7: Creating HTML templates..."

# --- index.html ---
cat > "$INSTALL_DIR/templates/index.html" << 'INDEXEOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internet Clipboard Server - Create</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 700px; margin: 20px auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #007bff; text-align: center; margin-bottom: 25px; }
        .flash { padding: 15px; border-radius: 8px; margin-bottom: 15px; font-weight: bold; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        form div { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        textarea, input[type="text"], input[type="file"] { 
            width: 100%; 
            padding: 10px; 
            box-sizing: border-box; 
            border: 1px solid #ccc; 
            border-radius: 6px;
        }
        textarea { height: 120px; resize: vertical; }
        input[type="submit"] {
            background-color: #5cb85c;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 1.1em;
            transition: background-color 0.3s;
        }
        input[type="submit"]:hover { background-color: #4cae4c; }
        .cli-note { margin-top: 30px; padding: 15px; background-color: #f0f8ff; border: 1px solid #007bff; border-radius: 8px; color: #0056b3; font-weight: bold; font-size: 0.9em;}
        .info-note { margin-top: 20px; padding: 10px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 6px; color: #856404; font-size: 0.9em;}
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 Internet Clipboard Server (Create Clip)</h1>
        
        <div class="flash error">
            {% for message in get_flashed_messages(category_filter=['error']) %}
                {{ message }}
            {% endfor %}
        </div>
        
        <div class="flash success">
            {% for message in get_flashed_messages(category_filter=['success']) %}
                {{ message }}
            {% endfor %}
        </div>
        
        <form method="POST" enctype="multipart/form-data">
            <div>
                <label for="content">Text Content (Optional):</label>
                <textarea id="content" name="content" placeholder="Paste your text here...">{{ old_content }}</textarea>
            </div>
            
            <div>
                <label for="files">Local File Upload (Optional):</label>
                <input type="file" id="files" name="files" multiple>
            </div>
            
            <div>
                <label for="url_files">File Upload via URL Link (Optional - One link per line):</label>
                <textarea id="url_files" name="url_files" placeholder="Enter file links...">{{ old_url_files }}</textarea>
            </div>

            <div>
                <label for="custom_key">Custom Link Key (Optional, e.g., 'my-secret-key'):</label>
                <input type="text" id="custom_key" name="custom_key" placeholder="Leave blank for a random key" value="{{ old_custom_key }}">
            </div>
            
            <input type="submit" value="Create Clip (Expires in {{ EXPIRY_DAYS }} days)">
        </form>
        
        <div class="info-note">
            📝 <strong>Note:</strong> All file types are allowed. Large files (up to 5000 seconds download time) are supported.
        </div>
        
        <div class="cli-note">
            ⚠️ Management panel is only accessible via the Command Line Interface (CLI) on the server: 
            <code>sudo /opt/clipboard_server/clipboard_cli.sh</code>
        </div>
    </div>
</body>
</html>
INDEXEOF

# --- clipboard.html ---
cat > "$INSTALL_DIR/templates/clipboard.html" << 'CLIPBOARDEOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clip: {{ key }}</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #007bff; text-align: center; margin-bottom: 20px; }
        pre { background-color: #eee; padding: 15px; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; overflow: auto; max-height: 400px; margin-bottom: 20px; border: 1px solid #ccc; position: relative; }
        .content-section { margin-bottom: 30px; }
        .files-section { margin-bottom: 30px; border-top: 1px solid #eee; padding-top: 20px; }
        .files-section h2 { color: #333; font-size: 1.2em; margin-bottom: 15px; }
        .file-item { display: flex; justify-content: space-between; align-items: center; background-color: #f0f8ff; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; border-right: 5px solid #007bff; }
        .file-item a { color: #007bff; text-decoration: none; font-weight: bold; }
        .file-item a:hover { text-decoration: underline; }
        .expiry-info { text-align: center; color: #d9534f; font-weight: bold; margin-bottom: 20px; }
        .back-link { display: block; text-align: center; margin-top: 30px; }
        .back-link a { color: #007bff; text-decoration: none; font-weight: bold; }
        .flash { padding: 15px; border-radius: 8px; margin-bottom: 15px; font-weight: bold; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .copy-button { background-color: #5cb85c; color: white; padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9em; float: left; margin-right: 10px; }
        .copy-button:hover { background-color: #4cae4c; }
        .clip-info { text-align: center; color: #6c757d; margin-bottom: 20px; font-size: 0.9em; }
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
        
        {% if clip and (content or files_info) %}
            <h1>Clip Content for: {{ key }}</h1>
            
            <div class="clip-info">
                Share this link: <code>http://{{ request.host }}/{{ key }}</code>
            </div>
            
            <div class="expiry-info">
                Expires in: {{ expiry_info_days }} days, {{ expiry_info_hours }} hours, and {{ expiry_info_minutes }} minutes.
            </div>

            <div class="content-section">
                <h2>Text Content</h2>
                {% if content %}
                    <button class="copy-button" onclick="copyContent()">Copy Text</button>
                    <pre id="text-content">{{ content }}</pre>
                {% else %}
                    <p> (This clip contains no text content and only has attached files) </p>
                {% endif %}
            </div>
        
        {% else %}
             <h1>Clip Not Found</h1>
             <div class="expiry-info">
                 {% if expired %}
                     This clipboard link has expired and its content has been deleted.
                 {% else %}
                     Clip with key **{{ key }}** does not exist.
                 {% endif %}
             </div>
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
            <a href="/">← Create New Clip</a>
        </div>
    </div>

    <script>
        function copyContent() {
            const contentElement = document.getElementById('text-content');
            if (!contentElement) {
                alert('Text element not found!');
                return;
            }
            
            // 1. Try modern clipboard API (async, preferred)
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(contentElement.innerText).then(() => {
                    alert('Text copied to clipboard!');
                }).catch(err => {
                    console.error('Copy failed (Modern API): ', err);
                    copyFallback(contentElement);
                });
            } else {
                copyFallback(contentElement);
            }
        }
        
        function copyFallback(element) {
            try {
                const tempTextArea = document.createElement('textarea');
                tempTextArea.value = element.innerText;
                
                tempTextArea.style.position = 'fixed';
                tempTextArea.style.top = '0';
                tempTextArea.style.left = '0';
                tempTextArea.style.opacity = '0';
                
                document.body.appendChild(tempTextArea);
                tempTextArea.select();
                tempTextArea.setSelectionRange(0, 99999);
                document.execCommand('copy');
                document.body.removeChild(tempTextArea);
                
                alert('Text copied to clipboard!');
            } catch (err) {
                console.error('Copy failed (Fallback): ', err);
                alert('Copy Error! Please manually select and copy the text.');
            }
        }
    </script>
</body>
</html>
CLIPBOARDEOF


# --- error.html ---
cat > "$INSTALL_DIR/templates/error.html" << 'ERROREOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 50px; text-align: center;}
        .container { max-width: 600px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #dc3545; margin-bottom: 20px; }
        p { font-size: 1.1em; color: #555; }
        .error-message { margin-top: 30px; padding: 15px; background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 8px; color: #721c24; font-weight: bold; }
        .troubleshoot { margin-top: 30px; padding: 15px; background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; color: #856404; text-align: left; }
        code { background-color: #f8f9fa; padding: 2px 5px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ Error Occurred</h1>
        <div class="error-message">
            <p>{{ message }}</p>
        </div>
        
        <div class="troubleshoot">
            <p><strong>Troubleshooting steps:</strong></p>
            <ol>
                <li>Check if the clipboard service is running:<br>
                    <code>sudo systemctl status clipboard.service</code></li>
                <li>View service logs:<br>
                    <code>sudo journalctl -u clipboard.service -f</code></li>
                <li>Restart the service:<br>
                    <code>sudo systemctl restart clipboard.service</code></li>
                <li>Use CLI tool to check database:<br>
                    <code>sudo /opt/clipboard_server/clipboard_cli.sh</code></li>
            </ol>
        </div>
        
        <p style="margin-top: 20px;">
            <a href="/">← Back to Home</a>
        </p>
    </div>
</body>
</html>
ERROREOF


# ============================================
# 6. Create Enhanced Systemd Service
# ============================================
print_status "6/7: Creating Systemd service for web server (Enhanced)..."

# --- clipboard.service ---
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Web Server (Full Submission, CLI Management)
After=network.target
StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=${INSTALL_DIR}
ExecStart=${GUNICORN_VENV_PATH} --workers 2 --threads 4 --bind 0.0.0.0:${CLIPBOARD_PORT} --timeout 120 --access-logfile - --error-logfile - web_service:app
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=clipboard

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}/uploads ${INSTALL_DIR}/clipboard.db

[Install]
WantedBy=multi-user.target
SERVICEEOF


# ============================================
# 7. Final Steps & Health Check
# ============================================
print_status "7/7: Initializing database, starting service, and running health check..."

# Create a simple wrapper script for CLI execution
cat > "$INSTALL_DIR/clipboard_cli.sh" << CLISHEOF
#!/bin/bash
source ${INSTALL_DIR}/venv/bin/activate
exec ${PYTHON_VENV_PATH} ${INSTALL_DIR}/clipboard_cli.py "\$@"
CLISHEOF
chmod +x "$INSTALL_DIR/clipboard_cli.sh"

# Create health check script
cat > "$INSTALL_DIR/health_check.py" << HEALTHEOF
#!/usr/bin/env python3
import requests
import sys
import time

def health_check():
    try:
        response = requests.get('http://localhost:3214/', timeout=5)
        if response.status_code == 200:
            print("✅ Health check PASSED: Service is responding")
            return True
        else:
            print(f"❌ Health check FAILED: Status code {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check FAILED: {e}")
        return False

if __name__ == '__main__':
    # Try multiple times
    for i in range(3):
        print(f"Health check attempt {i+1}/3...")
        if health_check():
            sys.exit(0)
        if i < 2:
            time.sleep(2)
    sys.exit(1)
HEALTHEOF

chmod +x "$INSTALL_DIR/health_check.py"

# Initialize DB using the new wrapper script
"$INSTALL_DIR/clipboard_cli.sh" --init-db 

# Fix permissions
chmod -R 755 "$INSTALL_DIR"
chmod 777 "$INSTALL_DIR/uploads"
chmod 666 "$INSTALL_DIR/clipboard.db" 2>/dev/null || true

systemctl daemon-reload
systemctl enable clipboard.service

# Start service with delay
print_status "Starting clipboard service..."
systemctl start clipboard.service

# Wait a moment for service to start
sleep 3

# Run health check
print_status "Running health check..."
if "$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/health_check.py"; then
    HEALTH_STATUS="✅"
else
    HEALTH_STATUS="⚠️ "
    print_warning "Health check failed, but service may still be starting..."
    sleep 5
fi

# Get current IP
CURRENT_IP=$(hostname -I | awk '{print $1}')
if [ -z "$CURRENT_IP" ]; then
    CURRENT_IP="YOUR_IP"
fi

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V42 - Enhanced Stability)"
echo "================================================"
echo "${HEALTH_STATUS} Web service is configured on port ${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "🌐 Web Address: http://${CURRENT_IP}:${CLIPBOARD_PORT}"
echo "🌐 Local Access: http://localhost:${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "💻 CLI Management:"
echo -e "   ${BLUE}sudo ${INSTALL_DIR}/clipboard_cli.sh${NC}"
echo "------------------------------------------------"
echo "📋 Features:"
echo "   • No file type restrictions"
echo "   • 5000 seconds download timeout"
echo "   • Enhanced error handling"
echo "   • Automatic database repair"
echo "------------------------------------------------"
echo "🔧 Service Commands:"
echo "   Status:  sudo systemctl status clipboard.service"
echo "   Restart: sudo systemctl restart clipboard.service"
echo "   Logs:    sudo journalctl -u clipboard.service -f"
echo "------------------------------------------------"
echo "⚠️  If you see 503 error, wait 30 seconds and refresh"
echo "================================================"

# Final check
if systemctl is-active --quiet clipboard.service; then
    print_status "Service is running successfully!"
else
    print_warning "Service may need manual start. Running: sudo systemctl start clipboard.service"
    systemctl start clipboard.service
fi
