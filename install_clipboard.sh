#!/bin/bash
# Internet Clipboard Server Installer (V44 - PROGRESS BAR EDITION)
# FIXED: Added Live Progress Bar for URL Downloads to prevent incomplete files.

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
echo "📋 Internet Clipboard Server Installer (V44 - PROGRESS BAR EDITION)"
echo "=================================================="
echo "New Features: 1) Live Progress Bar for URL Downloads"
echo "              2) Real-time download status monitoring"
echo "              3) Prevent 404 errors with completion check"
echo "              4) Enhanced user experience"
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
print_status "2/7: Updating configuration and directory structure..."

mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
chmod -R 777 "$INSTALL_DIR" 

# --- Create/Update .env file ---
if [ ! -f "$INSTALL_DIR/.env" ] || ! grep -q "SECRET_KEY" "$INSTALL_DIR/.env"; then
    echo "Creating new .env file."
    cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
ENVEOF
else
    # Update/Ensure keys exist
    sed -i "/^CLIPBOARD_PORT=/c\CLIPBOARD_PORT=${CLIPBOARD_PORT}" "$INSTALL_DIR/.env"
    if ! grep -q "EXPIRY_DAYS" "$INSTALL_DIR/.env"; then
        echo "EXPIRY_DAYS=${EXPIRY_DAYS}" >> "$INSTALL_DIR/.env"
    fi
    sed -i "/^DOTENV_FULL_PATH=/c\DOTENV_FULL_PATH=${INSTALL_DIR}/.env" "$INSTALL_DIR/.env"
fi

# ============================================
# 3. Create web_service.py (V44 - PROGRESS BAR EDITION)
# ============================================
print_status "3/7: Creating web_service.py (V44 - With Progress Bar API)..."

cat > "$INSTALL_DIR/web_service.py" << 'PYEOF_WEB_SERVICE'
import os
import sqlite3
import re
import string
import random
import time
import threading
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g, jsonify
from dotenv import load_dotenv, find_dotenv
from werkzeug.utils import secure_filename
import requests 
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# --- Configuration & Init ---
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', find_dotenv(usecwd=True))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, 'clipboard.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
EXPIRY_DAYS_DEFAULT = int(os.getenv('EXPIRY_DAYS', '30')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 
    'mp3', 'mp4', 'exe', 'bin', 'iso', 'apk', 'apks', 'deb', 'msi', 
    'dmg', 'tar', 'gz', 'xz', 'bz2'
}

# --- Global Progress Tracking ---
download_progress = {}  # Stores download progress: {task_id: {"progress": 0-100, "status": "..."}}

# --- Utility Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        try:
            db = g._database = sqlite3.connect(
                DATABASE_PATH, 
                timeout=30,
                check_same_thread=False,
                isolation_level=None 
            )
            db.row_factory = sqlite3.Row 
            db.execute('PRAGMA foreign_keys=ON') 
        except sqlite3.OperationalError as e:
            logger.error(f"[FATAL] Could not connect to database at {DATABASE_PATH}: {e}")
            raise RuntimeError("Database connection failed.")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def allowed_file(filename):
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

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
    now_ts = int(time.time()) 

    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_ts,))
    expired_files = cursor.fetchall()

    for file_path_tuple in expired_files:
        file_paths = file_path_tuple['file_path'].split(',') if file_path_tuple['file_path'] else []
        for file_path in file_paths:
            full_path = os.path.join(UPLOAD_FOLDER, file_path.strip())
            if file_path and os.path.exists(full_path):
                try:
                    os.remove(full_path)
                    logger.info(f"Removed expired file: {full_path}")
                except OSError as e:
                    logger.warning(f"Error removing file {full_path}: {e}")
            
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_ts,))
    db.commit() 
    logger.info("Cleaned up expired clips")

# --- Progress API Endpoint ---
@app.route('/progress/<task_id>')
def get_progress(task_id):
    """API endpoint to get download progress"""
    progress_data = download_progress.get(task_id, {"progress": 0, "status": "waiting", "message": ""})
    return jsonify(progress_data)

# --- Download Worker Function (runs in thread) ---
def download_worker(url, key, task_id, file_paths, index, total):
    """
    Downloads a file in a separate thread with progress tracking
    """
    try:
        # Initialize progress
        download_progress[task_id] = {
            "progress": 0, 
            "status": f"downloading_{index}", 
            "message": f"Starting download {index}/{total}: {os.path.basename(url[:50])}..."
        }
        
        # Validate URL
        if not url.lower().startswith(('http://', 'https://')):
            download_progress[task_id] = {
                "progress": 0,
                "status": "error",
                "message": f"Invalid URL format: {url[:50]}..."
            }
            return False
            
        # Start download with streaming
        response = requests.get(url, allow_redirects=True, stream=True, timeout=None)
        
        if response.status_code != 200:
            download_progress[task_id] = {
                "progress": 0,
                "status": "error",
                "message": f"HTTP Error {response.status_code} for {url[:50]}..."
            }
            return False

        # Determine filename
        content_disposition = response.headers.get('Content-Disposition')
        if content_disposition:
            fname_match = re.search(r'filename="?([^"]+)"?', content_disposition)
            if fname_match:
                filename = fname_match.group(1)
            else:
                filename = os.path.basename(url.split('?', 1)[0])
        else:
            filename = os.path.basename(url.split('?', 1)[0])
            
        if not filename or filename == '.':
            filename = "downloaded_file" 
        
        # Check file extension
        if not allowed_file(filename):
            download_progress[task_id] = {
                "progress": 0,
                "status": "error",
                "message": f"File type not allowed: {filename}"
            }
            return False
        
        filename = secure_filename(filename)
        unique_filename = f"{key}_{filename}"
        full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Get total size if available
        total_size = response.headers.get('content-length')
        if total_size:
            total_size = int(total_size)
        else:
            total_size = None
        
        # Download with progress tracking
        downloaded = 0
        with open(full_path, 'wb') as f:
            if total_size:
                # Track progress for known size
                for chunk in response.iter_content(chunk_size=16384):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        progress = int((downloaded / total_size) * 100)
                        download_progress[task_id] = {
                            "progress": progress,
                            "status": f"downloading_{index}",
                            "message": f"Downloading {filename}: {progress}% ({downloaded//1024}KB/{total_size//1024}KB)"
                        }
            else:
                # Unknown size - just download
                f.write(response.content)
                download_progress[task_id] = {
                    "progress": 100,
                    "status": f"downloading_{index}",
                    "message": f"Downloaded {filename} (size unknown)"
                }
        
        file_paths.append(unique_filename)
        download_progress[task_id] = {
            "progress": 100,
            "status": "completed",
            "message": f"Successfully downloaded: {filename}"
        }
        
        logger.info(f"Downloaded file: {filename} -> {unique_filename}")
        return True
        
    except requests.exceptions.Timeout:
        download_progress[task_id] = {
            "progress": 0,
            "status": "error",
            "message": f"Download timed out: {url[:50]}..."
        }
        return False
    except requests.exceptions.RequestException as e:
        download_progress[task_id] = {
            "progress": 0,
            "status": "error",
            "message": f"Download failed: {str(e)[:100]}"
        }
        return False
    except Exception as e:
        download_progress[task_id] = {
            "progress": 0,
            "status": "error",
            "message": f"Unexpected error: {str(e)[:100]}"
        }
        return False

# --- Database Initialization ---
def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
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
    logger.info("Database initialized")

# --- Main Routes ---
@app.route('/', methods=['GET', 'POST'])
def index():
    # Reload environment variables
    load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    current_expiry_days = int(os.getenv('EXPIRY_DAYS', '30'))

    context = {
        'EXPIRY_DAYS': current_expiry_days,
        'old_content': '',
        'old_custom_key': '',
        'old_url_files': '',
        'task_id': ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    }

    if request.method == 'POST':
        content = request.form.get('content', '') 
        custom_key = request.form.get('custom_key', '').strip()
        url_files_input = request.form.get('url_files', '')
        task_id = request.form.get('task_id', '')
        
        uploaded_files = request.files.getlist('files')
        url_list = [u.strip() for u in url_files_input.split('\n') if u.strip()] 

        context['old_content'] = content
        context['old_custom_key'] = custom_key
        context['old_url_files'] = url_files_input
        
        content_stripped = content.strip()
        has_content = content_stripped or any(f.filename for f in uploaded_files) or url_list
        
        if not has_content:
            flash('Please provide text content, upload files, or paste file URLs.', 'error')
            return render_template('index.html', **context) 

        key = custom_key or generate_key()
        
        # Validation
        if custom_key and not re.match(KEY_REGEX, custom_key):
            flash('Invalid custom key format. Use 3-64 letters, numbers, hyphens or underscores.', 'error')
            return render_template('index.html', **context) 
            
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
            if cursor.fetchone():
                flash(f'Key "{key}" already in use.', 'error')
                return render_template('index.html', **context) 
        except RuntimeError:
            flash("Database connection error.", 'error')
            return render_template('index.html', **context) 
            
        # File Handling
        file_paths = []
        has_upload_error = False
        threads = []
        
        # 1. Local File Upload
        for file in uploaded_files:
            if file and file.filename:
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{key}_{filename}"
                    try:
                        file.save(os.path.join(UPLOAD_FOLDER, unique_filename))
                        file_paths.append(unique_filename)
                        logger.info(f"Uploaded file: {filename}")
                    except Exception as e:
                        flash(f'Error saving {filename}: {e}', 'error')
                        has_upload_error = True
                        break
                else:
                    flash(f'File type not allowed: {file.filename}', 'error')
                    has_upload_error = True
                    break
        
        # 2. Remote URL Download with Progress Tracking
        if not has_upload_error and url_list:
            # Initialize progress tracking for this task
            download_progress[task_id] = {
                "progress": 0,
                "status": "starting",
                "message": f"Preparing to download {len(url_list)} file(s)..."
            }
            
            # Start download threads
            for i, url in enumerate(url_list):
                thread = threading.Thread(
                    target=download_worker,
                    args=(url, key, f"{task_id}_{i}", file_paths, i+1, len(url_list))
                )
                threads.append(thread)
                thread.start()
            
            # Wait for all downloads to complete
            for thread in threads:
                thread.join()
            
            # Check if any downloads failed
            for i in range(len(url_list)):
                progress_key = f"{task_id}_{i}"
                if progress_key in download_progress:
                    if download_progress[progress_key]["status"] == "error":
                        has_upload_error = True
                        error_msg = download_progress[progress_key]["message"]
                        flash(f'Download failed: {error_msg}', 'error')
                        break
            
        if has_upload_error:
            # Clean up any partially downloaded files
            for fp in file_paths:
                try: 
                    os.remove(os.path.join(UPLOAD_FOLDER, fp))
                except: 
                    pass
            # Clean up progress data
            for i in range(len(url_list)):
                progress_key = f"{task_id}_{i}"
                if progress_key in download_progress:
                    del download_progress[progress_key]
            return render_template('index.html', **context) 
            
        # Database Insertion
        created_at_ts = int(time.time())
        expires_at_ts = int(created_at_ts + (current_expiry_days * 24 * 3600))
        file_path_string = ','.join(file_paths)
        
        try:
            cursor.execute(
                "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (key, content_stripped, file_path_string, created_at_ts, expires_at_ts) 
            )
            db.commit() 
            logger.info(f"Created new clip: {key}")
            
            # Clean up progress data after successful creation
            for i in range(len(url_list)):
                progress_key = f"{task_id}_{i}"
                if progress_key in download_progress:
                    del download_progress[progress_key]
            
            return redirect(url_for('view_clip', key=key))
            
        except sqlite3.OperationalError as e:
            logger.error(f"SQLITE ERROR: {e}")
            flash("Database error during clip creation.", 'error')
            for fp in file_paths:
                try: 
                    os.remove(os.path.join(UPLOAD_FOLDER, fp))
                except: 
                    pass
            return render_template('index.html', **context)

    # GET request
    try:
        cleanup_expired_clips()
    except RuntimeError:
        flash("Database connection error during cleanup.", 'error')
    
    return render_template('index.html', **context)

@app.route('/<key>')
def view_clip(key):
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT content, file_path, expires_at FROM clips WHERE key = ?", (key,))
        clip = cursor.fetchone()
    except RuntimeError:
        return render_template('error.html', message="Database error. Check the database using the CLI."), 500
    except sqlite3.OperationalError as e:
        logger.error(f"SQLITE ERROR: {e}")
        return render_template('error.html', message="Database uninitialized or corrupted. Run the CLI tool."), 500

    if not clip:
        return render_template('clipboard.html', clip=None, key=key)

    content = clip['content']
    file_path_string = clip['file_path']
    expires_at_ts = clip['expires_at']
    
    now_ts = int(time.time())
    
    if expires_at_ts < now_ts:
        cleanup_expired_clips()
        return render_template('clipboard.html', clip=None, key=key, expired=True)

    # Calculate time left
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
            try:
                original_filename = p.split('_', 2)[-1] 
            except IndexError:
                original_filename = p
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

@app.route('/download/<filename>')
def download_file(filename):
    """
    Fixed download route - serves files from uploads folder
    """
    logger.info(f"Download request for: {filename}")
    
    # Security check
    if not filename or '..' in filename or '/' in filename:
        flash('Invalid file request.', 'error')
        return redirect(url_for('index'))
    
    # Extract key from filename
    parts = filename.split('_', 1)
    if len(parts) < 2:
        flash('Invalid file format.', 'error')
        return redirect(url_for('index'))
    
    key = parts[0]
    
    # Check if file exists in database
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        flash('File not found or link expired.', 'error')
        return redirect(url_for('index'))

    file_paths_string, expires_at_ts = clip
    
    # Check if filename is in the associated files
    file_list = [p.strip() for p in file_paths_string.split(',')] if file_paths_string else []
    if filename not in file_list:
        flash('File not found in the associated clip.', 'error')
        return redirect(url_for('view_clip', key=key))

    if expires_at_ts < int(time.time()):
        cleanup_expired_clips()
        flash('File link has expired.', 'error')
        return redirect(url_for('index'))
    
    # Extract original filename for download name
    original_filename = filename.split('_', 2)[-1] if '_' in filename else filename
    
    try:
        logger.info(f"Serving file: {filename} as {original_filename}")
        return send_from_directory(
            UPLOAD_FOLDER, 
            filename, 
            as_attachment=True, 
            download_name=original_filename
        )
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        flash('File not found on server.', 'error')
        return redirect(url_for('index'))

# Initialize database on first run
if not os.path.exists(DATABASE_PATH):
    init_db()

if __name__ == '__main__':
    pass
PYEOF_WEB_SERVICE

# ============================================
# 4. Create clipboard_cli.py (CLI Tool - Updated for V44)
# ============================================
print_status "4/7: Creating clipboard_cli.py (Updated for V44)..."
cat > "$INSTALL_DIR/clipboard_cli.py" << 'PYEOF_CLI_TOOL'
import os
import sqlite3
import random
import string
import re
import sys
import time
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
    now_ts = int(time.time()) 

    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_ts,))
    expired_files = cursor.fetchall()

    for file_path_tuple in expired_files:
        file_paths = file_path_tuple['file_path'].split(',') if file_path_tuple['file_path'] else []
        for file_path in file_paths:
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', file_path.strip())
            if file_path and os.path.exists(full_path):
                try:
                    os.remove(full_path)
                except OSError as e:
                    print(f"[{Color.YELLOW}WARNING{Color.END}] Error removing file {full_path}: {e}")
            
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_ts,))
    conn.commit()
    conn.close()

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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, key, content, file_path, created_at, expires_at FROM clips ORDER BY id DESC")
    clips = cursor.fetchall()
    conn.close()

    if not clips:
        print(f"\n{Color.YELLOW}No active clips found.{Color.END}")
        return

    print(f"\n{Color.BLUE}{Color.BOLD}--- Active Clips ({len(clips)}) ---{Color.END}")
    
    print(f"{Color.CYAN}{'ID':<4} {'Key':<10} {'Link (IP:Port/Key)':<30} {'Content Preview':<24} {'Files':<6} {'Remaining':<10} {'Expires (UTC)':<20}{Color.END}")
    print("-" * 104)
    
    for clip in clips:
        content_preview = (clip['content'][:21] + '...') if clip['content'] and len(clip['content']) > 21 else (clip['content'] or "No content")
        file_count = len([p for p in clip['file_path'].split(',') if p.strip()]) if clip['file_path'] else 0
        
        expires_at_dt = datetime.fromtimestamp(clip['expires_at'], tz=timezone.utc)
        expiry_date_utc = expires_at_dt.strftime('%Y-%m-%d %H:%M:%S')

        remaining_time = format_remaining_time(clip['expires_at'])
        full_link = f"{SERVER_IP}:{CLIPBOARD_PORT}/{clip['key']}"
        
        print(f"{clip['id']:<4} {Color.BOLD}{clip['key']:<10}{Color.END} {Color.UNDERLINE}{full_link:<30}{Color.END} {content_preview:<24} {file_count:<6} {remaining_time:<10} {expiry_date_utc:<20}")
    print("-" * 104)


def delete_clip():
    list_clips()
    if not input(f"\n{Color.YELLOW}Do you want to continue with deletion? (yes/no): {Color.END}").lower().strip().startswith('y'):
        print("Deletion cancelled.")
        return

    clip_id_or_key = input("Enter the ID or Key of the clip to delete: ").strip()

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
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', file_path)
            if os.path.exists(full_path):
                os.remove(full_path)
                print(f" - File deleted: {os.path.basename(file_path)}")
                
    cursor.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
    conn.commit()
    conn.close()
    
    print(f"\n{Color.GREEN}✅ Clip ID {clip_id} (Key: {clip_key}) successfully deleted.{Color.END}")

def get_clip_by_id_or_key(identifier):
    conn = get_db_connection()
    cursor = conn.cursor()
    if identifier.isdigit():
        cursor.execute("SELECT id, key, content, expires_at FROM clips WHERE id = ?", (int(identifier),))
    else:
        cursor.execute("SELECT id, key, content, expires_at FROM clips WHERE key = ?", (identifier,))
    clip = cursor.fetchone()
    conn.close()
    return clip

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
            current_expiry_dt = datetime.fromtimestamp(clip['expires_at'], tz=timezone.utc)
            new_expiry_dt = current_expiry_dt + timedelta(days=adjustment_days)
            
        else:
            new_days = int(new_days_str)
            if new_days <= 0:
                print(f"{Color.RED}Error: Total days must be a positive integer.{Color.END}")
                return
            
            new_expiry_dt = datetime.fromtimestamp(time.time(), tz=timezone.utc) + timedelta(days=new_days)

        new_expires_at_ts = int(new_expiry_dt.timestamp())

        conn = get_db_connection()
        cursor = conn.cursor()
        
        if new_expires_at_ts < int(time.time()):
             print(f"{Color.RED}Error: New expiry date is in the past. Use a larger number or '+' adjustment.{Color.END}")
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

    clip_id_or_key = input("\nEnter the ID or Key of the clip to edit (for Key/Content): ").strip()

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

def main_menu():
    global EXPIRY_DAYS, BASE_URL, SERVER_IP
    
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
        print(f"{Color.PURPLE}{Color.BOLD}   Clipboard CLI Management V44 (Base URL: {BASE_URL}){Color.END}")
        print(f"{Color.PURPLE}{Color.BOLD}========================================{Color.END}")
        print(f"1. {Color.GREEN}Create New Clip{Color.END} (Text Only)")
        print(f"2. {Color.BLUE}List All Clips{Color.END}")
        print(f"3. {Color.CYAN}Edit Clip{Color.END} (Key, Content or Expiry)")
        print(f"4. {Color.RED}Delete Clip{Color.END}")
        print(f"5. {Color.YELLOW}Change Default Expiry Days{Color.END} (Current: {EXPIRY_DAYS} Days)") 
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
        elif choice == '0':
            print(f"\n{Color.BOLD}Exiting CLI Management. Goodbye!{Color.END}")
            break
        else:
            print(f"{Color.RED}Invalid choice. Please try again.{Color.END}")

if __name__ == '__main__':
    main_menu()
PYEOF_CLI_TOOL

# ============================================
# 5. Create HTML Templates (V44 - With Progress Bar)
# ============================================
print_status "5/7: Creating HTML templates with Progress Bar..."

# --- index.html (V44 - With Progress Bar) ---
cat > "$INSTALL_DIR/templates/index.html" << 'INDEXEOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internet Clipboard Server V44 - Create</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #333; 
            margin: 0; 
            padding: 20px;
            min-height: 100vh;
        }
        .container { 
            max-width: 800px; 
            margin: 20px auto; 
            background-color: #fff; 
            padding: 40px; 
            border-radius: 16px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
            transition: all 0.3s ease;
        }
        h1 { 
            color: #2c3e50; 
            text-align: center; 
            margin-bottom: 30px; 
            font-size: 2.2em;
            background: linear-gradient(90deg, #3498db, #2ecc71);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .flash { 
            padding: 15px; 
            border-radius: 10px; 
            margin-bottom: 20px; 
            font-weight: 600;
            border-left: 5px solid;
            animation: slideIn 0.5s ease;
        }
        @keyframes slideIn {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        .error { 
            background-color: #ffebee; 
            color: #c62828; 
            border-left-color: #c62828;
        }
        .success { 
            background-color: #e8f5e9; 
            color: #2e7d32; 
            border-left-color: #2e7d32;
        }
        form div { 
            margin-bottom: 25px; 
            position: relative;
        }
        label { 
            display: block; 
            margin-bottom: 8px; 
            font-weight: 600;
            color: #2c3e50;
            font-size: 1.05em;
        }
        textarea, input[type="text"], input[type="file"] { 
            width: 100%; 
            padding: 14px; 
            box-sizing: border-box; 
            border: 2px solid #ddd; 
            border-radius: 10px;
            font-size: 1em;
            font-family: inherit;
            transition: all 0.3s ease;
        }
        textarea:focus, input[type="text"]:focus, input[type="file"]:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
        }
        textarea { 
            height: 150px; 
            resize: vertical; 
            line-height: 1.5;
        }
        input[type="submit"] {
            background: linear-gradient(90deg, #3498db, #2ecc71);
            color: white;
            padding: 16px 30px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1.2em;
            font-weight: 600;
            transition: all 0.3s ease;
            display: block;
            width: 100%;
            position: relative;
            overflow: hidden;
        }
        input[type="submit"]:hover:not(:disabled) { 
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(50, 50, 93, 0.1), 0 3px 6px rgba(0, 0, 0, 0.08);
        }
        input[type="submit"]:active:not(:disabled) { 
            transform: translateY(1px);
        }
        input[type="submit"]:disabled {
            opacity: 0.7;
            cursor: not-allowed;
        }
        .progress-container {
            display: none;
            margin-top: 30px;
            background: #f8f9fa;
            border-radius: 12px;
            padding: 25px;
            border: 2px solid #e9ecef;
            animation: fadeIn 0.5s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .progress-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .progress-title {
            font-weight: 600;
            color: #2c3e50;
            font-size: 1.1em;
        }
        .progress-percentage {
            font-weight: 700;
            color: #3498db;
            font-size: 1.2em;
        }
        .progress-bar {
            width: 100%;
            height: 24px;
            background: #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }
        .progress-fill {
            width: 0%;
            height: 100%;
            background: linear-gradient(90deg, #2ecc71, #3498db);
            border-radius: 12px;
            transition: width 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
            position: relative;
            overflow: hidden;
        }
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, 
                rgba(255,255,255,0) 0%, 
                rgba(255,255,255,0.3) 50%, 
                rgba(255,255,255,0) 100%);
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        .progress-status {
            margin-top: 10px;
            font-size: 0.95em;
            color: #666;
            text-align: center;
            min-height: 20px;
        }
        .progress-details {
            margin-top: 15px;
            font-size: 0.9em;
            color: #7f8c8d;
            background: #f8f9fa;
            padding: 12px;
            border-radius: 8px;
            border-left: 3px solid #3498db;
        }
        .cli-note { 
            margin-top: 40px; 
            padding: 20px; 
            background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%);
            border: 2px solid #bbdefb; 
            border-radius: 12px; 
            color: #1565c0; 
            font-weight: 600; 
            font-size: 0.95em;
            text-align: center;
        }
        .features {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 25px;
            justify-content: center;
        }
        .feature-item {
            background: #f8f9fa;
            padding: 12px 20px;
            border-radius: 25px;
            font-size: 0.9em;
            color: #2c3e50;
            border: 1px solid #dee2e6;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .feature-item::before {
            content: '✓';
            color: #2ecc71;
            font-weight: bold;
        }
        .task-id {
            font-size: 0.85em;
            color: #7f8c8d;
            text-align: center;
            margin-top: 10px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 Internet Clipboard Server V44</h1>
        
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
        
        <form id="uploadForm" method="POST" enctype="multipart/form-data">
            <input type="hidden" id="task_id" name="task_id" value="{{ task_id }}">
            
            <div>
                <label for="content">📝 Text Content (Optional):</label>
                <textarea id="content" name="content" placeholder="Paste your text here...">{{ old_content }}</textarea>
            </div>
            
            <div>
                <label for="files">📁 Local File Upload (Optional):</label>
                <input type="file" id="files" name="files" multiple>
            </div>
            
            <div>
                <label for="url_files">🔗 File Upload via URL Link (Optional - One link per line):</label>
                <textarea id="url_files" name="url_files" placeholder="Paste file URLs here (one per line)...

Examples:
https://example.com/file.zip
https://download.com/document.pdf">{{ old_url_files }}</textarea>
            </div>

            <div>
                <label for="custom_key">🔑 Custom Link Key (Optional, e.g., 'my-secret-key'):</label>
                <input type="text" id="custom_key" name="custom_key" placeholder="Leave blank for a random key" value="{{ old_custom_key }}">
            </div>
            
            <input type="submit" id="submitBtn" value="🚀 Create Clip (Expires in {{ EXPIRY_DAYS }} days)">
        </form>
        
        <div class="progress-container" id="progressContainer">
            <div class="progress-header">
                <div class="progress-title">📥 Download Progress</div>
                <div class="progress-percentage" id="progressPercentage">0%</div>
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
            <div class="progress-status" id="progressStatus">Waiting for download to start...</div>
            <div class="progress-details" id="progressDetails"></div>
        </div>
        
        <div class="task-id">
            Task ID: <strong>{{ task_id }}</strong>
        </div>
        
        <div class="features">
            <div class="feature-item">Live Progress Bar</div>
            <div class="feature-item">Multiple Files Support</div>
            <div class="feature-item">URL Downloads</div>
            <div class="feature-item">Custom Keys</div>
            <div class="feature-item">30-Day Expiry</div>
        </div>
        
        <div class="cli-note">
            ⚙️ Management panel is only accessible via the Command Line Interface (CLI) on the server: 
            <code>sudo /opt/clipboard_server/clipboard_cli.sh</code>
        </div>
    </div>
    
    <script>
        const form = document.getElementById('uploadForm');
        const submitBtn = document.getElementById('submitBtn');
        const progressContainer = document.getElementById('progressContainer');
        const progressFill = document.getElementById('progressFill');
        const progressPercentage = document.getElementById('progressPercentage');
        const progressStatus = document.getElementById('progressStatus');
        const progressDetails = document.getElementById('progressDetails');
        const urlTextarea = document.getElementById('url_files');
        const taskId = document.getElementById('task_id').value;
        
        let progressInterval = null;
        let isDownloading = false;
        
        // Update task ID in form for each new page load
        document.getElementById('task_id').value = taskId;
        
        form.addEventListener('submit', async function(e) {
            const urlContent = urlTextarea.value.trim();
            
            // Only show progress bar if there are URLs to download
            if (urlContent) {
                e.preventDefault();
                
                // Disable submit button
                submitBtn.disabled = true;
                submitBtn.value = "⏳ Processing...";
                
                // Show progress container with animation
                progressContainer.style.display = 'block';
                progressContainer.style.animation = 'fadeIn 0.5s ease';
                
                // Start progress monitoring
                startProgressMonitoring();
                
                // Submit form after a short delay to show progress UI
                setTimeout(() => {
                    form.submit();
                }, 100);
            }
            // If no URLs, just submit normally
        });
        
        function startProgressMonitoring() {
            if (progressInterval) {
                clearInterval(progressInterval);
            }
            
            let totalUrls = 0;
            const urlContent = urlTextarea.value.trim();
            if (urlContent) {
                totalUrls = urlContent.split('\n').filter(line => line.trim()).length;
            }
            
            progressInterval = setInterval(async () => {
                try {
                    // Check progress for each URL
                    let totalProgress = 0;
                    let totalCompleted = 0;
                    let allDone = true;
                    let anyError = false;
                    let errorMessage = '';
                    
                    for (let i = 0; i < totalUrls; i++) {
                        const progressKey = `${taskId}_${i}`;
                        const response = await fetch(`/progress/${progressKey}`);
                        if (response.ok) {
                            const data = await response.json();
                            
                            totalProgress += data.progress || 0;
                            
                            if (data.status === 'completed' || data.status === 'done') {
                                totalCompleted++;
                            } else if (data.status === 'error') {
                                anyError = true;
                                errorMessage = data.message || 'Unknown error';
                            }
                            
                            if (data.status !== 'completed' && data.status !== 'done' && data.status !== 'error') {
                                allDone = false;
                            }
                            
                            // Update status message for the first active download
                            if (i === 0 && data.message) {
                                progressStatus.textContent = data.message;
                                progressDetails.textContent = `Downloading file ${i+1}/${totalUrls}`;
                            }
                        }
                    }
                    
                    // Calculate average progress
                    const avgProgress = totalUrls > 0 ? Math.floor(totalProgress / totalUrls) : 0;
                    
                    // Update UI
                    progressFill.style.width = avgProgress + '%';
                    progressPercentage.textContent = avgProgress + '%';
                    
                    if (totalUrls === 0) {
                        progressStatus.textContent = 'No URLs to download';
                        progressDetails.textContent = 'Uploading local files only...';
                    } else if (anyError) {
                        progressStatus.textContent = 'Error: ' + errorMessage;
                        progressStatus.style.color = '#c62828';
                        stopProgressMonitoring();
                        resetForm();
                    } else if (allDone && totalUrls > 0) {
                        progressStatus.textContent = `✓ All ${totalCompleted} file(s) downloaded successfully!`;
                        progressStatus.style.color = '#2e7d32';
                        progressDetails.textContent = 'Finalizing and creating your clip...';
                        
                        // Wait a moment then redirect automatically
                        setTimeout(() => {
                            stopProgressMonitoring();
                            // The form was already submitted, so we just wait for redirect
                        }, 1500);
                    } else if (totalUrls > 0) {
                        progressStatus.textContent = `Downloading: ${totalCompleted}/${totalUrls} files completed`;
                        progressDetails.textContent = `Overall progress: ${avgProgress}%`;
                    }
                    
                } catch (error) {
                    console.error('Progress check failed:', error);
                    progressStatus.textContent = 'Progress check failed, but download continues...';
                }
            }, 1000); // Check every second
        }
        
        function stopProgressMonitoring() {
            if (progressInterval) {
                clearInterval(progressInterval);
                progressInterval = null;
            }
        }
        
        function resetForm() {
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.value = "🚀 Create Clip (Expires in {{ EXPIRY_DAYS }} days)";
                progressContainer.style.display = 'none';
            }, 3000);
        }
        
        // Clean up on page unload
        window.addEventListener('beforeunload', () => {
            stopProgressMonitoring();
        });
    </script>
</body>
</html>
INDEXEOF

# --- clipboard.html (Updated for V44) ---
cat > "$INSTALL_DIR/templates/clipboard.html" << 'CLIPBOARDEOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clip: {{ key }}</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #333; 
            margin: 0; 
            padding: 20px;
            min-height: 100vh;
        }
        .container { 
            max-width: 900px; 
            margin: 0 auto; 
            background-color: #fff; 
            padding: 40px; 
            border-radius: 16px; 
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
            animation: fadeIn 0.6s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        h1 { 
            color: #2c3e50; 
            text-align: center; 
            margin-bottom: 25px; 
            font-size: 2em;
            background: linear-gradient(90deg, #3498db, #2ecc71);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        pre { 
            background: #f8f9fa; 
            padding: 25px; 
            border-radius: 12px; 
            white-space: pre-wrap; 
            word-wrap: break-word; 
            overflow: auto; 
            max-height: 500px; 
            margin-bottom: 30px; 
            border: 2px solid #e9ecef; 
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 1.05em;
            line-height: 1.6;
        }
        .content-section { 
            margin-bottom: 40px; 
            position: relative;
        }
        .content-section h2 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.4em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .files-section { 
            margin-bottom: 40px; 
            border-top: 2px solid #e9ecef; 
            padding-top: 30px; 
        }
        .files-section h2 { 
            color: #2c3e50; 
            font-size: 1.4em; 
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .file-list {
            display: grid;
            gap: 15px;
        }
        .file-item { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px; 
            border-radius: 12px; 
            margin-bottom: 10px; 
            border-left: 5px solid #3498db;
            transition: all 0.3s ease;
            border: 1px solid #dee2e6;
        }
        .file-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            border-left-color: #2ecc71;
        }
        .file-info {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .file-name {
            font-weight: 600;
            color: #2c3e50;
            font-size: 1.1em;
            word-break: break-word;
        }
        .file-size {
            font-size: 0.9em;
            color: #6c757d;
        }
        .file-item a { 
            background: linear-gradient(90deg, #3498db, #2ecc71);
            color: white;
            padding: 12px 25px;
            border-radius: 8px;
            text-decoration: none; 
            font-weight: 600;
            transition: all 0.3s ease;
            white-space: nowrap;
            margin-left: 15px;
        }
        .file-item a:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
            text-decoration: none;
        }
        .expiry-info { 
            text-align: center; 
            color: #fff; 
            font-weight: 600; 
            margin-bottom: 30px;
            padding: 20px;
            border-radius: 12px;
            background: linear-gradient(135deg, #3498db, #2ecc71);
            box-shadow: 0 5px 15px rgba(52, 152, 219, 0.2);
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
        }
        .expiry-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            min-width: 80px;
        }
        .expiry-value {
            font-size: 1.8em;
            font-weight: 700;
        }
        .expiry-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .back-link { 
            display: block; 
            text-align: center; 
            margin-top: 40px; 
        }
        .back-link a { 
            background: linear-gradient(90deg, #6c757d, #495057);
            color: white; 
            padding: 15px 30px;
            border-radius: 10px;
            text-decoration: none; 
            font-weight: 600;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }
        .back-link a:hover { 
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(108, 117, 125, 0.3);
            text-decoration: none;
        }
        .flash { 
            padding: 20px; 
            border-radius: 12px; 
            margin-bottom: 25px; 
            font-weight: 600;
            border-left: 5px solid;
            animation: slideIn 0.5s ease;
        }
        .error { 
            background-color: #ffebee; 
            color: #c62828; 
            border-left-color: #c62828;
        }
        .success { 
            background-color: #e8f5e9; 
            color: #2e7d32; 
            border-left-color: #2e7d32;
        }
        .copy-button { 
            background: linear-gradient(90deg, #ff9800, #ff5722);
            color: white; 
            padding: 12px 25px; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            font-size: 1em; 
            font-weight: 600;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 20px;
        }
        .copy-button:hover { 
            background: linear-gradient(90deg, #ff5722, #ff9800);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(255, 87, 34, 0.3);
        }
        .clip-info {
            text-align: center;
            margin-bottom: 25px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
            border: 1px solid #e9ecef;
        }
        .clip-key {
            font-family: monospace;
            background: #2c3e50;
            color: white;
            padding: 8px 15px;
            border-radius: 6px;
            font-size: 1.2em;
            display: inline-block;
            margin: 10px 0;
        }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #6c757d;
        }
        .empty-state i {
            font-size: 3em;
            margin-bottom: 20px;
            opacity: 0.5;
        }
        .empty-state h2 {
            color: #6c757d;
            margin-bottom: 10px;
        }
        .version-badge {
            position: absolute;
            top: 20px;
            right: 20px;
            background: #2ecc71;
            color: white;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
        }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="version-badge">V44</div>
        
        <div class="flash error">
            {% for category, message in get_flashed_messages(with_categories=true) %}
                {% if category == 'error' %}
                    {{ message }}
                {% endif %}
            {% endfor %}
        </div>
        
        {% if clip and (content or files_info) %}
            <h1><i class="fas fa-clipboard"></i> Clipboard Content</h1>
            
            <div class="clip-info">
                <div>Access Key:</div>
                <div class="clip-key">{{ key }}</div>
                <div style="margin-top: 10px; font-size: 0.9em; color: #6c757d;">
                    Share this link: <strong>http://{{ request.host }}/{{ key }}</strong>
                </div>
            </div>
            
            <div class="expiry-info">
                <div class="expiry-item">
                    <div class="expiry-value">{{ expiry_info_days }}</div>
                    <div class="expiry-label">Days</div>
                </div>
                <div class="expiry-item">
                    <div class="expiry-value">{{ expiry_info_hours }}</div>
                    <div class="expiry-label">Hours</div>
                </div>
                <div class="expiry-item">
                    <div class="expiry-value">{{ expiry_info_minutes }}</div>
                    <div class="expiry-label">Minutes</div>
                </div>
                <div style="flex-basis: 100%; text-align: center; margin-top: 10px;">
                    <i class="fas fa-clock"></i> Time remaining until expiration
                </div>
            </div>

            <div class="content-section">
                <h2><i class="fas fa-file-alt"></i> Text Content</h2>
                {% if content %}
                    <button class="copy-button" onclick="copyContent()">
                        <i class="fas fa-copy"></i> Copy Text
                    </button>
                    <pre id="text-content">{{ content }}</pre>
                {% else %}
                    <div class="empty-state">
                        <i class="fas fa-file-alt"></i>
                        <h2>No Text Content</h2>
                        <p>This clip contains only attached files.</p>
                    </div>
                {% endif %}
            </div>
        
        {% else %}
             <h1><i class="fas fa-exclamation-triangle"></i> Clip Not Found</h1>
             <div class="expiry-info" style="background: linear-gradient(135deg, #dc3545, #c82333);">
                 {% if expired %}
                     <i class="fas fa-hourglass-end"></i> This clipboard link has expired and its content has been deleted.
                 {% else %}
                     <i class="fas fa-search"></i> Clip with key <strong>{{ key }}</strong> does not exist.
                 {% endif %}
             </div>
        {% endif %}
        
        {% if files_info %}
            <div class="files-section">
                <h2><i class="fas fa-paperclip"></i> Attached Files ({{ files_info|length }})</h2>
                <div class="file-list">
                    {% for file in files_info %}
                        <div class="file-item">
                            <div class="file-info">
                                <div class="file-name">
                                    <i class="fas fa-file"></i> {{ file.name }}
                                </div>
                                <div class="file-size">
                                    <i class="fas fa-hdd"></i> File ready for download
                                </div>
                            </div>
                            <a href="{{ url_for('download_file', filename=file.path) }}">
                                <i class="fas fa-download"></i> Download
                            </a>
                        </div>
                    {% endfor %}
                </div>
            </div>
        {% endif %}

        <div class="back-link">
            <a href="/">
                <i class="fas fa-arrow-left"></i> Create New Clip
            </a>
        </div>
    </div>

    <script>
        function copyContent() {
            const contentElement = document.getElementById('text-content');
            if (!contentElement) {
                alert('Text element not found!');
                return;
            }
            
            const button = event.target.closest('.copy-button');
            const originalHTML = button.innerHTML;
            
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(contentElement.innerText).then(() => {
                    button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                    button.style.background = 'linear-gradient(90deg, #2ecc71, #27ae60)';
                    setTimeout(() => {
                        button.innerHTML = originalHTML;
                        button.style.background = 'linear-gradient(90deg, #ff9800, #ff5722)';
                    }, 2000);
                }).catch(err => {
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
                
                const button = event.target.closest('.copy-button');
                const originalHTML = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                button.style.background = 'linear-gradient(90deg, #2ecc71, #27ae60)';
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.style.background = 'linear-gradient(90deg, #ff9800, #ff5722)';
                }, 2000);
            } catch (err) {
                alert('Copy Error! Please manually select and copy the text.');
            }
        }
    </script>
</body>
</html>
CLIPBOARDEOF

# --- error.html (Updated for V44) ---
cat > "$INSTALL_DIR/templates/error.html" << 'ERROREOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error - Clipboard Server V44</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #333; 
            margin: 0; 
            padding: 50px; 
            text-align: center;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container { 
            max-width: 700px; 
            background-color: #fff; 
            padding: 50px; 
            border-radius: 20px; 
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
            animation: fadeIn 0.8s ease;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.95); }
            to { opacity: 1; transform: scale(1); }
        }
        h1 { 
            color: #dc3545; 
            margin-bottom: 25px; 
            font-size: 2.5em;
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 15px;
        }
        p { 
            font-size: 1.2em; 
            color: #555; 
            line-height: 1.6;
            margin-bottom: 25px;
        }
        .error-message { 
            margin: 30px 0; 
            padding: 25px; 
            background: linear-gradient(135deg, #ffebee 0%, #ffcdd2 100%);
            border: 2px solid #ef5350; 
            border-radius: 15px; 
            color: #c62828; 
            font-weight: 600;
            font-size: 1.1em;
            text-align: left;
            border-left: 6px solid #c62828;
        }
        .code-block {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Consolas', 'Monaco', monospace;
            text-align: left;
            margin: 25px 0;
            font-size: 1.1em;
            overflow-x: auto;
        }
        .action-buttons {
            display: flex;
            gap: 20px;
            justify-content: center;
            margin-top: 35px;
            flex-wrap: wrap;
        }
        .action-button {
            padding: 15px 30px;
            border-radius: 10px;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }
        .back-button {
            background: linear-gradient(90deg, #3498db, #2980b9);
            color: white;
        }
        .log-button {
            background: linear-gradient(90deg, #6c757d, #495057);
            color: white;
        }
        .action-button:hover {
            transform: translateY(-3px);
            box-shadow: 0 7px 14px rgba(0, 0, 0, 0.15);
            text-decoration: none;
        }
        .version-info {
            margin-top: 30px;
            color: #7f8c8d;
            font-size: 0.9em;
        }
        .support-info {
            margin-top: 25px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 12px;
            border: 1px solid #e9ecef;
            text-align: left;
        }
        .support-info h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <h1><i class="fas fa-exclamation-circle"></i> Internal Error</h1>
        
        <div class="error-message">
            <p><strong>Error Details:</strong></p>
            <p>{{ message }}</p>
        </div>
        
        <p>This is likely a server configuration issue or a temporary problem.</p>
        
        <div class="support-info">
            <h3><i class="fas fa-life-ring"></i> Troubleshooting Steps:</h3>
            <ol>
                <li><strong>Check server logs:</strong> Run the command below to see detailed error information.</li>
                <li><strong>Verify database:</strong> Ensure the CLI tool has been initialized at least once.</li>
                <li><strong>Check service status:</strong> Make sure the clipboard service is running.</li>
                <li><strong>Restart service:</strong> Sometimes a simple restart fixes the issue.</li>
            </ol>
        </div>
        
        <div class="code-block">
            # Check service status<br>
            sudo systemctl status clipboard.service<br><br>
            
            # View server logs<br>
            sudo journalctl -u clipboard.service -f<br><br>
            
            # Restart service<br>
            sudo systemctl restart clipboard.service<br><br>
            
            # Run CLI to check database<br>
            sudo /opt/clipboard_server/clipboard_cli.sh
        </div>
        
        <div class="action-buttons">
            <a href="/" class="action-button back-button">
                <i class="fas fa-home"></i> Back to Home
            </a>
            <a href="#" onclick="alert('Run: sudo journalctl -u clipboard.service -f')" class="action-button log-button">
                <i class="fas fa-terminal"></i> View Logs Command
            </a>
        </div>
        
        <div class="version-info">
            <i class="fas fa-code"></i> Clipboard Server V44 - Progress Bar Edition
        </div>
    </div>
</body>
</html>
ERROREOF

# ============================================
# 6. Create Systemd Service (V44 - Enhanced)
# ============================================
print_status "6/7: Creating Systemd service (V44 - Enhanced)..."
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Web Server V44 (Progress Bar Edition)
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
# Enhanced configuration for V44 with progress tracking
ExecStart=${GUNICORN_VENV_PATH} --workers 4 --threads 4 --worker-class gthread --timeout 0 --bind 0.0.0.0:${CLIPBOARD_PORT} web_service:app
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env
Restart=always
RestartSec=3
StartLimitInterval=60s
StartLimitBurst=3

# Security enhancements
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}/uploads ${INSTALL_DIR}/clipboard.db

[Install]
WantedBy=multi-user.target
SERVICEEOF

# ============================================
# 7. Final Steps
# ============================================
print_status "7/7: Initializing database and starting service..."

# Create CLI wrapper script
cat > "$INSTALL_DIR/clipboard_cli.sh" << CLISHEOF
#!/bin/bash
source ${INSTALL_DIR}/venv/bin/activate
exec ${PYTHON_VENV_PATH} ${INSTALL_DIR}/clipboard_cli.py "\$@"
CLISHEOF
chmod +x "$INSTALL_DIR/clipboard_cli.sh"

# Initialize database
sqlite3 "$DATABASE_PATH" "CREATE TABLE IF NOT EXISTS clips (
    id INTEGER PRIMARY KEY,
    key TEXT UNIQUE NOT NULL,
    content TEXT,
    file_path TEXT, 
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);" 2>/dev/null || true

systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

# Get server IP
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="YOUR_SERVER_IP"
fi

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V44)"
echo "================================================"
echo "✅ Web service is active on port ${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "🌐 Web Address: http://${SERVER_IP}:${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "💻 CLI Management:"
echo -e "   ${BLUE}sudo ${INSTALL_DIR}/clipboard_cli.sh${NC}"
echo "------------------------------------------------"
echo "📁 Upload Directory: ${INSTALL_DIR}/uploads"
echo "🗄️  Database: ${INSTALL_DIR}/clipboard.db"
echo "------------------------------------------------"
echo "🚀 V44 ENHANCEMENTS:"
echo "   • Live Progress Bar for URL downloads"
echo "   • Real-time download status monitoring"
echo "   • Threaded download manager"
echo "   • Enhanced UI with animations"
echo "   • Improved error handling"
echo "------------------------------------------------"
echo "🔧 Service Management:"
echo "   Status:  sudo systemctl status clipboard.service"
echo "   Logs:    sudo journalctl -u clipboard.service -f"
echo "   Restart: sudo systemctl restart clipboard.service"
echo "   Stop:    sudo systemctl stop clipboard.service"
echo "================================================"
echo ""
echo "✅ V44 is ready with Live Progress Tracking!"
echo "   Users can now see real-time download progress."
echo ""
echo "⚠️  First-time setup complete."
echo "   You can now access the web interface at:"
echo -e "   ${GREEN}http://${SERVER_IP}:${CLIPBOARD_PORT}${NC}"
echo ""
