#!/bin/bash
# Internet Clipboard Server Installer (V43 - Fixed URL Download Crash)
# حل مشکل 503 هنگام ارسال لینک

set -e

# --- Configuration ---
INSTALL_DIR="/opt/clipboard_server"
CLIPBOARD_PORT="3214" 
EXPIRY_DAYS="30"
DATABASE_PATH="${INSTALL_DIR}/clipboard.db"
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
echo "📋 Internet Clipboard Server Installer (V43 - URL Fix)"
echo "=================================================="

# ============================================
# 1. System Setup & Venv
# ============================================
print_status "1/7: Preparing system and virtual environment..."

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

# Install specific stable versions
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
print_status "2/7: Updating configuration..."

mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
chmod -R 777 "$INSTALL_DIR" 

# --- Create/Update .env file ---
cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
FLASK_ENV=production
GUNICORN_WORKERS=1
MAX_DOWNLOAD_SIZE=10737418240  # 10GB
ENVEOF

# ============================================
# 3. Create web_service.py (FIXED URL DOWNLOAD)
# ============================================
print_status "3/7: Creating web_service.py with URL download fix..."
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
import threading

# --- Configuration & Init ---
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', find_dotenv(usecwd=True))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db') 
UPLOAD_FOLDER = 'uploads'
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
EXPIRY_DAYS_DEFAULT = int(os.getenv('EXPIRY_DAYS', '30')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
MAX_DOWNLOAD_SIZE = int(os.getenv('MAX_DOWNLOAD_SIZE', 10737418240))  # 10GB default

# Allow all file types
ALLOWED_EXTENSIONS = set()

# Thread-local storage for download errors
download_errors = threading.local()

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
            print(f"[FATAL] Database error: {e}")
            # Create database if doesn't exist
            try:
                os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
                db = g._database = sqlite3.connect(DATABASE_PATH, timeout=10, check_same_thread=False, isolation_level=None)
                db.row_factory = sqlite3.Row 
                db.execute('PRAGMA foreign_keys=ON') 
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
    return '.' in filename

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
                
        cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_ts,))
        db.commit()
    except Exception as e:
        print(f"[ERROR] Cleanup failed: {e}")

def download_and_save_file(url, key):
    """
    Downloads a file from a URL.
    Returns: (bool success, str filename, str error_message)
    """
    try:
        # Basic URL validation
        if not url.lower().startswith(('http://', 'https://')):
            return False, None, "URL must start with http:// or https://."
            
        # Set headers to mimic browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        # Stream download with timeout
        response = requests.get(url, headers=headers, stream=True, timeout=30, allow_redirects=True)
        
        if response.status_code != 200:
            return False, None, f"HTTP Error {response.status_code}"

        # Get filename
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
        
        # Clean filename
        filename = secure_filename(filename)
        
        # Ensure unique filename
        base_name, ext = os.path.splitext(filename)
        if not ext:
            # Try to get extension from Content-Type
            content_type = response.headers.get('Content-Type', '')
            if 'application/zip' in content_type:
                ext = '.zip'
            elif 'application/pdf' in content_type:
                ext = '.pdf'
            elif 'image/' in content_type:
                ext = '.jpg'  # Default image extension
        
        filename = f"{base_name}{ext}"
        unique_filename = f"{key}_{filename}"
        full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Ensure upload directory exists
        upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), UPLOAD_FOLDER)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file with size limit
        local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), full_path)
        downloaded_size = 0
        
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    
                    # Check size limit
                    if downloaded_size > MAX_DOWNLOAD_SIZE:
                        os.remove(local_path)
                        return False, None, f"File too large (max {MAX_DOWNLOAD_SIZE//1073741824}GB)"
        
        return True, full_path, None

    except requests.exceptions.Timeout:
        return False, None, "Download timed out (30 seconds)"
    except requests.exceptions.RequestException as e:
        return False, None, f"Network error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error: {str(e)}"

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', message="Page not found."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', message="Internal server error. Please try again later."), 500

# --- Main Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    current_expiry_days = int(os.getenv('EXPIRY_DAYS', '30'))

    context = {
        'EXPIRY_DAYS': current_expiry_days,
        'old_content': '',
        'old_custom_key': '',
        'old_url_files': '' 
    }

    if request.method == 'POST':
        content = request.form.get('content', '') 
        custom_key = request.form.get('custom_key', '').strip()
        url_files_input = request.form.get('url_files', '') 
        
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
            print(f"[ERROR] Database error: {e}")
            flash("Database connection error. Please try again.", 'error')
            return render_template('index.html', **context) 
            
        # Handle file uploads and downloads
        file_paths = []
        
        # 1. Local files
        for file in uploaded_files:
            if file and file.filename:
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
                        flash(f'Error saving file {filename}: {e}', 'error')
                        # Cleanup uploaded files
                        for fp in file_paths:
                            try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                            except: pass
                        return render_template('index.html', **context)
                else:
                    flash(f'Invalid file: {file.filename}', 'error')
                    for fp in file_paths:
                        try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                        except: pass
                    return render_template('index.html', **context)
        
        # 2. URL downloads (SINGLE THREADED for stability)
        for url in url_list:
            success, file_path, error_msg = download_and_save_file(url, key)
            if success:
                file_paths.append(file_path)
            else:
                flash(f'Failed to download from {url[:50]}...: {error_msg}', 'error')
                # Cleanup
                for fp in file_paths:
                    try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                    except: pass
                return render_template('index.html', **context)
            
        # Save to database
        created_at_ts = int(time.time())
        expires_at_ts = int(created_at_ts + (current_expiry_days * 24 * 3600))
        file_path_string = ','.join(file_paths)
        
        try:
            cursor.execute(
                "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (key, content_stripped, file_path_string, created_at_ts, expires_at_ts) 
            )
            db.commit() 
            
            return redirect(url_for('view_clip', key=key))
            
        except Exception as e:
            print(f"[ERROR] Database save error: {e}")
            flash("Error saving clip. Please try again.", 'error')
            # Cleanup files
            for fp in file_paths:
                try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                except: pass
            return render_template('index.html', **context)

    # GET request
    try:
        cleanup_expired_clips()
    except Exception as e:
        print(f"[ERROR] Cleanup failed: {e}")
    
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
        return render_template('error.html', message="Database error."), 500

    if not clip:
        return render_template('clipboard.html', clip=None, key=key)

    content = clip['content']
    file_path_string = clip['file_path']
    expires_at_ts = clip['expires_at']
    
    now_ts = int(time.time())
    
    if expires_at_ts < now_ts:
        cleanup_expired_clips()
        return render_template('clipboard.html', clip=None, key=key, expired=True)

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
        flash('Database error.', 'error')
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
# 4. Create clipboard_cli.py
# ============================================
print_status "4/7: Creating clipboard_cli.py..."
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
from dotenv import load_dotenv

DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
CLIPBOARD_PORT = os.getenv('CLIPBOARD_PORT', '3214')

class Color:
    PURPLE = '\033[95m'; BLUE = '\033[94m'; CYAN = '\033[96m'
    GREEN = '\033[92m'; YELLOW = '\033[93m'; RED = '\033[91m'
    END = '\033[0m'; BOLD = '\033[1m'; UNDERLINE = '\033[4m'

def get_db_connection():
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except:
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
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
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    print(f"{Color.GREEN}Database initialized.{Color.END}")

def main_menu():
    load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    init_db()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--init-db':
        return

    while True:
        print(f"\n{Color.PURPLE}{Color.BOLD}Clipboard CLI Management{Color.END}")
        print(f"1. {Color.GREEN}Create New Clip{Color.END}")
        print(f"2. {Color.BLUE}List All Clips{Color.END}")
        print(f"3. {Color.CYAN}Edit Clip{Color.END}")
        print(f"4. {Color.RED}Delete Clip{Color.END}")
        print(f"5. {Color.YELLOW}Change Default Expiry{Color.END} ({EXPIRY_DAYS} Days)")
        print("0. Exit")
        
        choice = input("Enter your choice: ").strip()

        if choice == '1':
            print(f"\n{Color.BLUE}Create New Clip{Color.END}")
            content = input("Text content: ").strip()
            custom_key = input("Custom key (optional): ").strip()
            
            if not content:
                content = "Empty clip"
            
            key = custom_key or ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                          (key, content, "", int(time.time()), int(time.time()) + EXPIRY_DAYS*24*3600))
            conn.commit()
            conn.close()
            
            print(f"{Color.GREEN}Clip created: {key}{Color.END}")
            
        elif choice == '2':
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT key, content, expires_at FROM clips ORDER BY id DESC")
            clips = cursor.fetchall()
            conn.close()
            
            print(f"\n{Color.BLUE}Active Clips:{Color.END}")
            for clip in clips:
                remaining = (clip['expires_at'] - int(time.time())) // 86400
                print(f"  {clip['key']}: {clip['content'][:50]}... (Expires in {remaining} days)")
                
        elif choice == '0':
            break

if __name__ == '__main__':
    main_menu()

PYEOF_CLI_TOOL

# ============================================
# 5. Create HTML Templates
# ============================================
print_status "5/7: Creating HTML templates..."

# index.html
cat > "$INSTALL_DIR/templates/index.html" << 'INDEXEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Internet Clipboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        textarea, input[type="text"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        textarea { height: 100px; }
        .submit-btn { background: #28a745; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .submit-btn:hover { background: #218838; }
        .error { color: #dc3545; padding: 10px; background: #f8d7da; border-radius: 5px; margin-bottom: 15px; }
        .info { color: #856404; background: #fff3cd; padding: 10px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 Internet Clipboard</h1>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="error">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="info">
            <strong>Note:</strong> All file types supported. URL downloads may take time for large files.
        </div>
        
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label for="content">Text Content (Optional):</label>
                <textarea id="content" name="content" placeholder="Paste text here...">{{ old_content }}</textarea>
            </div>
            
            <div class="form-group">
                <label for="files">Upload Files (Optional):</label>
                <input type="file" id="files" name="files" multiple>
            </div>
            
            <div class="form-group">
                <label for="url_files">Download from URLs (One per line):</label>
                <textarea id="url_files" name="url_files" placeholder="https://example.com/file.zip">{{ old_url_files }}</textarea>
            </div>
            
            <div class="form-group">
                <label for="custom_key">Custom Link Key (Optional):</label>
                <input type="text" id="custom_key" name="custom_key" placeholder="my-secret-key" value="{{ old_custom_key }}">
            </div>
            
            <button type="submit" class="submit-btn">Create Clip (Expires in {{ EXPIRY_DAYS }} days)</button>
        </form>
    </div>
</body>
</html>
INDEXEOF

# clipboard.html
cat > "$INSTALL_DIR/templates/clipboard.html" << 'CLIPBOARDEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Clip: {{ key }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        .content { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; white-space: pre-wrap; }
        .files { margin: 20px 0; }
        .file-item { padding: 10px; background: #e9ecef; margin: 5px 0; border-radius: 5px; }
        .file-item a { color: #007bff; text-decoration: none; }
        .expiry { color: #dc3545; font-weight: bold; }
        .back { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #6c757d; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        {% if clip and (content or files_info) %}
            <h1>Clip: {{ key }}</h1>
            
            <div class="expiry">
                Expires in: {{ expiry_info_days }} days, {{ expiry_info_hours }} hours, {{ expiry_info_minutes }} minutes
            </div>
            
            {% if content %}
                <h3>Content:</h3>
                <div class="content">{{ content }}</div>
            {% endif %}
            
            {% if files_info %}
                <h3>Files ({{ files_info|length }}):</h3>
                <div class="files">
                    {% for file in files_info %}
                        <div class="file-item">
                            📎 {{ file.name }} 
                            <a href="{{ url_for('download_file', file_path=file.path) }}">Download</a>
                        </div>
                    {% endfor %}
                </div>
            {% endif %}
            
        {% else %}
            <h1>Clip Not Found</h1>
            <p>This clip has expired or does not exist.</p>
        {% endif %}
        
        <a href="/" class="back">← Create New Clip</a>
    </div>
</body>
</html>
CLIPBOARDEOF

# error.html
cat > "$INSTALL_DIR/templates/error.html" << 'ERROREOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; text-align: center; }
        .container { max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #dc3545; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 5px; }
        .back { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Error</h1>
        <div class="error">{{ message }}</div>
        <p>Please try again or contact the administrator.</p>
        <a href="/" class="back">← Back to Home</a>
    </div>
</body>
</html>
ERROREOF

# ============================================
# 6. Create Systemd Service
# ============================================
print_status "6/7: Creating systemd service..."

cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Clipboard Web Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env
Environment=PYTHONUNBUFFERED=1
ExecStart=${GUNICORN_VENV_PATH} --workers 1 --bind 0.0.0.0:${CLIPBOARD_PORT} --timeout 120 web_service:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
SERVICEEOF

# ============================================
# 7. Final Setup
# ============================================
print_status "7/7: Final setup..."

# CLI wrapper
cat > "$INSTALL_DIR/clipboard_cli.sh" << 'CLISHEOF'
#!/bin/bash
source /opt/clipboard_server/venv/bin/activate
python3 /opt/clipboard_server/clipboard_cli.py "$@"
CLISHEOF
chmod +x "$INSTALL_DIR/clipboard_cli.sh"

# Initialize DB
"$INSTALL_DIR/venv/bin/python3" "$INSTALL_DIR/clipboard_cli.py" --init-db

# Fix permissions
chmod -R 755 "$INSTALL_DIR"
chmod 777 "$INSTALL_DIR/uploads" 2>/dev/null || true
mkdir -p "$INSTALL_DIR/uploads"

# Start service
systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

sleep 2

# Test
if curl -s http://localhost:${CLIPBOARD_PORT}/ > /dev/null; then
    echo ""
    echo "========================================"
    echo "✅ Installation Successful!"
    echo "========================================"
    echo "🌐 Web Interface: http://$(curl -s ifconfig.me):${CLIPBOARD_PORT}"
    echo "💻 CLI Tool: sudo /opt/clipboard_server/clipboard_cli.sh"
    echo ""
    echo "🔧 Features:"
    echo "   • Fixed URL download crashes"
    echo "   • All file types supported"
    echo "   • 10GB max file size"
    echo "   • Stable single-worker setup"
    echo "========================================"
else
    echo "⚠️ Service may need manual start. Running:"
    echo "sudo systemctl restart clipboard.service"
    systemctl restart clipboard.service
fi
