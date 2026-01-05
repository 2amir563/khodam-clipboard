#!/bin/bash
# Internet Clipboard Server Installer (CLI Management + Full Web Submission)
# V41 - EDIT CLIP EXPIRY: Added option to change the expiry date of a specific clip via the CLI.
# FIX: Adjusted JavaScript in clipboard.html for reliable text copying when files are present.
# MOD: Enhanced download system with curl/wget fallbacks and better error handling

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
echo "📋 Internet Clipboard Server Installer (V41 + Robust Download System)"
echo "=================================================="

# ============================================
# 1. System Setup & Venv (WITH CURL/WGET)
# ============================================
print_status "1/7: Preparing system with curl/wget and cleaning old DB..."

# Stop service if running 
systemctl stop clipboard.service 2>/dev/null || true

apt update -y
apt install -y python3 python3-pip python3-venv curl wget net-tools

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
# 3. Create web_service.py (ROBUST DOWNLOAD SYSTEM)
# ============================================
print_status "3/7: Creating web_service.py (Robust download with multiple methods)..."
cat > "$INSTALL_DIR/web_service.py" << 'PYEOF_WEB_SERVICE'
import os
import sqlite3
import re
import string
import random
import time
import urllib.parse
import subprocess
import tempfile
import ssl
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv, find_dotenv
from werkzeug.utils import secure_filename
import requests 
import socket

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

# Extended list of allowed file extensions
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'svg', 'webp', 'tiff', 'psd',
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'dmg', 
    'mp3', 'mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4a', 'wav', 'ogg', 'flac',
    'exe', 'msi', 'apk', 'deb', 'rpm', 'apks', 'xapk', 'appimage',
    'bin', 'dll', 'so', 'dylib', 'sys', 'drv',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
    'html', 'htm', 'css', 'js', 'json', 'xml', 'csv', 'sql', 'py', 'java', 'cpp', 'c', 'h',
    'ps1', 'bat', 'sh', 'bash', 'zsh', 'fish',
    'ttf', 'otf', 'woff', 'woff2', 'eot',
    'torrent', 'md', 'rst', 'log', 'ini', 'conf', 'cfg', 'yml', 'yaml',
    'key', 'pem', 'crt', 'cer', 'pfx', 'p12',
    'db', 'sqlite', 'sqlite3', 'mdb', 'accdb',
    'sketch', 'fig', 'xd', 'ai', 'ps', 'eps',
    '3ds', 'obj', 'fbx', 'stl', 'blend', 'ma', 'mb',
    'vmdk', 'vhd', 'vhdx', 'ova', 'ovf',
    'epub', 'mobi', 'azw', 'azw3', 'fb2',
    'heic', 'heif', 'cr2', 'nef', 'arw', 'orf',
    'swf', 'swc', 'fla', 'as', 'mxml',
    'lua', 'pl', 'pm', 'tcl', 'rb', 'go', 'rs', 'php', 'asp', 'aspx',
    'djvu', 'xps', 'oxps', 'ps', 'eps', 'ai',
    'pkg', 'run', 'sh', 'bash', 'zsh', 'fish',
    'reg', 'inf', 'cat', 'msc', 'msi', 'msp', 'mst'
}

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
            raise RuntimeError("Database connection failed.")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
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

def test_network_connection():
    """Test if we can reach common external servers"""
    test_urls = [
        "https://google.com",
        "https://github.com",
        "https://cloudflare.com"
    ]
    
    results = []
    for url in test_urls:
        try:
            response = requests.head(url, timeout=5)
            results.append(f"{url}: HTTP {response.status_code}")
        except Exception as e:
            results.append(f"{url}: Failed - {str(e)}")
    
    return results

def download_with_requests(url, output_path, timeout=30):
    """Download using requests library with multiple retries"""
    headers_list = [
        {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        },
        {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br'
        },
        {
            'User-Agent': 'curl/7.88.1',
            'Accept': '*/*'
        }
    ]
    
    for i, headers in enumerate(headers_list):
        try:
            print(f"[DEBUG] Requests attempt {i+1} for {url}")
            response = requests.get(
                url, 
                headers=headers,
                stream=True, 
                timeout=timeout,
                verify=True,
                allow_redirects=True
            )
            
            if response.status_code == 200:
                total_size = int(response.headers.get('content-length', 0))
                downloaded = 0
                
                with open(output_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                
                # Verify file was downloaded
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    print(f"[DEBUG] Successfully downloaded {os.path.getsize(output_path)} bytes")
                    return True, f"Downloaded with requests (method {i+1})"
                else:
                    print(f"[DEBUG] File empty or not created")
                    continue
            else:
                print(f"[DEBUG] HTTP {response.status_code} with method {i+1}")
                if response.status_code == 503:
                    return False, f"Server unavailable (503) - likely server-side issue"
                
        except requests.exceptions.SSLError:
            # Try without SSL verification
            try:
                response = requests.get(
                    url, 
                    headers=headers,
                    stream=True, 
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
                if response.status_code == 200:
                    with open(output_path, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                        return True, f"Downloaded with requests (no SSL verify)"
            except Exception as e:
                print(f"[DEBUG] SSL retry failed: {e}")
                continue
                
        except Exception as e:
            print(f"[DEBUG] Requests method {i+1} failed: {e}")
            continue
    
    return False, "All requests methods failed"

def download_with_wget(url, output_path, timeout=60):
    """Download using wget command"""
    try:
        # Clean URL for wget
        clean_url = url.strip()
        
        # Create wget command
        cmd = [
            'wget',
            '-O', output_path,
            '-T', str(timeout),
            '--tries', '3',
            '--retry-connrefused',
            '--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '--header=Accept: */*',
            '--header=Accept-Language: en-US,en;q=0.5',
            '--no-check-certificate',
            clean_url
        ]
        
        print(f"[DEBUG] Running wget command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        
        print(f"[DEBUG] wget stdout: {result.stdout[:200]}")
        print(f"[DEBUG] wget stderr: {result.stderr[:200]}")
        
        if result.returncode == 0:
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                return True, "Downloaded with wget"
            else:
                return False, "wget succeeded but file is empty"
        else:
            return False, f"wget failed with code {result.returncode}: {result.stderr[:100]}"
            
    except subprocess.TimeoutExpired:
        return False, "wget timeout"
    except Exception as e:
        return False, f"wget error: {str(e)}"

def download_with_curl(url, output_path, timeout=60):
    """Download using curl command"""
    try:
        cmd = [
            'curl',
            '-L',  # Follow redirects
            '-o', output_path,
            '-m', str(timeout),
            '--retry', '3',
            '--retry-delay', '5',
            '-H', 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-H', 'Accept: */*',
            '--insecure',  # Don't verify SSL
            '--silent',
            '--show-error',
            url
        ]
        
        print(f"[DEBUG] Running curl command: {' '.join(cmd[:10])}...")
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=timeout + 10
        )
        
        if result.returncode == 0:
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                return True, "Downloaded with curl"
            else:
                return False, "curl succeeded but file is empty"
        else:
            error_msg = result.stderr[:200] if result.stderr else "Unknown error"
            return False, f"curl failed: {error_msg}"
            
    except subprocess.TimeoutExpired:
        return False, "curl timeout"
    except Exception as e:
        return False, f"curl error: {str(e)}"

def download_and_save_file(url, key, file_paths):
    """
    Robust file download with multiple fallback methods
    """
    # Basic URL validation
    if not url.lower().startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://."
    
    # Extract filename
    parsed_url = urllib.parse.urlparse(url)
    filename = os.path.basename(parsed_url.path)
    
    if not filename or filename == '.':
        # Generate a filename based on key
        filename = f"download_{key}.zip"
    
    # Check file extension
    if not allowed_file(filename):
        return False, f"File type not allowed: {filename}"
    
    filename = secure_filename(filename)
    unique_filename = f"{key}_{filename}"
    full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), full_path)
    
    print(f"[INFO] Starting download: {url}")
    print(f"[INFO] Target file: {local_path}")
    
    # Create uploads directory if it doesn't exist
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    
    # Test network connection first
    print("[DEBUG] Testing network connectivity...")
    network_test = test_network_connection()
    print(f"[DEBUG] Network test results: {network_test}")
    
    # METHOD 1: Try curl first (most reliable for CLI)
    print("[DEBUG] Trying curl...")
    success, msg = download_with_curl(url, local_path, timeout=45)
    if success:
        file_size = os.path.getsize(local_path)
        print(f"[SUCCESS] Downloaded {file_size} bytes with curl")
        file_paths.append(full_path)
        return True, f"Downloaded successfully ({file_size} bytes)"
    
    # METHOD 2: Try wget
    print("[DEBUG] Trying wget...")
    success, msg = download_with_wget(url, local_path, timeout=45)
    if success:
        file_size = os.path.getsize(local_path)
        print(f"[SUCCESS] Downloaded {file_size} bytes with wget")
        file_paths.append(full_path)
        return True, f"Downloaded successfully ({file_size} bytes)"
    
    # METHOD 3: Try requests as last resort
    print("[DEBUG] Trying requests...")
    success, msg = download_with_requests(url, local_path, timeout=45)
    if success:
        file_size = os.path.getsize(local_path)
        print(f"[SUCCESS] Downloaded {file_size} bytes with requests")
        file_paths.append(full_path)
        return True, f"Downloaded successfully ({file_size} bytes)"
    
    # Clean up failed download
    if os.path.exists(local_path):
        try:
            os.remove(local_path)
        except:
            pass
    
    # Comprehensive error message
    error_msg = f"""
    ❌ Download failed for: {filename}
    URL: {url}
    
    🔍 Diagnostic Information:
    - Network test: {network_test}
    - All download methods failed
    
    🛠️ Possible Causes:
    1. Server is down or returning 503 (Service Unavailable)
    2. Network firewall blocking the connection
    3. DNS resolution issues
    4. Server blocking your IP address
    5. URL requires authentication
    
    💡 Solutions to Try:
    1. Check if you can access the URL directly from your server:
       curl -I "{url}"
    2. Try from a different network/VPN
    3. Download manually and use DIRECT UPLOAD
    4. Check server firewall/iptables rules
    5. Verify DNS is working: nslookup github.com
    
    📝 For GitHub releases:
    - GitHub may rate-limit your IP
    - Try again in a few minutes
    - Or use direct file upload instead
    """
    
    print(f"[ERROR] {error_msg}")
    return False, error_msg


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
        except RuntimeError:
            flash("Database connection error.", 'error')
            return render_template('index.html', **context) 
            
        # File Handling (Local & Remote)
        file_paths = []
        has_upload_error = False

        # 1. Local File Upload
        for file in uploaded_files:
            if file and file.filename:
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{key}_{filename}"
                    full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
                    try:
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
    except RuntimeError:
         flash("Database connection error during cleanup. Please run CLI tool.", 'error')
    
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
        print(f"SQLITE ERROR: {e}")
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

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

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

@app.route('/network-test')
def network_test_page():
    """Page to test network connectivity"""
    test_results = test_network_connection()
    return render_template('network_test.html', results=test_results)

if __name__ == '__main__':
    pass

PYEOF_WEB_SERVICE

# ============================================
# 4. Create clipboard_cli.py (The CLI Management Tool)
# ============================================
print_status "4/7: Creating clipboard_cli.py (CLI Tool)..."
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
import requests

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

def test_network_from_cli():
    """Test network connectivity from CLI"""
    print(f"\n{Color.CYAN}{Color.BOLD}--- Network Connectivity Test ---{Color.END}")
    
    test_urls = [
        ("Google", "https://google.com"),
        ("GitHub", "https://github.com"),
        ("Cloudflare", "https://cloudflare.com")
    ]
    
    for name, url in test_urls:
        try:
            response = requests.head(url, timeout=5)
            print(f"{Color.GREEN}✓{Color.END} {name}: HTTP {response.status_code}")
        except requests.exceptions.Timeout:
            print(f"{Color.RED}✗{Color.END} {name}: Timeout")
        except requests.exceptions.ConnectionError:
            print(f"{Color.RED}✗{Color.END} {name}: Connection failed")
        except Exception as e:
            print(f"{Color.RED}✗{Color.END} {name}: {str(e)[:50]}")

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
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path.strip())
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
            
            # Find the original creation time (This is complex/buggy, simpler is: adjust from current expiry)
            # Simpler approach: Calculate new expiry date based on adjustment from current expiry
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
        print(f"   {Color.BOLD}New Expiry:{Color.END} {new_expiry_dt.strftime('%Y-%m-d %H:%M:%S UTC')}")
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
        print(f"6. {Color.CYAN}Test Network Connectivity{Color.END}")
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
            test_network_from_cli()
        elif choice == '0':
            print(f"\n{Color.BOLD}Exiting CLI Management. Goodbye!{Color.END}")
            break
        else:
            print(f"{Color.RED}Invalid choice. Please try again.{Color.END}")

if __name__ == '__main__':
    main_menu()

PYEOF_CLI_TOOL

# ============================================
# 5. Create HTML Templates
# ============================================
print_status "5/7: Creating HTML templates..."

# --- network_test.html ---
cat > "$INSTALL_DIR/templates/network_test.html" << 'NETWORKTESTEOF'
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Test</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 700px; margin: 20px auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #007bff; text-align: center; margin-bottom: 25px; }
        .result { padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 5px solid #007bff; background-color: #f8f9fa; }
        .success { border-left-color: #28a745; background-color: #d4edda; }
        .error { border-left-color: #dc3545; background-color: #f8d7da; }
        .back-link { display: block; text-align: center; margin-top: 30px; }
        .back-link a { color: #007bff; text-decoration: none; font-weight: bold; }
        .troubleshoot { margin-top: 30px; padding: 20px; background-color: #fff3cd; border-radius: 8px; border: 1px solid #ffeaa7; }
        .troubleshoot h3 { margin-top: 0; color: #856404; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Network Connectivity Test</h1>
        
        <p>Testing connection to external servers...</p>
        
        {% for result in results %}
        <div class="result {% if 'HTTP 200' in result or 'HTTP 30' in result %}success{% else %}error{% endif %}">
            {{ result }}
        </div>
        {% endfor %}
        
        <div class="troubleshoot">
            <h3>🔧 Troubleshooting Tips:</h3>
            <p>If tests are failing:</p>
            <ol>
                <li>Check your server's internet connection</li>
                <li>Verify firewall rules allow outbound HTTP/HTTPS</li>
                <li>Check DNS configuration: <code>nslookup google.com</code></li>
                <li>Test with curl: <code>curl -I https://google.com</code></li>
                <li>Check for proxy settings</li>
                <li>Verify server time is correct (affects SSL)</li>
            </ol>
            <p><strong>Note:</strong> If GitHub returns 503, it may be rate-limiting your IP.</p>
        </div>
        
        <div class="back-link">
            <a href="/">← Back to Create Clip</a>
        </div>
    </div>
</body>
</html>
NETWORKTESTEOF

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
        .info { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .warning { background-color: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
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
        .tips { margin-top: 20px; padding: 15px; background-color: #e8f5e8; border: 1px solid #c3e6cb; border-radius: 8px; }
        .tips h3 { margin-top: 0; color: #155724; }
        .tips ul { margin-bottom: 0; padding-left: 20px; }
        .network-test { margin-top: 15px; text-align: center; }
        .network-test a { color: #007bff; text-decoration: none; font-weight: bold; }
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
        
        <div class="flash warning">
            <strong>⚠️ Important:</strong> If URL downloads fail with 503 errors, your server may have network issues.
            Try the <a href="/network-test" style="color: #856404; font-weight: bold;">Network Test</a> to diagnose.
        </div>
        
        <form method="POST" enctype="multipart/form-data">
            <div>
                <label for="content">Text Content (Optional):</label>
                <textarea id="content" name="content" placeholder="Paste your text here...">{{ old_content }}</textarea>
            </div>
            
            <div>
                <label for="files">📁 Local File Upload (Recommended - Most Reliable):</label>
                <input type="file" id="files" name="files" multiple>
            </div>
            
            <div>
                <label for="url_files">🔗 File Upload via URL (If local upload works):</label>
                <textarea id="url_files" name="url_files" placeholder="Enter file URLs (one per line)...">{{ old_url_files }}</textarea>
            </div>

            <div>
                <label for="custom_key">🔑 Custom Link Key (Optional):</label>
                <input type="text" id="custom_key" name="custom_key" placeholder="Leave blank for random key" value="{{ old_custom_key }}">
            </div>
            
            <input type="submit" value="Create Clip (Expires in {{ EXPIRY_DAYS }} days)">
        </form>
        
        <div class="network-test">
            <a href="/network-test">🌐 Test Network Connectivity</a>
        </div>
        
        <div class="tips">
            <h3>💡 Pro Tips:</h3>
            <ul>
                <li><strong>For 503 errors:</strong> Use DIRECT FILE UPLOAD instead of URLs</li>
                <li><strong>Large files:</strong> Upload directly for better reliability</li>
                <li><strong>GitHub releases:</strong> May rate-limit your IP - try again later</li>
                <li><strong>Network issues:</strong> Check server firewall and DNS settings</li>
                <li><strong>Best practice:</strong> Download manually → Upload to server</li>
            </ul>
        </div>
        
        <div class="cli-note">
            ⚙️ Server Management: <code>sudo /opt/clipboard_server/clipboard_cli.sh</code>
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
            
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(contentElement.innerText).then(() => {
                    alert('Text copied to clipboard!');
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
                alert('Text copied to clipboard!');
            } catch (err) {
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
        .troubleshoot { margin-top: 30px; padding: 20px; background-color: #fff3cd; border-radius: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ Internal Error</h1>
        <div class="error-message">
            <p>{{ message }}</p>
        </div>
        <div class="troubleshoot">
            <h3>Troubleshooting Steps:</h3>
            <ol style="text-align: left;">
                <li>Check server logs: <code>sudo journalctl -u clipboard.service</code></li>
                <li>Ensure database is initialized: <code>sudo /opt/clipboard_server/clipboard_cli.sh --init-db</code></li>
                <li>Restart the service: <code>sudo systemctl restart clipboard.service</code></li>
                <li>Check disk space: <code>df -h</code></li>
                <li>Verify permissions: <code>ls -la /opt/clipboard_server/</code></li>
            </ol>
        </div>
    </div>
</body>
</html>
ERROREOF

# ============================================
# 6. Create Systemd Service
# ============================================
print_status "6/7: Creating Systemd service for web server..."

cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Web Server (Full Submission, CLI Management)
After=network.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
ExecStart=${GUNICORN_VENV_PATH} --workers 2 --bind 0.0.0.0:${CLIPBOARD_PORT} web_service:app
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env
Restart=always
RestartSec=10
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF

# ============================================
# 7. Final Steps with DIAGNOSTICS
# ============================================
print_status "7/7: Initializing database and starting service with diagnostics..."

# Create wrapper script
cat > "$INSTALL_DIR/clipboard_cli.sh" << CLISHEOF
#!/bin/bash
source ${INSTALL_DIR}/venv/bin/activate
exec ${PYTHON_VENV_PATH} ${INSTALL_DIR}/clipboard_cli.py "\$@"
CLISHEOF
chmod +x "$INSTALL_DIR/clipboard_cli.sh"

# Create diagnostic script
cat > "$INSTALL_DIR/diagnose.sh" << 'DIAGEOF'
#!/bin/bash
echo "🔍 Clipboard Server Diagnostics"
echo "================================"

echo "1. Checking service status..."
systemctl status clipboard.service --no-pager

echo -e "\n2. Testing network connectivity..."
curl -I --max-time 10 https://google.com 2>/dev/null | head -1
curl -I --max-time 10 https://github.com 2>/dev/null | head -1

echo -e "\n3. Checking disk space..."
df -h /opt

echo -e "\n4. Checking server logs (last 20 lines)..."
journalctl -u clipboard.service -n 20 --no-pager

echo -e "\n5. Testing direct curl to GitHub..."
echo "Testing: https://github.com/2dust/v2rayN/releases/download/7.16.8/v2rayN-windows-arm64-desktop.zip"
curl -I --max-time 15 "https://github.com/2dust/v2rayN/releases/download/7.16.8/v2rayN-windows-arm64-desktop.zip" 2>&1 | head -5

echo -e "\n📝 If GitHub returns 503:"
echo "   - GitHub may be rate-limiting your IP"
echo "   - Try again in a few minutes"
echo "   - Use DIRECT UPLOAD instead of URLs"
echo "   - Check server firewall/iptables rules"
DIAGEOF
chmod +x "$INSTALL_DIR/diagnose.sh"

# Initialize DB
"$INSTALL_DIR/clipboard_cli.sh" --init-db 

systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

# Wait a moment for service to start
sleep 3

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V41 + Robust Download)"
echo "================================================"
echo "✅ Web service is active on port ${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "🌐 Web Interface: http://$(hostname -I | awk '{print $1}'):${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "💻 CLI Management:"
echo -e "   ${BLUE}sudo ${INSTALL_DIR}/clipboard_cli.sh${NC}"
echo "------------------------------------------------"
echo "🔍 Diagnostics:"
echo -e "   ${YELLOW}sudo ${INSTALL_DIR}/diagnose.sh${NC}"
echo "------------------------------------------------"
echo "📝 IMPORTANT - For 503 Errors:"
echo "   1. Run the diagnostic script above"
echo "   2. Use DIRECT FILE UPLOAD instead of URLs"
echo "   3. Check server firewall/network settings"
echo "   4. GitHub may rate-limit your IP - try later"
echo "------------------------------------------------"
echo "📋 Quick Test:"
echo "   Open http://$(hostname -I | awk '{print $1}'):${CLIPBOARD_PORT} in browser"
echo "   Upload a small file directly (not via URL)"
echo "================================================"
