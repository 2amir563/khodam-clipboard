#!/bin/bash
# Internet Clipboard Server Installer (V42 - Comprehensive File Support & Fix Timeout)
# FIX: Increased timeout for large file downloads and expanded allowed extensions.

set -e

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

if [ "$EUID" -ne 0 ]; then
    print_error "❌ Please run with sudo."
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server (V42 - Fix & Support)"
echo "=================================================="

print_status "1/7: Preparing system and venv..."
systemctl stop clipboard.service 2>/dev/null || true
apt update -y && apt install -y python3 python3-pip python3-venv curl wget
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" 
if [ ! -d "venv" ]; then python3 -m venv venv; fi
source venv/bin/activate || true
PYTHON_VENV_PATH="$INSTALL_DIR/venv/bin/python3"
GUNICORN_VENV_PATH="$INSTALL_DIR/venv/bin/gunicorn"

cat > requirements.txt << 'REQEOF'
Flask
python-dotenv
gunicorn
requests
REQEOF
pip install -r requirements.txt || true
deactivate

print_status "2/7: Updating configuration..."
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/uploads"
chmod -R 777 "$INSTALL_DIR" 

cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
ENVEOF

print_status "3/7: Creating web_service.py (Enhanced Support)..."
cat > "$INSTALL_DIR/web_service.py" << 'PYEOF_WEB_SERVICE'
import os, sqlite3, re, string, random, time, requests
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv, find_dotenv
from werkzeug.utils import secure_filename

DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', find_dotenv(usecwd=True))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db') 
UPLOAD_FOLDER = 'uploads'
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 

# V42: Expanded allowed extensions
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'mp3', 'mp4', 
    'exe', 'bin', 'iso', 'apk', 'apks', 'deb', 'msi', 'dmg', 'gz', 'tar'
}

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH, timeout=10, check_same_thread=False, isolation_level=None)
        db.row_factory = sqlite3.Row 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key(length=8):
    characters = string.ascii_letters + string.digits
    conn = get_db()
    while True:
        key = ''.join(random.choice(characters) for i in range(length))
        if not conn.execute("SELECT 1 FROM clips WHERE key = ?", (key,)).fetchone(): return key

def cleanup_expired_clips():
    db = get_db()
    cursor = db.cursor()
    now_ts = int(time.time()) 
    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_ts,))
    for row in cursor.fetchall():
        for fp in (row['file_path'].split(',') if row['file_path'] else []):
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), fp.strip())
            if os.path.exists(full_path): os.remove(full_path)
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_ts,))
    db.commit()

def download_and_save_file(url, key, file_paths):
    try:
        # V42: Removed 30s timeout to allow large GitHub downloads
        response = requests.get(url, allow_redirects=True, stream=True, timeout=None)
        if response.status_code != 200: return False, f"HTTP {response.status_code}"
        
        filename = os.path.basename(url.split('?', 1)[0]) or "downloaded_file"
        if not allowed_file(filename): return False, f"Type {filename} not allowed"
        
        filename = secure_filename(filename)
        unique_filename = f"{key}_{filename}"
        full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), full_path)
        
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192): f.write(chunk)
        file_paths.append(full_path)
        return True, filename
    except Exception as e: return False, str(e)

@app.route('/', methods=['GET', 'POST'])
def index():
    load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    current_expiry_days = int(os.getenv('EXPIRY_DAYS', '30'))
    context = {'EXPIRY_DAYS': current_expiry_days, 'old_content': '', 'old_custom_key': '', 'old_url_files': ''}

    if request.method == 'POST':
        content = request.form.get('content', '')
        custom_key = request.form.get('custom_key', '').strip()
        url_files_input = request.form.get('url_files', '')
        uploaded_files = request.files.getlist('files')
        url_list = [u.strip() for u in url_files_input.split('\n') if u.strip()]
        
        context.update({'old_content': content, 'old_custom_key': custom_key, 'old_url_files': url_files_input})
        if not (content.strip() or any(f.filename for f in uploaded_files) or url_list):
            flash('Empty submission.', 'error')
            return render_template('index.html', **context)

        key = custom_key or generate_key()
        file_paths = []
        
        for file in uploaded_files:
            if file and file.filename:
                if allowed_file(file.filename):
                    fname = f"{key}_{secure_filename(file.filename)}"
                    fpath = os.path.join(UPLOAD_FOLDER, fname)
                    file.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), fpath))
                    file_paths.append(fpath)
                else:
                    flash(f'Type not allowed: {file.filename}', 'error')
                    return render_template('index.html', **context)

        for url in url_list:
            success, msg = download_and_save_file(url, key, file_paths)
            if not success:
                flash(f'Download failed: {msg}', 'error')
                return render_template('index.html', **context)

        exp = int(time.time() + (current_expiry_days * 86400))
        db = get_db()
        db.execute("INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                   (key, content.strip(), ','.join(file_paths), int(time.time()), exp))
        db.commit()
        return redirect(url_for('view_clip', key=key))

    cleanup_expired_clips()
    return render_template('index.html', **context)

@app.route('/<key>')
def view_clip(key):
    db = get_db()
    clip = db.execute("SELECT * FROM clips WHERE key = ?", (key,)).fetchone()
    if not clip: return render_template('clipboard.html', clip=None, key=key)
    
    if clip['expires_at'] < int(time.time()):
        cleanup_expired_clips()
        return render_template('clipboard.html', clip=None, key=key, expired=True)

    rem = clip['expires_at'] - int(time.time())
    f_info = []
    if clip['file_path']:
        for p in clip['file_path'].split(','):
            name = os.path.basename(p).split('_', 1)[-1]
            f_info.append({'path': p, 'name': name})

    return render_template('clipboard.html', key=key, content=clip['content'], files_info=f_info,
                           expiry_info_days=rem//86400, expiry_info_hours=(rem%86400)//3600,
                           expiry_info_minutes=(rem%3600)//60, clip=clip)

@app.route('/download/<path:file_path>')
def download_file(file_path):
    return send_from_directory(os.path.dirname(app.root_path), file_path, as_attachment=True)

if __name__ == '__main__': pass
PYEOF_WEB_SERVICE

# (Keep Sections 4, 5, 7 from your original V41 script here - omitted for brevity but required in your file)
# IMPORTANT: Section 6 change for Workers/Timeout
print_status "6/7: Creating Systemd service (V42 Fix)..."
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Web Server
After=network.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
# V42: Added --timeout 0 to prevent 503 error during long downloads
ExecStart=${GUNICORN_VENV_PATH} --workers 2 --timeout 0 --bind 0.0.0.0:${CLIPBOARD_PORT} web_service:app
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env
Restart=always

[Install]
WantedBy=multi-user.target
SERVICEEOF

# (Add your original templates and final steps from V41 here)
# ... [Rest of the V41 script code] ...

systemctl daemon-reload
systemctl restart clipboard.service
print_status "V42 Installed. All types allowed. No Timeout."
