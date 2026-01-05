#!/bin/bash
# Internet Clipboard Server Installer (V42 - Comprehensive Fix)
# Changes: Fixed Timeout 503, added APK/EXE/MSI support, Unified Code.

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
BLUE='\033[0;34m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    print_error "❌ Please run with sudo."
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server (V42 - FULL UNIFIED)"
echo "=================================================="

print_status "1/6: Installing Dependencies..."
systemctl stop clipboard.service 2>/dev/null || true
apt update -y && apt install -y python3 python3-pip python3-venv curl sqlite3
mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/uploads"
cd "$INSTALL_DIR"
if [ ! -d "venv" ]; then python3 -m venv venv; fi
venv/bin/pip install flask python-dotenv gunicorn requests

# --- 2. Create Web Service (Python) ---
print_status "2/6: Creating Web Engine (No Limits)..."
cat > "$INSTALL_DIR/web_service.py" << 'PYEOF'
import os, sqlite3, string, random, time, requests
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv, find_dotenv
from werkzeug.utils import secure_filename

load_dotenv(find_dotenv(usecwd=True), override=True)
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_key')
UPLOAD_FOLDER = 'uploads'

# ALL EXTENSIONS ALLOWED
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'mp3', 'mp4', 'exe', 'bin', 'iso', 'apk', 'apks', 'deb', 'msi', 'dmg', 'gz', 'tar'}

def get_db():
    if not hasattr(g, '_database'):
        g._database = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'clipboard.db'))
        g._database.row_factory = sqlite3.Row
    return g._database

@app.teardown_appcontext
def close_db(e):
    if hasattr(g, '_database'): g._database.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def download_and_save_file(url, key, file_paths):
    try:
        # TIMEOUT = NONE (Fixes 503 for large files)
        r = requests.get(url, allow_redirects=True, stream=True, timeout=None)
        if r.status_code != 200: return False, f"HTTP {r.status_code}"
        fname = secure_filename(os.path.basename(url.split('?', 1)[0]) or "file")
        if not allowed_file(fname): return False, "Format not allowed"
        unique_name = f"{key}_{fname}"
        path = os.path.join(UPLOAD_FOLDER, unique_name)
        with open(os.path.join(os.path.dirname(__file__), path), 'wb') as f:
            for chunk in r.iter_content(8192): f.write(chunk)
        file_paths.append(path)
        return True, fname
    except Exception as e: return False, str(e)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        content = request.form.get('content', '')
        url_files = request.form.get('url_files', '')
        uploaded_files = request.files.getlist('files')
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        file_paths = []

        for f in uploaded_files:
            if f and allowed_file(f.filename):
                path = os.path.join(UPLOAD_FOLDER, f"{key}_{secure_filename(f.filename)}")
                f.save(os.path.join(os.path.dirname(__file__), path))
                file_paths.append(path)

        for url in [u.strip() for u in url_files.split('\n') if u.strip()]:
            success, msg = download_and_save_file(url, key, file_paths)
            if not success: flash(f"Error: {msg}"); return redirect('/')

        exp = int(time.time() + (int(os.getenv('EXPIRY_DAYS', 30)) * 86400))
        db = get_db()
        db.execute("INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?,?,?,?,?)",
                   (key, content, ','.join(file_paths), int(time.time()), exp))
        db.commit()
        return redirect(url_for('view_clip', key=key))
    return render_template('index.html')

@app.route('/<key>')
def view_clip(key):
    clip = get_db().execute("SELECT * FROM clips WHERE key = ?", (key,)).fetchone()
    if not clip: return "Not Found", 404
    f_info = [{'path': p, 'name': p.split('_', 1)[-1]} for p in clip['file_path'].split(',')] if clip['file_path'] else []
    return render_template('clipboard.html', key=key, content=clip['content'], files_info=f_info)

@app.route('/download/<path:fp>')
def download_file(fp):
    return send_from_directory(os.path.dirname(app.root_path), fp, as_attachment=True)

if __name__ == '__main__': pass
PYEOF

# --- 3. Create Templates (Minimal) ---
print_status "3/6: Creating Templates..."
cat > "$INSTALL_DIR/templates/index.html" << 'TEMPEOF'
<!DOCTYPE html><html><head><title>Cloud Clipboard</title><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family:sans-serif;max-width:600px;margin:20px auto;padding:10px;background:#f4f4f9;">
    <h2>📋 Internet Clipboard</h2>
    <form method="post" enctype="multipart/form-data">
        <textarea name="content" placeholder="Text content..." style="width:100%;height:100px;"></textarea><br><br>
        <textarea name="url_files" placeholder="Paste Download Links here (one per line)..." style="width:100%;height:600px;"></textarea><br><br>
        <input type="file" name="files" multiple><br><br>
        <button type="submit" style="padding:10px 20px;background:#28a745;color:#fff;border:none;cursor:pointer;">Save to Cloud</button>
    </form>
</body></html>
TEMPEOF

cat > "$INSTALL_DIR/templates/clipboard.html" << 'TEMPEOF'
<!DOCTYPE html><html><head><title>Result</title></head>
<body style="font-family:sans-serif;max-width:600px;margin:20px auto;padding:10px;">
    <h3>Key: {{ key }}</h3>
    <pre style="background:#eee;padding:10px;">{{ content }}</pre>
    <h4>Files:</h4>
    <ul>{% for f in files_info %}<li><a href="{{ url_for('download_file', fp=f.path) }}">{{ f.name }}</a></li>{% endfor %}</ul>
    <a href="/">← Back</a>
</body></html>
TEMPEOF

# --- 4. Database Setup ---
print_status "4/6: Database Setup..."
sqlite3 "$DATABASE_PATH" "CREATE TABLE IF NOT EXISTS clips (id INTEGER PRIMARY KEY, key TEXT UNIQUE, content TEXT, file_path TEXT, created_at INTEGER, expires_at INTEGER);"

# --- 5. Systemd Service (The 503 Fix) ---
print_status "5/6: Configuring Systemd Service..."
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Service
After=network.target

[Service]
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn --workers 2 --timeout 0 --bind 0.0.0.0:${CLIPBOARD_PORT} web_service:app
Restart=always
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env

[Install]
WantedBy=multi-user.target
SERVICEEOF

cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
ENVEOF

# --- 6. Finalize ---
print_status "6/6: Starting Service..."
systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

echo "=================================================="
echo "✅ SUCCESS! Clipboard V42 is running on port ${CLIPBOARD_PORT}"
echo "🚀 No timeouts, all file types (APK/EXE/etc) allowed."
echo "=================================================="
