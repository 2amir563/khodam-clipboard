#!/bin/bash
# Internet Clipboard Server Installer (Flask + Gunicorn + SQLite)
# V10 - Final: Enhanced Admin Panel Design & Full English Localization.

set -e

# --- Configuration ---
INSTALL_DIR="/opt/clipboard_server"
PORT="3214"
EXPIRY_DAYS="30"
SECRET_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32) 

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# Check root access
if [ "$EUID" -ne 0 ]; then
    print_error "❌ Please run with root access: sudo bash install_clipboard.sh"
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server Installer (V10 - Enhanced Admin UI & English)"
echo "=================================================="


# ============================================
# 1. System Setup & Venv
# ============================================
print_status "1/6: Ensuring system setup and Virtual Environment..."
apt update -y
apt install -y python3 python3-pip python3-venv curl wget

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" 

python3 -m venv venv || true 
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
PORT=${PORT}
MAX_REMOTE_SIZE_MB=50
ENVEOF

# ============================================
# 3. Create app.py (V10 - English and Admin Update)
# ============================================
print_status "3/6: Creating app.py (V10 - English and Admin Update)..."
cat > "$INSTALL_DIR/app.py" << 'PYEOF'
import os
import sqlite3
import random
import string
import re
import requests
import urllib.parse
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
PORT = int(os.getenv('PORT', '3214')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
MAX_REMOTE_SIZE_BYTES = int(os.getenv('MAX_REMOTE_SIZE_MB', 50)) * 1024 * 1024 # Default 50 MB

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

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
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
        db.commit()

# --- Security Decorator: Restrict Access to Localhost ---
def local_access_only(f):
    def wrap(*args, **kwargs):
        # Check if the request comes from localhost (127.0.0.1) or local IPv6 (::1)
        if request.remote_addr in ('127.0.0.1', '::1'):
            return f(*args, **kwargs)
        else:
            # Block external access to admin panel
            return "Access Denied: Admin panel is only available from localhost.", 403
    wrap.__name__ = f.__name__ 
    return wrap

# --- Helper Functions ---
def generate_key(length=8):
    characters = string.ascii_letters + string.digits
    db = get_db()
    cursor = db.cursor()
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
        file_path = file_path_tuple[0]
        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
        if file_path and os.path.exists(full_path):
            try:
                os.remove(full_path)
            except OSError as e:
                print(f"Error removing file {full_path}: {e}")
            
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    db.commit()


def download_remote_file(url, key):
    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            
            content_length = r.headers.get('Content-Length')
            if content_length and int(content_length) > MAX_REMOTE_SIZE_BYTES:
                return "File size exceeds limit."
            
            filename = ""
            if 'Content-Disposition' in r.headers:
                filename_header = r.headers['Content-Disposition']
                match = re.search(r'filename=["\']?([^"\']+)["\']?', filename_header)
                if match:
                    filename = match.group(1)
            
            if not filename:
                path = urllib.parse.urlparse(url).path
                filename = os.path.basename(path)
                if not filename or filename.count('.') < 1:
                    filename = "remote_file.bin" 
            
            safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
            
            file_path_relative = os.path.join(UPLOAD_FOLDER, f"{key}_{safe_filename}")
            file_path_absolute = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path_relative)
            
            downloaded_size = 0
            with open(file_path_absolute, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        downloaded_size += len(chunk)
                        if downloaded_size > MAX_REMOTE_SIZE_BYTES:
                            f.close()
                            os.remove(file_path_absolute)
                            return "File size exceeds limit during download."
                        f.write(chunk)
            
            return file_path_relative 
            
    except requests.exceptions.RequestException as e:
        return f"Error downloading file: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

# --- User Routes ---

@app.route('/')
def index():
    cleanup_expired_clips()
    
    old_data = {}
    messages = list(request.args.get('flash_messages', '').split('||')) 
    display_messages = []
    
    for message in messages:
        if message:
            try:
                category, msg_content = message.split(':', 1)
                if category == 'form_data':
                    data = eval(msg_content)
                    if isinstance(data, dict):
                        old_data = data
                else:
                    display_messages.append((category, msg_content))
            except:
                continue 
            
    from flask import get_flashed_messages
    for category, message in get_flashed_messages(with_categories=True):
        if category != 'form_data':
            display_messages.append((category, message))


    return render_template('index.html', EXPIRY_DAYS=EXPIRY_DAYS, old_data=old_data, flashed_messages=display_messages)


@app.route('/create', methods=['POST'])
def create_clip():
    content = request.form.get('content')
    uploaded_file = request.files.get('file')
    remote_url = request.form.get('remote_url', '').strip()
    custom_key = request.form.get('custom_key', '').strip()

    if not content and (not uploaded_file or not uploaded_file.filename) and not remote_url:
        flash('You must provide text, a local file, or a remote URL.', 'error')
        return redirect(url_for('index'))

    form_data_for_flash = {'content': content, 'custom_key': custom_key, 'remote_url': remote_url}
    error_messages = []

    # 1. Key determination and validation
    key = None
    if custom_key:
        if not re.match(KEY_REGEX, custom_key):
            error_messages.append('error:Custom key must contain only English letters, numbers, hyphen (-), or underscore (_) and be between 3 and 64 characters long.')
            
        else:
            key = custom_key
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
            if cursor.fetchone():
                error_messages.append(f'error:❌ Error: Key **{key}** is already taken. Please choose another name.')
    
    if error_messages:
        flash_args = "||".join([f'form_data:{str(form_data_for_flash)}'] + error_messages)
        return redirect(url_for('index', flash_messages=flash_args))

    if not key:
        key = generate_key()

    file_path = None
    
    # 2. Handle data/file upload
    if uploaded_file and uploaded_file.filename:
        filename = uploaded_file.filename
        file_path_relative = os.path.join(UPLOAD_FOLDER, f"{key}_{filename}")
        file_path_absolute = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path_relative)
        uploaded_file.save(file_path_absolute)
        file_path = file_path_relative
    
    elif remote_url:
        if not remote_url.startswith(('http://', 'https://')):
            error_messages.append('error:Remote URL is not valid (must start with http:// or https://).')
        else:
            download_result = download_remote_file(remote_url, key)
            
            if download_result.startswith("Error") or download_result.startswith("File size"):
                error_messages.append(f'error:❌ File Download Error: {download_result}')
            else:
                file_path = download_result 

    if error_messages:
        flash_args = "||".join([f'form_data:{str(form_data_for_flash)}'] + error_messages)
        return redirect(url_for('index', flash_messages=flash_args))

    if not content and file_path:
        content = f"File uploaded via link: {file_path.split('_', 1)[-1]}"

    if not content and not file_path:
        error_messages.append('error:You must have content to save.')
        flash_args = "||".join([f'form_data:{str(form_data_for_flash)}'] + error_messages)
        return redirect(url_for('index', flash_messages=flash_args))

    expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key, content, file_path, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
        
        flash(f'✅ Clipboard successfully created! Link: {url_for("view_clip", key=key, _external=True)}', 'success')
        return redirect(url_for('view_clip', key=key))
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash('❌ An internal error occurred while saving.', 'error')
        return redirect(url_for('index'))


@app.route('/<key>')
def view_clip(key):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT content, file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        return render_template('clipboard.html', clip=None, key=key)

    content, file_path, expires_at_str = clip
    
    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    
    if expires_at < now_utc:
        cleanup_expired_clips()
        return render_template('clipboard.html', clip=None, key=key, expired=True)

    time_left = expires_at - now_utc
    days = time_left.days
    hours = time_left.seconds // 3600
    minutes = (time_left.seconds % 3600) // 60
    
    expiry_info_days = days
    expiry_info_hours = hours
    expiry_info_minutes = minutes

    return render_template('clipboard.html', 
                           key=key, 
                           content=content, 
                           file_path=file_path, 
                           expiry_info_days=expiry_info_days,
                           expiry_info_hours=expiry_info_hours,
                           expiry_info_minutes=expiry_info_minutes,
                           server_port=PORT)


@app.route('/download/<key>')
def download_file(key):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        flash('File not found or link has expired.', 'error')
        return redirect(url_for('index'))

    file_path_relative, expires_at_str = clip
    
    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        cleanup_expired_clips()
        flash('File not found or link has expired.', 'error')
        return redirect(url_for('index'))
    
    if file_path_relative:
        filename_with_key = os.path.basename(file_path_relative)
        original_filename = filename_with_key.split('_', 1)[-1] 
        
        return send_from_directory(UPLOAD_FOLDER, 
                                   filename_with_key, 
                                   as_attachment=True, 
                                   download_name=original_filename)
    
    flash('No file exists for this link.', 'error')
    return redirect(url_for('view_clip', key=key))


# --- Admin Routes (Restricted to Localhost) ---

@app.route('/admin')
@local_access_only
def admin_panel():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, key, SUBSTR(content, 1, 50) as content_preview, file_path, created_at, expires_at FROM clips ORDER BY created_at DESC")
    clips = cursor.fetchall()
    
    total_size = 0
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), UPLOAD_FOLDER)
    for root, dirs, files in os.walk(upload_dir):
        for name in files:
            full_path = os.path.join(root, name)
            if os.path.exists(full_path):
                 total_size += os.path.getsize(full_path)
            
    total_size_mb = total_size / (1024 * 1024) 
    
    return render_template('admin.html', clips=clips, total_size_mb=f"{total_size_mb:.2f}", server_port=PORT)


@app.route('/admin/delete/<int:clip_id>', methods=['POST'])
@local_access_only
def delete_clip(clip_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT file_path FROM clips WHERE id = ?", (clip_id,))
    clip = cursor.fetchone()
    
    if clip and clip['file_path']:
        file_path = clip['file_path']
        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
        if os.path.exists(full_path):
            try:
                os.remove(full_path)
                flash(f'File for ID {clip_id} was successfully deleted.', 'success')
            except OSError as e:
                flash(f'Error deleting file: {e}', 'error')
                return redirect(url_for('admin_panel'))

    cursor.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
    db.commit()
    flash(f'Clip ID {clip_id} was successfully deleted from database.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/edit_key/<int:clip_id>', methods=['GET', 'POST'])
@local_access_only
def edit_key(clip_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT id, key, file_path, created_at, expires_at FROM clips WHERE id = ?", (clip_id,))
    clip = cursor.fetchone()
    
    if not clip:
        flash('Clip not found.', 'error')
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        new_key = request.form.get('key').strip()
        
        cursor.execute("SELECT key FROM clips WHERE id = ?", (clip_id,))
        current_key = cursor.fetchone()['key']
        
        if new_key != current_key:
            if not re.match(KEY_REGEX, new_key):
                flash('New key is invalid.', 'error')
                return redirect(url_for('edit_key', clip_id=clip_id))
            
            cursor.execute("SELECT 1 FROM clips WHERE key = ? AND id != ?", (new_key, clip_id))
            if cursor.fetchone():
                flash(f'❌ Error: Key **{new_key}** is already taken.', 'error')
                return redirect(url_for('edit_key', clip_id=clip_id))

        # Update key only
        cursor.execute(
            "UPDATE clips SET key = ? WHERE id = ?",
            (new_key, clip_id)
        )
        db.commit()
        flash(f'Key for Clip ID {clip_id} successfully updated to: {new_key}', 'success')
        return redirect(url_for('admin_panel'))
    
    return render_template('edit_key.html', clip=clip)

@app.route('/admin/edit_content/<int:clip_id>', methods=['GET', 'POST'])
@local_access_only
def edit_content(clip_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id, key, content, file_path FROM clips WHERE id = ?", (clip_id,))
    clip = cursor.fetchone()
    
    if not clip:
        flash('Clip not found.', 'error')
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        new_content = request.form.get('content')

        # Update content only
        cursor.execute(
            "UPDATE clips SET content = ? WHERE id = ?",
            (new_content, clip_id)
        )
        db.commit()
        flash(f'Content for Clip ID {clip_id} successfully updated.', 'success')
        return redirect(url_for('admin_panel'))
    
    return render_template('edit_content.html', clip=clip)


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=True)
PYEOF

# ============================================
# 4. Create index.html (English)
# ============================================
print_status "4/6: Creating index.html (English)..."
cat > "$INSTALL_DIR/templates/index.html" << 'HTM_INDEX'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Internet Clipboard</title><style>body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }.container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }textarea, input[type="file"], input[type="text"] { width: 95%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }input[type="submit"] { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }input[type="submit"]:hover { background-color: #0056b3; }.flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }</style></head><body><div class="container"><h2>Clipboard Server</h2><p>Share text, a local file, or a remote URL between devices.</p>
{% if flashed_messages %}
<ul style="list-style: none; padding: 0;">
{% for category, message in flashed_messages %}
    <li class="flash-{{ category }}">{{ message | safe }}</li>
{% endfor %}
</ul>
{% endif %}
<form method="POST" action="{{ url_for('create_clip') }}" enctype="multipart/form-data">
    <textarea name="content" rows="6" placeholder="Your content/text here">{{ old_data.get('content', '') }}</textarea>
    <p>— OR —</p>
    
    <div style="text-align: left; margin-bottom: 15px;">
        <label for="file">Upload Local File:</label>
        <input type="file" name="file" id="file" style="width: 100%; margin-top: 5px;">
    </div>

    <p>— OR —</p>

    <div style="text-align: left; margin-bottom: 15px;">
        <label for="remote_url">Remote File URL (will be downloaded to server):</label>
        <input type="text" name="remote_url" id="remote_url" placeholder="e.g., https://example.com/file.zip" value="{{ old_data.get('remote_url', '') }}" style="width: 100%; margin-top: 5px;">
    </div>

    <hr style="border: 1px dashed #ccc; margin: 15px 0;">
    
    <input type="text" name="custom_key" placeholder="Custom Key (Optional, e.g., MyProjectKey)" value="{{ old_data.get('custom_key', '') }}" pattern="^[a-zA-Z0-9_-]{3,64}$" title="Custom key must be 3-64 characters long and contain only letters, numbers, hyphen, or underscore.">
    <input type="submit" value="Create Link">
    <p style="font-size: 0.8em; color: #777;">If the custom key is empty, a random key will be generated.</p>
</form>
<p>Content/file will be automatically deleted after **{{ EXPIRY_DAYS }} days**.</p></div></body></html>
HTM_INDEX

# ============================================
# 5. Create clipboard.html (English)
# ============================================
print_status "5/6: Creating clipboard.html (English)..."
cat > "$INSTALL_DIR/templates/clipboard.html" << 'HTM_CLIPBOARD'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Clipboard - {{ key }}</title><style>body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }.container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; } .content-box { border: 1px solid #ccc; background-color: #eee; padding: 15px; margin-top: 15px; text-align: left; white-space: pre-wrap; word-wrap: break-word; border-radius: 4px; }a { color: #007bff; text-decoration: none; font-weight: bold; }a:hover { text-decoration: underline; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }.file-info { background-color: #e9f7fe; padding: 15px; border-radius: 4px; margin-top: 15px; text-align: left; }</style></head><body><div class="container"><h2>Clipboard: {{ key }}</h2>
{% with messages = get_flashed_messages(with_categories=true) %}
{% if messages %}
<ul style="list-style: none; padding: 0;">
{% for category, message in messages %}
    {% if category != 'form_data' %}
        <li class="flash-{{ category }}">{{ message | safe }}</li>
    {% endif %}
{% endfor %}
</ul>
{% endif %}
{% endwith %}
{% if clip is none %}<div class="flash-error">{% if expired %}❌ This link has expired and its content has been deleted.{% else %}❌ No content found at this address.{% endif %}</div><p><a href="{{ url_for('index') }}">Return to Home</a></p>{% else %}{% if file_path %}<div class="file-info"><h3>Attached File:</h3><p>Click below to download the file:</p><p><a href="{{ url_for('download_file', key=key) }}">Download File ({{ file_path.split('_', 1)[-1] }})</a></p></div>{% endif %}{% if content %}<h3>Text Content:</h3><div class="content-box">{{ content }}</div>{% endif %}<p style="margin-top: 20px;">⏱️ Remaining Expiry:<br>
    **{{ expiry_info_days }}** days, **{{ expiry_info_hours }}** hours, **{{ expiry_info_minutes }}** minutes</p><p><a href="{{ url_for('index') }}" style="margin-top: 20px; display: inline-block;">Create New Clip</a></p>
    
    <p style="margin-top: 20px; font-size: 0.8em; color: #999;">To access the Admin Panel, connect to the server via SSH and open <a href="http://127.0.0.1:{{ server_port }}/admin">http://127.0.0.1:{{ server_port }}/admin</a> in a local server browser (e.g., `lynx`).</p>
    
{% endif %}</div></body></html>
HTM_CLIPBOARD

# ============================================
# 6. Create Admin Templates (admin.html, edit_key.html, edit_content.html)
# ============================================
print_status "6/6: Creating admin templates (English & New Design)..."

# --- admin.html ---
cat > "$INSTALL_DIR/templates/admin.html" << 'HTM_ADMIN'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Admin Panel</title><style>
    body { font-family: Arial, sans-serif; background-color: #e9ebee; color: #333; padding: 20px; }
    .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
    h2 { text-align: center; color: #007bff; margin-bottom: 20px; }
    table { width: 100%; border-collapse: separate; border-spacing: 0 10px; margin-top: 20px; }
    th, td { padding: 12px 15px; text-align: left; vertical-align: middle; }
    thead th { background-color: #007bff; color: white; font-weight: bold; border-bottom: none; }
    tbody tr { background-color: #f9f9f9; border-radius: 8px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05); }
    tbody tr:hover { background-color: #f1f1f1; }
    a.button { display: inline-block; padding: 6px 12px; margin: 2px; text-decoration: none; color: white; border-radius: 4px; font-size: 0.9em; text-align: center; }
    a.view { background-color: #007bff; }
    a.edit-key { background-color: #ffc107; color: #333; }
    a.edit-content { background-color: #17a2b8; }
    form.delete-form { display: inline; }
    button.delete-btn { background-color: #dc3545; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 0.9em; transition: background-color 0.3s; }
    button.delete-btn:hover { background-color: #c82333; }
    span.file { background-color: #e9f7fe; padding: 3px 6px; border-radius: 3px; font-size: 0.85em; color: #0056b3; font-weight: bold; }
    .flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }
    .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }
    .stats { background-color: #f0f0f5; padding: 15px; border-radius: 6px; margin-bottom: 20px; text-align: left; }
    .stats p { margin: 5px 0; font-size: 1.1em; }
</style></head><body><div class="container">
    <h2>Clipboard Admin Panel</h2>
    <div class="stats">
        <p><b>Total Uploaded Size:</b> {{ total_size_mb }} MB</p>
        <p style="color: #777;">**Local Access Only:** This panel is only available via http://127.0.0.1:{{ server_port }}/admin</p>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
    <ul style="list-style: none; padding: 0;">
    {% for category, message in messages %}
        {% if category != 'form_data' %}
            <li class="flash-{{ category }}">{{ message | safe }}</li>
        {% endif %}
    {% endfor %}
    </ul>
    {% endif %}
    {% endwith %}

    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Key/Link</th>
                <th>Content Preview</th>
                <th>File</th>
                <th>Created At</th>
                <th>Expires At</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for clip in clips %}
            <tr>
                <td>{{ clip['id'] }}</td>
                <td>{{ clip['key'] }}</td>
                <td>{{ clip['content_preview'] }}{% if clip['content']|length > 50 %}...{% endif %}</td>
                <td>{% if clip['file_path'] %}<span class="file">{{ clip['file_path'].split('_', 1)[-1] }}</span>{% else %}N/A{% endif %}</td>
                <td>{{ clip['created_at'].split(' ')[0] }}</td>
                <td>{{ clip['expires_at'].split(' ')[0] }}</td>
                <td>
                    <a href="{{ url_for('view_clip', key=clip['key']) }}" class="button view" target="_blank">View</a>
                    <a href="{{ url_for('edit_key', clip_id=clip['id']) }}" class="button edit-key">Edit Key</a>
                    <a href="{{ url_for('edit_content', clip_id=clip['id']) }}" class="button edit-content">Edit Content</a>
                    <form class="delete-form" method="POST" action="{{ url_for('delete_clip', clip_id=clip['id']) }}" onsubmit="return confirm('Are you sure you want to delete clip ID {{ clip[\'id\'] }}? This action is irreversible.');">
                        <button type="submit" class="delete-btn">Delete</button>
                    </form>
                </td>
            </tr>
            {% else %}
            <tr>
                <td colspan="7" style="text-align: center; padding: 20px;">No clips currently stored in the database.</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <p style="margin-top: 20px;"><a href="{{ url_for('index') }}">← Return to Home</a></p>
</div></body></html>
HTM_ADMIN

# --- edit_key.html ---
cat > "$INSTALL_DIR/templates/edit_key.html" << 'HTM_EDIT_KEY'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Edit Key</title><style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }
    .container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 500px; margin: 0 auto; }
    input[type="text"] { width: 95%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    input[type="submit"] { background-color: #ffc107; color: #333; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }
    input[type="submit"]:hover { background-color: #e0a800; }
    .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }
    .info { background-color: #e9f7fe; padding: 10px; border-radius: 4px; margin-bottom: 15px; text-align: left; }
</style></head><body><div class="container">
    <h2>Edit Clip Key (ID: {{ clip['id'] }})</h2>
    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
    <ul style="list-style: none; padding: 0;">
    {% for category, message in messages %}
        {% if category != 'form_data' %}
            <li class="flash-{{ category }}">{{ message | safe }}</li>
        {% endif %}
    {% endfor %}
    </ul>
    {% endif %}
    {% endwith %}

    <div class="info">
        <p><b>Current Key:</b> {{ clip['key'] }}</p>
        <p><b>Expires:</b> {{ clip['expires_at'].split(' ')[0] }}</p>
        {% if clip['file_path'] %}<p><b>File:</b> {{ clip['file_path'].split('_', 1)[-1] }}</p>{% endif %}
    </div>

    <form method="POST" action="{{ url_for('edit_key', clip_id=clip['id']) }}">
        <label for="key" style="display: block; text-align: left; margin-top: 10px;">New Key/Address:</label>
        <input type="text" name="key" value="{{ clip['key'] }}" pattern="^[a-zA-Z0-9_-]{3,64}$" title="Must be 3-64 characters (letters, numbers, hyphen, underscore)." required>
        
        <input type="submit" value="Update Key">
    </form>
    <p style="margin-top: 20px;"><a href="{{ url_for('admin_panel') }}">← Return to Admin Panel</a></p>
</div></body></html>
HTM_EDIT_KEY

# --- edit_content.html ---
cat > "$INSTALL_DIR/templates/edit_content.html" << 'HTM_EDIT_CONTENT'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Edit Content</title><style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }
    .container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }
    textarea { width: 95%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    input[type="submit"] { background-color: #17a2b8; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }
    input[type="submit"]:hover { background-color: #138496; }
    .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }
    .info { background-color: #e9f7fe; padding: 10px; border-radius: 4px; margin-bottom: 15px; text-align: left; }
</style></head><body><div class="container">
    <h2>Edit Clip Content (ID: {{ clip['id'] }})</h2>
    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
    <ul style="list-style: none; padding: 0;">
    {% for category, message in messages %}
        {% if category != 'form_data' %}
            <li class="flash-{{ category }}">{{ message | safe }}</li>
        {% endif %}
    {% endfor %}
    </ul>
    {% endif %}
    {% endwith %}
    
    <div class="info">
        <p><b>Key:</b> {{ clip['key'] }}</p>
        {% if clip['file_path'] %}<p><b>File Attached:</b> {{ clip['file_path'].split('_', 1)[-1] }}</p>{% endif %}
    </div>

    <form method="POST" action="{{ url_for('edit_content', clip_id=clip['id']) }}">
        <label for="content" style="display: block; text-align: left; margin-top: 10px;">Text Content:</label>
        <textarea name="content" rows="10" placeholder="Your text content">{{ clip['content'] }}</textarea>
        
        <input type="submit" value="Update Content">
    </form>
    <p style="margin-top: 20px;"><a href="{{ url_for('admin_panel') }}">← Return to Admin Panel</a></p>
</div></body></html>
HTM_EDIT_CONTENT

# ============================================
# 7. Final Steps
# ============================================
print_status "7/7: Initializing Database and restarting service..."
$PYTHON_VENV_PATH -c "from app import init_db; init_db()"

cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Service
After=network.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
ExecStart=${GUNICORN_VENV_PATH} --workers 4 --bind 0.0.0.0:${PORT} app:app
Restart=always
TimeoutSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V10)"
echo "================================================"
echo "✅ Service Status: $(systemctl is-active clipboard.service)"
echo "🌐 Your server is running on port $PORT."
echo "------------------------------------------------"
echo "🛑 IMPORTANT: Admin Panel is Localhost Only."
echo "   To access the panel, use a text browser like 'lynx' or SSH tunneling."
echo "🔗 Admin Panel URL: http://127.0.0.1:${PORT}/admin"
echo "------------------------------------------------"
echo "To access from server SSH terminal:"
echo "   1. Install lynx: sudo apt install -y lynx"
echo "   2. Run: lynx http://127.0.0.1:${PORT}/admin"
echo "------------------------------------------------"
echo "Status:   sudo systemctl status clipboard.service"
echo "Restart:  sudo systemctl restart clipboard.service"
echo "Logs:     sudo journalctl -u clipboard.service -f"
echo "================================================"
