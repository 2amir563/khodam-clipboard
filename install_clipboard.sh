#!/bin/bash
# Internet Clipboard Server Installer (Flask + Gunicorn + SQLite)
# V15 - FINAL: Separate Admin Port (3215) with Password Protection.

set -e

# --- Configuration ---
INSTALL_DIR="/opt/clipboard_server"
CLIPBOARD_PORT="3214"
ADMIN_PORT="3215" 
EXPIRY_DAYS="30"
SECRET_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32) 

# 🛑 1. SET YOUR ADMIN PASSWORD HERE (Required for V15)
ADMIN_PASSWORD="YOUR_SECURE_PASSWORD_HERE" # <--- MUST BE CHANGED!
# 🛑 ----------------------------------------------------

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

if [ "$ADMIN_PASSWORD" = "YOUR_SECURE_PASSWORD_HERE" ]; then
    print_error "❌ Please edit the install script and set a strong password for ADMIN_PASSWORD."
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server Installer (V15 - Separate Admin Port & Password)"
echo "=================================================="


# ============================================
# 1. System Setup & Venv
# ============================================
print_status "1/7: Ensuring system setup and Virtual Environment..."
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
werkzeug # For password hashing
REQEOF
pip install -r requirements.txt || true
deactivate

# ============================================
# 2. Update .env and Directories
# ============================================
print_status "2/7: Updating configuration and ensuring directory structure..."

mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
chmod 777 "$INSTALL_DIR/uploads" 

# Hash the password for secure storage
ADMIN_PASSWORD_HASH=$(python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('$ADMIN_PASSWORD'))")

# --- Create .env file ---
cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
ADMIN_PORT=${ADMIN_PORT}
MAX_REMOTE_SIZE_MB=50
ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
ENVEOF

# ============================================
# 3. Create app.py (Primary Service: 3214)
# ============================================
print_status "3/7: Creating app.py (Primary service)..."
cat > "$INSTALL_DIR/app.py" << 'PYEOF_APP'
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
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
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

# --- Helper Functions (copied from V14) ---
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


def download_remote_file(url, key_prefix, index):
    """Downloads a single remote file and returns its relative path or an error string."""
    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            
            content_length = r.headers.get('Content-Length')
            if content_length and int(content_length) > MAX_REMOTE_SIZE_BYTES:
                return "File size exceeds limit."
            
            # Try to get filename from headers
            filename = f"file_{index}"
            if 'Content-Disposition' in r.headers:
                filename_header = r.headers['Content-Disposition']
                match = re.search(r'filename=["\']?([^"\']+)["\']?', filename_header)
                if match:
                    filename = match.group(1)
            
            # Fallback to URL path
            if filename == f"file_{index}":
                path = urllib.parse.urlparse(url).path
                filename = os.path.basename(path)
                if not filename or filename.count('.') < 1:
                    filename = f"remote_file_{index}.bin" 
            
            safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
            
            file_path_relative = os.path.join(UPLOAD_FOLDER, f"{key_prefix}_{index}_{safe_filename}")
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
    # --- Simplified Create Clip Logic (V14) ---
    content = request.form.get('content')
    uploaded_file = request.files.get('file')
    remote_urls_input = request.form.get('remote_urls', '').strip()
    custom_key = request.form.get('custom_key', '').strip()

    is_content_empty = not content
    is_local_file_empty = (not uploaded_file or not uploaded_file.filename)
    is_remote_urls_empty = not remote_urls_input

    if is_content_empty and is_local_file_empty and is_remote_urls_empty:
        flash('You must provide text, a local file, or remote URLs.', 'error')
        return redirect(url_for('index'))

    form_data_for_flash = {'content': content, 'custom_key': custom_key, 'remote_urls': remote_urls_input}
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

    file_paths_list = []
    
    # 2. Handle single local file upload
    if uploaded_file and uploaded_file.filename:
        filename = uploaded_file.filename
        file_path_relative = os.path.join(UPLOAD_FOLDER, f"{key}_0_{filename}") 
        file_path_absolute = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path_relative)
        uploaded_file.save(file_path_absolute)
        file_paths_list.append(file_path_relative)
    
    # 3. Handle multiple remote URLs
    remote_urls = [url.strip() for url in remote_urls_input.split('\n') if url.strip()]
    remote_index_start = 1 if uploaded_file and uploaded_file.filename else 0
    
    if remote_urls:
        downloaded_count = 0
        for i, url in enumerate(remote_urls):
            if not url.startswith(('http://', 'https://')):
                error_messages.append(f'error:Remote URL #{i+1} is not valid (must start with http:// or https://): {url[:50]}...')
                continue
            
            download_index = remote_index_start + i
            download_result = download_remote_file(url, key, download_index)
            
            if download_result.startswith("Error") or download_result.startswith("File size"):
                error_messages.append(f'error:❌ File Download Error for URL #{i+1}: {download_result}')
            else:
                file_paths_list.append(download_result)
                downloaded_count += 1

    file_path_string = ','.join(file_paths_list)

    if error_messages:
        flash_args = "||".join([f'form_data:{str(form_data_for_flash)}'] + error_messages)
        return redirect(url_for('index', flash_messages=flash_args))

    if not content and file_paths_list:
        content = "Files attached:\n" + "\n".join([f"{os.path.basename(p).split('_', 2)[-1]}" for p in file_paths_list])

    if not content and not file_paths_list:
        error_messages.append('error:You must have content or a file to save.')
        flash_args = "||".join([f'form_data:{str(form_data_for_flash)}'] + error_messages)
        return redirect(url_for('index', flash_messages=flash_args))

    expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key, content, file_path_string, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
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
    
    expiry_info_days = days
    expiry_info_hours = hours
    expiry_info_minutes = minutes
    
    file_paths_list = file_path_string.split(',') if file_path_string else []
    
    # Prepare file info for display/download
    files_info = []
    for p in file_paths_list:
        if p.strip():
            filename_with_key = os.path.basename(p.strip())
            # We skip the key_prefix and index part
            original_filename = filename_with_key.split('_', 2)[-1] 
            files_info.append({'path': p.strip(), 'name': original_filename})


    return render_template('clipboard.html', 
                           key=key, 
                           content=content, 
                           files_info=files_info,
                           expiry_info_days=expiry_info_days,
                           expiry_info_hours=expiry_info_hours,
                           expiry_info_minutes=expiry_info_minutes,
                           server_port=CLIPBOARD_PORT)


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
    init_db()
    app.run(host='0.0.0.0', port=CLIPBOARD_PORT, debug=True)
PYEOF_APP

# ============================================
# 4. Create admin.py (Admin Service: 3215)
# ============================================
print_status "4/7: Creating admin.py (Admin service with password protection)..."
cat > "$INSTALL_DIR/admin.py" << 'PYEOF_ADMIN'
import os
import sqlite3
import re
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, g, session
from dotenv import load_dotenv
from werkzeug.security import check_password_hash

load_dotenv()

# --- Configuration ---
admin_app = Flask(__name__)
admin_app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
ADMIN_PORT = int(os.getenv('ADMIN_PORT', '3215')) 
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'

# --- Database Management ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row 
    return db

@admin_app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- Security Decorator: Admin Authentication ---
def login_required(f):
    def wrap(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Login required to access the admin panel.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

# --- Admin Authentication Routes ---

@admin_app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        password = request.form.get('password')
        if ADMIN_PASSWORD_HASH and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid password.', 'error')
            return render_template('login.html', admin_port=ADMIN_PORT)
    return render_template('login.html', admin_port=ADMIN_PORT)

@admin_app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))


# --- Admin Routes ---

@admin_app.route('/admin')
@login_required
def admin_panel():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, key, content, file_path, created_at, expires_at FROM clips ORDER BY created_at DESC")
    clips_db = cursor.fetchall()
    
    total_size = 0
    total_files = 0
    
    clips = []
    for clip in clips_db:
        file_list = []
        content_safe = clip['content'] if clip['content'] else "No text content"
        content_preview = content_safe[:50] + ('...' if len(content_safe) > 50 else '')

        if clip['file_path']:
            file_paths = [p.strip() for p in clip['file_path'].split(',') if p.strip()]
            for file_path in file_paths:
                 full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
                 
                 if os.path.exists(full_path):
                     try:
                         total_size += os.path.getsize(full_path)
                         total_files += 1
                         file_name = os.path.basename(file_path).split('_', 2)[-1]
                         file_list.append(file_name)
                     except:
                         continue
        
        clips.append({
            'id': clip['id'],
            'key': clip['key'],
            'content_preview': content_preview,
            'file_list': file_list,
            'created_at': clip['created_at'].split(' ')[0],
            'expires_at': clip['expires_at'].split(' ')[0],
        })

    total_size_mb = total_size / (1024 * 1024) if total_size > 0 else 0.0
    
    return render_template('admin.html', 
                           clips=clips, 
                           total_size_mb=f"{total_size_mb:.2f}", 
                           total_files=total_files, 
                           server_port=CLIPBOARD_PORT,
                           admin_port=ADMIN_PORT)


@admin_app.route('/admin/delete/<int:clip_id>', methods=['POST'])
@login_required
def delete_clip(clip_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT file_path FROM clips WHERE id = ?", (clip_id,))
    clip = cursor.fetchone()
    
    if clip and clip['file_path']:
        file_paths = [p.strip() for p in clip['file_path'].split(',') if p.strip()]
        for file_path in file_paths:
            full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
            if os.path.exists(full_path):
                try:
                    os.remove(full_path)
                    flash(f'File {file_path} successfully deleted.', 'success')
                except OSError as e:
                    flash(f'Error deleting file {file_path}: {e}', 'error')
                    return redirect(url_for('admin_panel'))

    cursor.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
    db.commit()
    flash(f'Clip ID {clip_id} was successfully deleted from database.', 'success')
    return redirect(url_for('admin_panel'))


@admin_app.route('/admin/edit_key/<int:clip_id>', methods=['GET', 'POST'])
@login_required
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

        cursor.execute(
            "UPDATE clips SET key = ? WHERE id = ?",
            (new_key, clip_id)
        )
        db.commit()
        flash(f'Key for Clip ID {clip_id} successfully updated to: {new_key}', 'success')
        return redirect(url_for('admin_panel'))
    
    file_paths_string = clip['file_path'] if clip['file_path'] else ""
    file_list = [os.path.basename(p.strip()).split('_', 2)[-1] for p in file_paths_string.split(',') if p.strip()]

    return render_template('edit_key.html', clip=clip, file_list=file_list, admin_port=ADMIN_PORT)

@admin_app.route('/admin/edit_content/<int:clip_id>', methods=['GET', 'POST'])
@login_required
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

        cursor.execute(
            "UPDATE clips SET content = ? WHERE id = ?",
            (new_content, clip_id)
        )
        db.commit()
        flash(f'Content for Clip ID {clip_id} successfully updated.', 'success')
        return redirect(url_for('admin_panel'))
    
    file_paths_string = clip['file_path'] if clip['file_path'] else ""
    file_list = [os.path.basename(p.strip()).split('_', 2)[-1] for p in file_paths_string.split(',') if p.strip()]
    
    return render_template('edit_content.html', clip=clip, file_list=file_list, admin_port=ADMIN_PORT)


if __name__ == '__main__':
    admin_app.run(host='0.0.0.0', port=ADMIN_PORT, debug=True)
PYEOF_ADMIN


# ============================================
# 5. Create Templates (Adding Login Page)
# ============================================
print_status "5/7: Creating/Updating Templates (Adding Login Page)..."

# --- login.html --- (New)
cat > "$INSTALL_DIR/templates/login.html" << 'HTM_LOGIN'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Admin Login</title><style>
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; color: #333; text-align: center; padding: 50px 10px; }
    .container { background: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); max-width: 400px; margin: 0 auto; }
    h2 { color: #dc3545; margin-bottom: 25px; }
    input[type="password"] { width: 95%; padding: 12px; margin-bottom: 20px; border: 1px solid #ced4da; border-radius: 6px; box-sizing: border-box; font-size: 1em; }
    input[type="submit"] { background-color: #dc3545; color: white; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background-color 0.3s; }
    input[type="submit"]:hover { background-color: #c82333; }
    .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 15px; border-radius: 5px; text-align: left; }
    .flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 15px; border-radius: 5px; text-align: left; }
    .port-info { font-size: 0.9em; color: #6c757d; margin-top: 15px; }
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" integrity="sha512-Fo3rlrZj/k7ujTnHg4C0UjCg6lK3T0B3l/4P7Q+E3pL6D7I2w7Jk1+xQ+K/7ZJ/5Y7c2P0G6Q5eR5jQ7zQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />
</head>
<body>
<div class="container">
    <h2><i class="fas fa-user-lock"></i> Admin Login (Port {{ admin_port }})</h2>
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

    <form method="POST" action="{{ url_for('admin_login') }}">
        <label for="password" style="display: block; text-align: left; margin-bottom: 5px; font-weight: bold;">Password:</label>
        <input type="password" name="password" required placeholder="Enter Admin Password">
        <input type="submit" value="Log In">
    </form>
    <p class="port-info">The clipboard content service runs on port **{{ admin_port - 1 }}**.</p>
</div>
</body>
</html>
HTM_LOGIN

# --- admin.html --- (Updated for logout)
cat > "$INSTALL_DIR/templates/admin.html" << 'HTM_ADMIN_GRAPHICAL'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Admin Panel</title><style>
    /* Global Styles */
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; color: #333; padding: 20px; }
    .container { max-width: 1300px; margin: 0 auto; background: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
    h2 { text-align: center; color: #007bff; margin-bottom: 30px; border-bottom: 2px solid #007bff; padding-bottom: 10px; }

    /* Stats Section */
    .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .stats-grid { display: flex; justify-content: space-around; gap: 20px; flex: 1; margin-right: 20px; }
    .stat-card { background: #e9ecef; border-radius: 8px; padding: 15px; flex: 1; min-width: 150px; text-align: center; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05); }
    .stat-card h3 { margin: 0 0 5px; color: #495057; font-size: 1em; }
    .stat-card p { font-size: 1.8em; font-weight: bold; color: #007bff; margin: 0; }
    
    .logout-btn { background-color: #dc3545; color: white; padding: 10px 15px; border: none; border-radius: 6px; cursor: pointer; text-decoration: none; font-weight: bold; }
    .logout-btn:hover { background-color: #c82333; }

    /* Table Styles */
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    thead th { background-color: #007bff; color: white; padding: 12px 15px; text-align: left; font-weight: bold; border: none; }
    tbody tr { border-bottom: 1px solid #dee2e6; transition: background-color 0.3s; }
    tbody tr:hover { background-color: #f1f1f1; }
    td { padding: 12px 15px; vertical-align: middle; font-size: 0.95em; }
    
    /* File Tags */
    span.file { background-color: #17a2b8; color: white; padding: 4px 8px; border-radius: 5px; font-size: 0.8em; font-weight: 500; margin-right: 5px; display: inline-block; margin-bottom: 5px; }
    
    /* Actions */
    .actions a, .actions button { 
        display: inline-block; 
        padding: 8px; 
        margin: 2px; 
        text-decoration: none; 
        color: white; 
        border-radius: 50%; 
        width: 30px; 
        height: 30px; 
        line-height: 14px; 
        text-align: center; 
        font-weight: bold;
        font-size: 1em;
        border: none;
        cursor: pointer;
        transition: background-color 0.3s, transform 0.2s;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    .actions a:hover, .actions button:hover { transform: scale(1.1); }
    
    a.view { background-color: #28a745; } 
    a.edit-key { background-color: #ffc107; color: #333; } 
    a.edit-content { background-color: #17a2b8; } 
    button.delete-btn { background-color: #dc3545; } 
    form.delete-form { display: inline; }
    
    /* Flash Messages */
    .flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 5px; text-align: left; }
    .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 5px; text-align: left; }
    
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" integrity="sha512-Fo3rlrZj/k7ujTnHg4C0UjCg6lK3T0B3l/4P7Q+E3pL6D7I2w7Jk1+xQ+K/7ZJ/5Y7c2P0G6Q5eR5jQ7zQ==" crossorigin="anonymous" referrerpolicy="no-referrer" /></head>
<body>
<div class="container">
    <h2><i class="fas fa-clipboard-list"></i> Clipboard Admin Panel (Port {{ admin_port }})</h2>
    
    <div class="header-bar">
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Clips</h3>
                <p>{{ clips|length }}</p>
            </div>
            <div class="stat-card">
                <h3>Total Files</h3>
                <p>{{ total_files }}</p>
            </div>
            <div class="stat-card">
                <h3>Total Size</h3>
                <p>{{ total_size_mb }} MB</p>
            </div>
        </div>
        <a href="{{ url_for('admin_logout') }}" class="logout-btn"><i class="fas fa-sign-out-alt"></i> Logout</a>
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
                <th>Files ({{ total_files }})</th>
                <th>Created At</th>
                <th>Expires At</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for clip in clips %}
            <tr>
                <td>{{ clip['id'] }}</td>
                <td><a href="http://{{ request.host.split(':')[0] }}:{{ server_port }}/{{ clip['key'] }}" target="_blank" title="Go to Clip">{{ clip['key'] }}</a></td>
                <td>{{ clip['content_preview'] }}</td>
                <td>{% if clip['file_list'] %}{% for file_name in clip['file_list'] %}<span class="file" title="{{ file_name }}">{{ file_name[:20] }}{% if file_name|length > 20 %}...{% endif %}</span>{% endfor %}{% else %}N/A{% endif %}</td>
                <td>{{ clip['created_at'] }}</td>
                <td>{{ clip['expires_at'] }}</td>
                <td class="actions">
                    <a href="http://{{ request.host.split(':')[0] }}:{{ server_port }}/{{ clip['key'] }}" class="view" target="_blank" title="View Clip"><i class="fas fa-eye"></i></a>
                    <a href="{{ url_for('edit_key', clip_id=clip['id']) }}" class="edit-key" title="Edit Key"><i class="fas fa-key"></i></a>
                    <a href="{{ url_for('edit_content', clip_id=clip['id']) }}" class="edit-content" title="Edit Content"><i class="fas fa-edit"></i></a>
                    <form class="delete-form" method="POST" action="{{ url_for('delete_clip', clip_id=clip['id']) }}" onsubmit="return confirm('Are you sure you want to delete clip ID {{ clip[\'id\'] }}? This action is irreversible.');">
                        <button type="submit" class="delete-btn" title="Delete Clip"><i class="fas fa-trash-alt"></i></button>
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

    <p style="margin-top: 20px;"><a href="http://{{ request.host.split(':')[0] }}:{{ server_port }}/"><i class="fas fa-home"></i> Return to Main Clipboard (Port {{ server_port }})</a></p>
</div>
</body>
</html>
HTM_ADMIN_GRAPHICAL

# --- index.html, clipboard.html, edit_key.html, edit_content.html (No Change needed, uses relative paths or old ports)
# We reuse V14 templates for these, ensuring admin related links point to the correct port (3215) where applicable in admin.py.
# The previous version's templates are already correct for the primary service.

# ============================================
# 6. Create Systemd Services (Two Separate Services)
# ============================================
print_status "6/7: Creating two separate Systemd services (clipboard.service and admin.service)..."

# --- clipboard.service (Port 3214) ---
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Service (Port ${CLIPBOARD_PORT})
After=network.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
ExecStart=${GUNICORN_VENV_PATH} --workers 4 --bind 0.0.0.0:${CLIPBOARD_PORT} app:app
Restart=always
TimeoutSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF

# --- admin.service (Port 3215) ---
cat > /etc/systemd/system/admin.service << SERVICEEOF
[Unit]
Description=Flask Admin Service (Port ${ADMIN_PORT})
After=network.target clipboard.service

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
ExecStart=${GUNICORN_VENV_PATH} --workers 2 --bind 0.0.0.0:${ADMIN_PORT} admin:admin_app
Restart=always
TimeoutSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF


# ============================================
# 7. Final Steps
# ============================================
print_status "7/7: Initializing Database and starting services..."
$PYTHON_VENV_PATH -c "from app import init_db; init_db()"

systemctl daemon-reload
systemctl enable clipboard.service
systemctl enable admin.service

# Stop previous service if running under old name
systemctl is-active --quiet clipboard.service.old && systemctl stop clipboard.service.old || true
systemctl is-enabled --quiet clipboard.service.old && systemctl disable clipboard.service.old || true

systemctl restart clipboard.service
systemctl restart admin.service

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V15)"
echo "================================================"
echo "✅ CLIPBOARD STATUS (Port ${CLIPBOARD_PORT}): $(systemctl is-active clipboard.service)"
echo "✅ ADMIN STATUS (Port ${ADMIN_PORT}): $(systemctl is-active admin.service)"
echo "------------------------------------------------"
echo "🌐 CLIPBOARD URL: http://YOUR_IP:${CLIPBOARD_PORT}"
echo "🔒 ADMIN PANEL URL: http://YOUR_IP:${ADMIN_PORT}/admin"
echo "🔑 ADMIN PASSWORD: ${ADMIN_PASSWORD}"
echo "------------------------------------------------"
echo "Status:   sudo systemctl status clipboard.service admin.service"
echo "Restart:  sudo systemctl restart clipboard.service admin.service"
echo "================================================"
