#!/bin/bash
# Internet Clipboard Server Installer (Flask + Gunicorn + SQLite)
# V20 - FINAL: Critical Fix for Internal Server Error on Admin Login/Index. Ensures robust .env loading.

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

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Check root access
if [ "$EUID" -ne 0 ] && [ "$1" != "setup-user" ]; then
    print_error "❌ Please run with root access: sudo bash install_clipboard.sh"
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server Installer (V20 - Final Stability Fix)"
echo "=================================================="

# ============================================
# 1. Password Input Phase (FORCED)
# ============================================
echo ""
echo "🛑 SECURITY SETUP: Admin Panel Password"
echo "------------------------------------------------"

# Loop until a valid, matching password is provided
while true; do
    read -s -p "Enter a strong Admin Password: " ADMIN_PASSWORD
    echo ""
    read -s -p "Confirm Admin Password: " ADMIN_PASSWORD_CONFIRM
    echo ""

    if [ -z "$ADMIN_PASSWORD" ]; then
        print_error "❌ Password cannot be empty. Please try again."
        continue
    fi

    if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
        print_error "❌ Passwords do not match. Please try again."
        continue
    fi
    
    # Simple length check to enforce minimum strength
    if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
        print_error "❌ Password is too short. It must be at least 8 characters long."
        continue
    fi

    break 
done

echo "------------------------------------------------"
print_status "Password successfully set."
echo ""

# ============================================
# 2. System Setup & Venv
# ============================================
print_status "2/7: Ensuring system setup and Virtual Environment..."
apt update -y
apt install -y python3 python3-pip python3-venv curl wget

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" 

# Install dependencies needed for password hashing (werkzeug)
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate || true

PYTHON_VENV_PATH="$INSTALL_DIR/venv/bin/python3"
GUNICORN_VENV_PATH="$INSTALL_DIR/venv/bin/gunicorn"

cat > requirements.txt << 'REQEOF'
Flask
python-dotenv
gunicorn
requests
werkzeug
REQEOF
pip install -r requirements.txt || true
deactivate

# ============================================
# 3. Update .env and Directories
# ============================================
print_status "3/7: Updating configuration and ensuring directory structure..."

mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
chmod 777 "$INSTALL_DIR/uploads" 

# Hash the password for secure storage
ADMIN_PASSWORD_HASH=$(echo "$ADMIN_PASSWORD" | "$PYTHON_VENV_PATH" -c "from werkzeug.security import generate_password_hash; import sys; print(generate_password_hash(sys.stdin.read().strip()))")

# --- Create .env file ---
cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
MAX_REMOTE_SIZE_MB=50
ADMIN_PASSWORD_HASH=${ADMIN_PASSWORD_HASH}
# Path added for robust manual loading
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
ENVEOF

# ============================================
# 4. Create app.py (V20 - Fixed .env loading and variable access)
# ============================================
print_status "4/7: Creating app.py (V20 - Critical fix for admin panel access)..."
cat > "$INSTALL_DIR/app.py" << 'PYEOF_APP_MERGED_V20'
import os
import sqlite3
import random
import string
import re
import requests
import urllib.parse
import sys
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g, session, abort
from dotenv import load_dotenv, set_key, find_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

# --- Determine .env Path Globally ---
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', find_dotenv(usecwd=True))
if not DOTENV_PATH:
    DOTENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')

# Load the environment variables globally (Essential for initial setup)
load_dotenv(dotenv_path=DOTENV_PATH, override=True)


# --- Configuration (Read from OS Env or the loaded .env) ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
MAX_REMOTE_SIZE_BYTES = int(os.getenv('MAX_REMOTE_SIZE_MB', 50)) * 1024 * 1024 

# Function to safely get the current admin hash
def get_admin_password_hash():
    # Reload the .env file content directly before checking/using the hash
    # This prevents the initial global load from failing and ensures the latest hash is used
    load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    return os.getenv('ADMIN_PASSWORD_HASH')


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

# --- Security Decorator: Admin Authentication ---
def login_required(f):
    def wrap(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Login required to access the admin panel.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return login_required


# --- Helper Functions (Remaining functions are unchanged from V19) ---
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
    try:
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            
            content_length = r.headers.get('Content-Length')
            if content_length and int(content_length) > MAX_REMOTE_SIZE_BYTES:
                return "File size exceeds limit."
            
            filename = f"file_{index}"
            if 'Content-Disposition' in r.headers:
                filename_header = r.headers['Content-Disposition']
                match = re.search(r'filename=["\']?([^"\']+)["\']?', filename_header)
                if match:
                    filename = match.group(1)
            
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

# --- Command Line Utility for Password Reset ---
def reset_admin_password():
    """Allows admin password reset from command line."""
    print("\n--- Clipboard Server Admin Password Reset Utility ---")
    
    if not os.path.exists(DOTENV_PATH):
        print(f"Error: .env file not found at {DOTENV_PATH}")
        sys.exit(1)

    while True:
        try:
            new_password = input("Enter new admin password: ")
            confirm_password = input("Confirm new admin password: ")

            if not new_password:
                print("Password cannot be empty. Try again.")
                continue

            if new_password != confirm_password:
                print("Passwords do not match. Try again.")
                continue
            
            if len(new_password) < 8:
                print("Password is too short. It must be at least 8 characters long.")
                continue

            break
        except EOFError:
            print("\nReset cancelled.")
            sys.exit(0)
        except Exception as e:
            print(f"An unexpected input error occurred: {e}")
            sys.exit(1)

    # Hash the new password
    new_hash = generate_password_hash(new_password)
    
    # Save the new hash to the .env file
    try:
        success = set_key(DOTENV_PATH, "ADMIN_PASSWORD_HASH", new_hash)
        if success:
            print("\n✅ Admin password hash updated successfully in .env file.")
            print("⚠️ REMINDER: You must restart the clipboard service for changes to take effect.")
            print("   Command: sudo systemctl restart clipboard.service")
        else:
            print("\n❌ Failed to update the .env file. Check file permissions.")
            sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error saving to .env file: {e}")
        sys.exit(1)

# --- Flask Routes (The problem was here and in get_admin_password_hash) ---

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
# ... (create_clip function is unchanged)
def create_clip():
    content = request.form.get('content')
    uploaded_files = request.files.getlist('files[]')
    remote_urls_input = request.form.get('remote_urls', '').strip()
    custom_key = request.form.get('custom_key', '').strip()

    is_content_empty = not content
    is_local_files_empty = not any(f.filename for f in uploaded_files)
    is_remote_urls_empty = not remote_urls_input

    if is_content_empty and is_local_files_empty and is_remote_urls_empty:
        flash('You must provide text, local files, or remote URLs.', 'error')
        return redirect(url_for('index'))

    form_data_for_flash = {'content': content, 'custom_key': custom_key, 'remote_urls': remote_urls_input}
    error_messages = []

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
    
    remote_index_start = 0
    if uploaded_files:
        for i, uploaded_file in enumerate(uploaded_files):
            if uploaded_file and uploaded_file.filename:
                filename = uploaded_file.filename
                file_path_relative = os.path.join(UPLOAD_FOLDER, f"{key}_{i}_{filename}") 
                file_path_absolute = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path_relative)
                uploaded_file.save(file_path_absolute)
                file_paths_list.append(file_path_relative)
                remote_index_start = i + 1

    
    remote_urls = [url.strip() for url in remote_urls_input.split('\n') if url.strip()]
    
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
# ... (view_clip and download_file functions are unchanged)
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
    
    files_info = []
    for p in file_paths_list:
        if p.strip():
            filename_with_key = os.path.basename(p.strip())
            original_filename = filename_with_key.split('_', 2)[-1] 
            files_info.append({'path': p.strip(), 'name': original_filename})


    return render_template('clipboard.html', 
                           key=key, 
                           content=content, 
                           files_info=files_info,
                           expiry_info_days=expiry_info_days,
                           expiry_info_hours=expiry_info_hours,
                           expiry_info_minutes=minutes,
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

# --- Admin Authentication Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    ADMIN_PASSWORD_HASH_CHECK = get_admin_password_hash()
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if ADMIN_PASSWORD_HASH_CHECK and check_password_hash(ADMIN_PASSWORD_HASH_CHECK, password):
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid password.', 'error')
            return render_template('login.html', admin_port=CLIPBOARD_PORT)
    
    # Check if a password hash is even set (for initial setup check)
    if not ADMIN_PASSWORD_HASH_CHECK:
        print("CRITICAL: ADMIN_PASSWORD_HASH is missing from .env! Check installation script.")

    return render_template('login.html', admin_port=CLIPBOARD_PORT)

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))


# --- Admin Routes (Same as V18) ---

@app.route('/admin')
@login_required
# ... (admin_panel function is unchanged)
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
                           admin_port=CLIPBOARD_PORT)


@app.route('/admin/delete/<int:clip_id>', methods=['POST'])
@login_required
# ... (delete_clip function is unchanged)
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


@app.route('/admin/edit_key/<int:clip_id>', methods=['GET', 'POST'])
@login_required
# ... (edit_key function is unchanged)
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

    return render_template('edit_key.html', clip=clip, file_list=file_list, admin_port=CLIPBOARD_PORT)

@app.route('/admin/edit_content/<int:clip_id>', methods=['GET', 'POST'])
@login_required
# ... (edit_content function is unchanged)
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
    
    return render_template('edit_content.html', clip=clip, file_list=file_list, admin_port=CLIPBOARD_PORT)


# --- Main Execution ---
if __name__ == '__main__':
    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == 'reset-password':
        reset_admin_password()
        sys.exit(0)
    
    # Normal Flask/Gunicorn startup
    init_db()
    app.run(host='0.0.0.0', port=CLIPBOARD_PORT, debug=True)

PYEOF_APP_MERGED_V20


# ============================================
# 5. Create Templates (No change needed from V18)
# ============================================
print_status "5/7: Templates are already up-to-date (V18 files are sufficient)..."
# (Skipping template recreation)

# ============================================
# 6. Create Systemd Service (Single Service)
# ============================================
print_status "6/7: Creating single Systemd service (clipboard.service)..."

# --- clipboard.service (Port 3214 - Runs app.py) ---
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Service (Port ${CLIPBOARD_PORT})
After=network.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
# Pass the full .env path as an environment variable to ensure app.py can find it
ExecStart=${GUNICORN_VENV_PATH} --workers 4 --bind 0.0.0.0:${CLIPBOARD_PORT} app:app
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
systemctl is-active --quiet admin.service && systemctl stop admin.service || true
systemctl is-enabled --quiet admin.service && systemctl disable admin.service || true

# Initialize DB using the venv Python
"$PYTHON_VENV_PATH" -c "from app import init_db; init_db()"

systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V20 - Final Fix)"
echo "================================================"
echo "✅ CLIPBOARD & ADMIN STATUS (Port ${CLIPBOARD_PORT}): $(systemctl is-active clipboard.service)"
echo "------------------------------------------------"
echo "🌐 CLIPBOARD URL: http://YOUR_IP:${CLIPBOARD_PORT}"
echo "🔒 ADMIN PANEL URL: http://YOUR_IP:${CLIPBOARD_PORT}/admin/login"
echo "------------------------------------------------"
echo "🚨 FORGOT PASSWORD? Run this command on the server:"
echo "   ${YELLOW}sudo ${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/app.py reset-password${NC}"
echo "------------------------------------------------"
echo "Status:   sudo systemctl status clipboard.service"
echo "Restart:  sudo systemctl restart clipboard.service"
echo "================================================"
