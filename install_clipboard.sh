#!/bin/bash
# Internet Clipboard Server Installer (Flask + Gunicorn + SQLite)
# V18 - FINAL: Multiple Local File Uploads + Merged Admin Panel (Port 3214) + Forced Password Input + Reset Utility.

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
if [ "$EUID" -ne 0 ]; then
    print_error "❌ Please run with root access: sudo bash install_clipboard.sh"
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server Installer (V18 - Merged Admin on Port ${CLIPBOARD_PORT})"
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
ENVEOF

# ============================================
# 4. Create app.py (Now includes Reset functionality)
# ============================================
print_status "4/7: Creating app.py (Including Admin logic, Multi-File, and Reset functionality)..."
cat > "$INSTALL_DIR/app.py" << 'PYEOF_APP_MERGED_V18'
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

# Load environment variables early
load_dotenv()

# --- Configuration ---
app = Flask(__name__)
# Use absolute path for environment file
DOTENV_PATH = find_dotenv(usecwd=True)
if not DOTENV_PATH:
    # Fallback to current directory if find_dotenv fails
    DOTENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')

app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
MAX_REMOTE_SIZE_BYTES = int(os.getenv('MAX_REMOTE_SIZE_MB', 50)) * 1024 * 1024 
ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')

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
    # ... (Download logic remains the same as V17)
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
    
    # Check if we are running in the correct environment/directory
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

# --- Flask Routes (Same as V17) ---

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
    if request.method == 'POST':
        password = request.form.get('password')
        
        # Reload hash in case of command line reset
        load_dotenv(override=True)
        ADMIN_PASSWORD_HASH = os.getenv('ADMIN_PASSWORD_HASH')

        if ADMIN_PASSWORD_HASH and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid password.', 'error')
            return render_template('login.html', admin_port=CLIPBOARD_PORT)
    return render_template('login.html', admin_port=CLIPBOARD_PORT)

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('admin_login'))


# --- Admin Routes (Same as V17) ---

@app.route('/admin')
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
                           admin_port=CLIPBOARD_PORT)


@app.route('/admin/delete/<int:clip_id>', methods=['POST'])
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


@app.route('/admin/edit_key/<int:clip_id>', methods=['GET', 'POST'])
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

    return render_template('edit_key.html', clip=clip, file_list=file_list, admin_port=CLIPBOARD_PORT)

@app.route('/admin/edit_content/<int:clip_id>', methods=['GET', 'POST'])
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

PYEOF_APP_MERGED_V18


# ============================================
# 5. Create Templates (No change needed from V17)
# ============================================
print_status "5/7: Templates are already up-to-date (V17 files are sufficient)..."
# The HTML templates (index.html, admin.html, login.html, etc.) from V17 are reused 
# as the password reset logic is handled via the command line utility in app.py.

# (Re-creating templates to ensure clean installation in case of manual deletion)
# --- index.html (Updated for multiple file input) ---
cat > "$INSTALL_DIR/templates/index.html" << 'HTM_INDEX_MULTI'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Internet Clipboard</title><style>body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }.container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }textarea, input[type="file"], input[type="text"] { width: 95%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }input[type="submit"] { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }input[type="submit"]:hover { background-color: #0056b3; }.flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }</style></head><body><div class="container"><h2>Clipboard Server</h2><p>Share text, local files, or remote file URLs between devices.</p>
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
        <label for="files[]">Upload Multiple Local Files:</label>
        <input type="file" name="files[]" id="files[]" multiple style="width: 100%; margin-top: 5px;"> 
    </div>

    <p>— OR —</p>

    <div style="text-align: left; margin-bottom: 15px;">
        <label for="remote_urls">Multiple Remote File URLs (one URL per line, will be downloaded to server):</label>
        <textarea name="remote_urls" id="remote_urls" rows="4" placeholder="e.g.,
https://example.com/file1.zip
https://another.com/image.jpg
">{{ old_data.get('remote_urls', '') }}</textarea>
    </div>

    <hr style="border: 1px dashed #ccc; margin: 15px 0;">
    
    <input type="text" name="custom_key" placeholder="Custom Key (Optional, e.g., MyProjectKey)" value="{{ old_data.get('custom_key', '') }}" pattern="^[a-zA-Z0-9_-]{3,64}$" title="Custom key must be 3-64 characters long and contain only letters, numbers, hyphen, or underscore.">
    <input type="submit" value="Create Link">
    <p style="font-size: 0.8em; color: #777;">If the custom key is empty, a random key will be generated.</p>
</form>
<p>Content/file will be automatically deleted after **{{ EXPIRY_DAYS }} days**.</p></div></body></html>
HTM_INDEX_MULTI

# --- login.html ---
cat > "$INSTALL_DIR/templates/login.html" << 'HTM_LOGIN_MERGED'
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
    <p class="port-info">The clipboard service runs on the same port.</p>
</div>
</body>
</html>
HTM_LOGIN_MERGED

# --- admin.html ---
cat > "$INSTALL_DIR/templates/admin.html" << 'HTM_ADMIN_GRAPHICAL_MERGED'
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

    <p style="margin-top: 20px;"><a href="{{ url_for('index') }}"><i class="fas fa-home"></i> Return to Main Clipboard (Port {{ server_port }})</a></p>
</div>
</body>
</html>
HTM_ADMIN_GRAPHICAL_MERGED

# --- clipboard.html ---
cat > "$INSTALL_DIR/templates/clipboard.html" << 'HTM_CLIPBOARD_MERGED_2'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Clipboard - {{ key }}</title><style>body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }.container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; } .content-box { border: 1px solid #ccc; background-color: #eee; padding: 15px; margin-top: 15px; text-align: left; white-space: pre-wrap; word-wrap: break-word; border-radius: 4px; }a { color: #007bff; text-decoration: none; font-weight: bold; }a:hover { text-decoration: underline; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: left; }.file-info { background-color: #e9f7fe; padding: 15px; border-radius: 4px; margin-top: 15px; text-align: left; }
.file-list { list-style: none; padding: 0; }
.file-list li { margin-bottom: 8px; }
</style></head><body><div class="container"><h2>Clipboard: {{ key }}</h2>
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
{% if clip is none %}<div class="flash-error">{% if expired %}❌ This link has expired and its content has been deleted.{% else %}❌ No content found at this address.{% endif %}</div><p><a href="{{ url_for('index') }}">Return to Home</a></p>{% else %}{% if files_info %}<div class="file-info"><h3>Attached Files:</h3><ul class="file-list">{% for file in files_info %}<li><a href="{{ url_for('download_file', file_path=file['path']) }}">Download File: {{ file['name'] }}</a></li>{% endfor %}</ul></div>{% endif %}{% if content %}<h3>Text Content:</h3><div class="content-box">{{ content }}</div>{% endif %}<p style="margin-top: 20px;">⏱️ Remaining Expiry:<br>
    **{{ expiry_info_days }}** days, **{{ expiry_info_hours }}** hours, **{{ expiry_info_minutes }}** minutes</p><p><a href="{{ url_for('index') }}" style="margin-top: 20px; display: inline-block;">Create New Clip</a></p>
{% endif %}</div></body></html>
HTM_CLIPBOARD_MERGED_2

# --- edit_key.html ---
cat > "$INSTALL_DIR/templates/edit_key.html" << 'HTM_EDIT_KEY_MERGED'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Edit Key</title><style>
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; color: #333; text-align: center; padding: 50px 10px; }
    .container { background: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); max-width: 500px; margin: 0 auto; }
    h2 { color: #ffc107; margin-bottom: 20px; }
    input[type="text"] { width: 95%; padding: 12px; margin-bottom: 20px; border: 1px solid #ced4da; border-radius: 6px; box-sizing: border-box; font-size: 1em; }
    input[type="submit"] { background-color: #ffc107; color: #333; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background-color 0.3s; }
    input[type="submit"]:hover { background-color: #e0a800; }
    .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 15px; border-radius: 5px; text-align: left; }
    .info { background-color: #e9f7fe; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: left; border-left: 5px solid #007bff; }
    .info p { margin: 5px 0; }
    span.file { background-color: #17a2b8; color: white; padding: 4px 8px; border-radius: 5px; font-size: 0.8em; font-weight: 500; margin-right: 5px; display: inline-block; margin-top: 5px;}
    .back-link { display: block; margin-top: 20px; color: #007bff; text-decoration: none; font-weight: bold; }
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" integrity="sha512-Fo3rlrZj/k7ujTnHg4C0UjCg6lK3T0B3l/4P7Q+E3pL6D7I2w7Jk1+xQ+K/7ZJ/5Y7c2P0G6Q5eR5jQ7zQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />
</head>
<body>
<div class="container">
    <h2><i class="fas fa-key"></i> Edit Clip Key (ID: {{ clip['id'] }})</h2>
    {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
    <ul style="list-style: none; padding: 0;">
    {% for category, message in messages %}
        {% if category != 'form_data' %}
            <li class="flash-{{ category }}">{{ message | safe }}</li>
        {% endif }
    {% endfor %}
    </ul>
    {% endif %}
    {% endwith %}

    <div class="info">
        <p><i class="fas fa-link"></i> <b>Current Key:</b> {{ clip['key'] }}</p>
        <p><i class="fas fa-calendar-times"></i> <b>Expires:</b> {{ clip['expires_at'].split(' ')[0] }}</p>
        <p><i class="fas fa-file-alt"></i> <b>Files:</b> {% if file_list %}{% for file_name in file_list %}<span class="file">{{ file_name }}</span>{% endfor %}{% else %}N/A{% endif %}</p>
    </div>

    <form method="POST" action="{{ url_for('edit_key', clip_id=clip['id']) }}">
        <label for="key" style="display: block; text-align: left; margin-bottom: 5px; font-weight: bold;">New Key/Address:</label>
        <input type="text" name="key" value="{{ clip['key'] }}" pattern="^[a-zA-Z0-9_-]{3,64}$" title="Must be 3-64 characters (letters, numbers, hyphen, underscore)." required>
        
        <input type="submit" value="Update Key">
    </form>
    <a href="{{ url_for('admin_panel') }}" class="back-link">← Return to Admin Panel</a>
</div>
</body>
</html>
HTM_EDIT_KEY_MERGED

# --- edit_content.html ---
cat > "$INSTALL_DIR/templates/edit_content.html" << 'HTM_EDIT_CONTENT_MERGED'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Edit Content</title><style>
    body { font-family: Arial, sans-serif; background-color: #f8f9fa; color: #333; text-align: center; padding: 50px 10px; }
    .container { background: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }
    h2 { color: #17a2b8; margin-bottom: 20px; }
    textarea { width: 95%; padding: 12px; margin-bottom: 20px; border: 1px solid #ced4da; border-radius: 6px; box-sizing: border-box; font-size: 1em; }
    input[type="submit"] { background-color: #17a2b8; color: white; padding: 12px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background-color 0.3s; }
    input[type="submit"]:hover { background-color: #138496; }
    .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 15px; border-radius: 5px; text-align: left; }
    .info { background-color: #e9f7fe; padding: 15px; border-radius: 8px; margin-bottom: 20px; text-align: left; border-left: 5px solid #007bff; }
    .info p { margin: 5px 0; }
    span.file { background-color: #17a2b8; color: white; padding: 4px 8px; border-radius: 5px; font-size: 0.8em; font-weight: 500; margin-right: 5px; display: inline-block; margin-top: 5px;}
    .back-link { display: block; margin-top: 20px; color: #007bff; text-decoration: none; font-weight: bold; }
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" integrity="sha512-Fo3rlrZj/k7ujTnHg4C0UjCg6lK3T0B3l/4P7Q+E3pL6D7I2w7Jk1+xQ+K/7ZJ/5Y7c2P0G6Q5eR5jQ7zQ==" crossorigin="anonymous" referrerpolicy="no-referrer" />
</head>
<body>
<div class="container">
    <h2><i class="fas fa-edit"></i> Edit Clip Content (ID: {{ clip['id'] }})</h2>
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
        <p><i class="fas fa-link"></i> <b>Key:</b> {{ clip['key'] }}</p>
        <p><i class="fas fa-file-alt"></i> <b>Files:</b> {% if file_list %}{% for file_name in file_list %}<span class="file">{{ file_name }}</span>{% endfor %}{% else %}N/A{% endif %}</p>
    </div>

    <form method="POST" action="{{ url_for('edit_content', clip_id=clip['id']) }}">
        <label for="content" style="display: block; text-align: left; margin-bottom: 5px; font-weight: bold;">Text Content:</label>
        <textarea name="content" rows="10" placeholder="Your text content">{{ clip['content'] }}</textarea>
        
        <input type="submit" value="Update Content">
    </form>
    <a href="{{ url_for('admin_panel') }}" class="back-link">← Return to Admin Panel</a>
</div>
</body>
</html>
HTM_EDIT_CONTENT_MERGED

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
ExecStart=${GUNICORN_VENV_PATH} --workers 4 --bind 0.0.0.0:${CLIPBOARD_PORT} app:app
# Use ExecStartPost to clean up temp files if necessary, or rely on internal cleanup
Restart=always
TimeoutSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF


# ============================================
# 7. Final Steps
# ============================================
print_status "7/7: Initializing Database and starting service..."
# Disable and stop the old separate admin service if it exists
systemctl is-active --quiet admin.service && systemctl stop admin.service || true
systemctl is-enabled --quiet admin.service && systemctl disable admin.service || true

# Initialize DB using the venv Python
"$PYTHON_VENV_PATH" -c "from app import init_db; init_db()"

systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server V18)"
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
