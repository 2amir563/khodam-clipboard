#!/bin/bash
# Internet Clipboard Server Installer (Flask + Gunicorn + SQLite)
# V7 - Final: Added remote file download via URL.

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
echo "📋 Internet Clipboard Server Installer (V7 - Remote URL Download)"
echo "=================================================="


# ============================================
# 1. System Setup & Venv (Adding 'requests' to requirements)
# ============================================
print_status "1/6: Installing essential tools and creating Virtual Environment (including requests)..."
apt update -y
apt install -y python3 python3-pip python3-venv curl wget

mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR" 

python3 -m venv venv || true 
source venv/bin/activate || true

PYTHON_VENV_PATH="$INSTALL_DIR/venv/bin/python3"
GUNICORN_VENV_PATH="$INSTALL_DIR/venv/bin/gunicorn"

# NOTE: Added 'requests' here
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
# Set maximum allowed download size from remote URL (e.g., 50MB)
MAX_REMOTE_SIZE_MB=50
ENVEOF

# ============================================
# 3. Create app.py (Modified for remote download logic)
# ============================================
print_status "3/6: Creating app.py (V7 - Remote Download Logic)..."
cat > "$INSTALL_DIR/app.py" << 'PYEOF'
import os
import sqlite3
import random
import string
import re
import requests
import urllib.parse
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g, get_flashed_messages
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

# --- Database Management (unchanged) ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
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

# --- Helper Functions (unchanged) ---
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


# --- Remote Download Helper ---
def download_remote_file(url, key):
    try:
        # Check file size before full download (using stream=True)
        with requests.get(url, stream=True, timeout=30) as r:
            r.raise_for_status()
            
            # Check content length (optional but recommended)
            content_length = r.headers.get('Content-Length')
            if content_length and int(content_length) > MAX_REMOTE_SIZE_BYTES:
                return "File size exceeds limit."
            
            # Extract filename from URL or Content-Disposition
            filename = ""
            if 'Content-Disposition' in r.headers:
                # Rudimentary filename extraction from Content-Disposition
                filename_header = r.headers['Content-Disposition']
                match = re.search(r'filename=["\']?([^"\']+)["\']?', filename_header)
                if match:
                    filename = match.group(1)
            
            if not filename:
                # Extract from URL path
                path = urllib.parse.urlparse(url).path
                filename = os.path.basename(path)
                # Fallback to a generic name if extraction fails
                if not filename or filename.count('.') < 1:
                    filename = "remote_file"
            
            # Ensure filename is safe and unique
            safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
            
            file_path_relative = os.path.join(UPLOAD_FOLDER, f"{key}_{safe_filename}")
            file_path_absolute = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path_relative)
            
            # Download file chunk by chunk
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
            
            return file_path_relative # Success
            
    except requests.exceptions.RequestException as e:
        return f"Error downloading file: {e}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"

# --- Routes ---

@app.route('/')
def index():
    cleanup_expired_clips()
    
    old_data = {}
    messages = get_flashed_messages(with_categories=True)
    display_messages = []
    
    for category, message in messages:
        if category == 'form_data':
            try:
                data = eval(message)
                if isinstance(data, dict):
                    old_data = data
            except:
                pass
        else:
            display_messages.append((category, message))
            
    return render_template('index.html', EXPIRY_DAYS=EXPIRY_DAYS, old_data=old_data, flashed_messages=display_messages)


@app.route('/create', methods=['POST'])
def create_clip():
    content = request.form.get('content')
    uploaded_file = request.files.get('file')
    remote_url = request.form.get('remote_url', '').strip()
    custom_key = request.form.get('custom_key', '').strip()

    # Priority check: ensure at least one data type is present
    if not content and (not uploaded_file or not uploaded_file.filename) and not remote_url:
        flash('شما باید متن، فایل محلی یا لینک خارجی ارائه دهید.', 'error')
        return redirect(url_for('index'))

    # Store current form data in flash message *before* potential error redirect
    form_data_for_flash = {'content': content, 'custom_key': custom_key, 'remote_url': remote_url}
    flash(str(form_data_for_flash), 'form_data') 

    # 1. Key determination and validation
    if custom_key:
        if not re.match(KEY_REGEX, custom_key):
            flash('لینک دلخواه باید فقط شامل حروف انگلیسی، اعداد، خط فاصله (-) یا زیرخط (_) باشد و طول آن بین 3 تا 64 کاراکتر باشد.', 'error')
            return redirect(url_for('index'))
            
        key = custom_key
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
        if cursor.fetchone():
            flash(f'❌ خطا: نام **{key}** قبلاً استفاده شده است. لطفاً نام دیگری انتخاب کنید.', 'error')
            return redirect(url_for('index'))
    else:
        key = generate_key()

    file_path = None
    
    # 2. Handle data/file upload
    if uploaded_file and uploaded_file.filename:
        # Local file upload
        filename = uploaded_file.filename
        file_path_relative = os.path.join(UPLOAD_FOLDER, f"{key}_{filename}")
        file_path_absolute = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path_relative)
        uploaded_file.save(file_path_absolute)
        file_path = file_path_relative
    
    elif remote_url:
        # Remote URL download
        if not remote_url.startswith(('http://', 'https://')):
            flash('لینک خارجی معتبر نیست (باید با http:// یا https:// شروع شود).', 'error')
            return redirect(url_for('index'))
            
        download_result = download_remote_file(remote_url, key)
        
        if download_result.startswith("Error") or download_result.startswith("File size"):
            flash(f'❌ خطای دانلود فایل: {download_result}', 'error')
            return redirect(url_for('index'))
        else:
            file_path = download_result # This is the relative file path

    # Check if a file was successfully uploaded/downloaded AND content is empty
    if not content and file_path:
        # If file is present but no text, set content to a placeholder
        content = f"File uploaded via link: {file_path.split('_', 1)[-1]}"

    # Check if we still don't have content or file_path (should be caught by initial check, but safety)
    if not content and not file_path:
        flash('شما باید محتوایی برای ذخیره داشته باشید.', 'error')
        return redirect(url_for('index'))
    
    # 3. Save to database
    expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key, content, file_path, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
        
        flash(f'✅ کلیپ‌بورد با موفقیت ایجاد شد! لینک: {url_for("view_clip", key=key, _external=True)}', 'success')
        return redirect(url_for('view_clip', key=key))
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash('❌ یک خطای داخلی هنگام ذخیره رخ داد.', 'error')
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
                           expiry_info_minutes=expiry_info_minutes)


@app.route('/download/<key>')
def download_file(key):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        flash('فایل یافت نشد یا لینک منقضی شده است.', 'error')
        return redirect(url_for('index'))

    file_path_relative, expires_at_str = clip
    
    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        cleanup_expired_clips()
        flash('فایل یافت نشد یا لینک منقضی شده است.', 'error')
        return redirect(url_for('index'))
    
    if file_path_relative:
        filename_with_key = os.path.basename(file_path_relative)
        original_filename = filename_with_key.split('_', 1)[-1] # Gets the part after the first underscore
        
        return send_from_directory(UPLOAD_FOLDER, 
                                   filename_with_key, 
                                   as_attachment=True, 
                                   download_name=original_filename)
    
    flash('فایلی برای این لینک وجود ندارد.', 'error')
    return redirect(url_for('view_clip', key=key))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=True)
PYEOF

# ============================================
# 4. Create index.html (Modified to include Remote URL field)
# ============================================
print_status "4/6: Creating index.html (V7 - Remote URL field)..."
cat > "$INSTALL_DIR/templates/index.html" << 'HTM_INDEX'
<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Internet Clipboard - کلیپ‌بورد اینترنتی</title><style>body { font-family: Tahoma, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }.container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }textarea, input[type="file"], input[type="text"] { width: 95%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }input[type="submit"] { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }input[type="submit"]:hover { background-color: #0056b3; }.flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; }</style></head><body><div class="container"><h2>Clipboard Server</h2><p>متن، فایل محلی یا لینک خارجی مورد نظر خود را برای انتقال بین دستگاه‌ها قرار دهید.</p>
{% if flashed_messages %}
<ul style="list-style: none; padding: 0;">
{% for category, message in flashed_messages %}
    <li class="flash-{{ category }}">{{ message | safe }}</li>
{% endfor %}
</ul>
{% endif %}
<form method="POST" action="{{ url_for('create_clip') }}" enctype="multipart/form-data">
    <textarea name="content" rows="6" placeholder="متن مورد نظر شما">{{ old_data.get('content', '') }}</textarea>
    <p>یا</p>
    
    <div style="text-align: right; margin-bottom: 15px;">
        <label for="file">فایل از کامپیوتر:</label>
        <input type="file" name="file" id="file" style="width: 100%; margin-top: 5px;">
    </div>

    <p>یا</p>

    <div style="text-align: right; margin-bottom: 15px;">
        <label for="remote_url">لینک خارجی فایل (Remote URL):</label>
        <input type="text" name="remote_url" id="remote_url" placeholder="مثلا: https://example.com/file.zip" value="{{ old_data.get('remote_url', '') }}" style="width: 100%; margin-top: 5px;">
    </div>

    <hr style="border: 1px dashed #ccc; margin: 15px 0;">
    
    <input type="text" name="custom_key" placeholder="لینک دلخواه (اختیاری، مثلا: MyProjectKey)" value="{{ old_data.get('custom_key', '') }}" pattern="^[a-zA-Z0-9_-]{3,64}$" title="لینک دلخواه باید بین 3 تا 64 کاراکتر بوده و شامل حروف انگلیسی، اعداد، خط فاصله یا زیرخط باشد.">
    <input type="submit" value="ایجاد لینک">
    <p style="font-size: 0.8em; color: #777;">اگر لینک دلخواه خالی باشد، یک لینک تصادفی ایجاد می‌شود.</p>
</form>
<p>فایل/متن به صورت خودکار پس از **{{ EXPIRY_DAYS }} روز** پاک خواهد شد.</p></div></body></html>
HTM_INDEX

# ============================================
# 5. Create clipboard.html (English Expiry)
# ============================================
print_status "5/6: Creating clipboard.html (V7 - English Expiry)..."
cat > "$INSTALL_DIR/templates/clipboard.html" << 'HTM_CLIPBOARD'
<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Clipboard - {{ key }}</title><style>body { font-family: Tahoma, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }.container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; } .content-box { border: 1px solid #ccc; background-color: #eee; padding: 15px; margin-top: 15px; text-align: right; white-space: pre-wrap; word-wrap: break-word; border-radius: 4px; }a { color: #007bff; text-decoration: none; font-weight: bold; }a:hover { text-decoration: underline; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; }.file-info { background-color: #e9f7fe; padding: 15px; border-radius: 4px; margin-top: 15px; }</style></head><body><div class="container"><h2>کلیپ‌بورد: {{ key }}</h2>
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
{% if clip is none %}<div class="flash-error">{% if expired %}❌ این لینک منقضی شده و محتوای آن پاک شده است.{% else %}❌ محتوایی با این آدرس یافت نشد.{% endif %}</div><p><a href="{{ url_for('index') }}">بازگشت به صفحه اصلی</a></p>{% else %}{% if file_path %}<div class="file-info"><h3>فایل ضمیمه:</h3><p>برای دانلود فایل زیر کلیک کنید:</p><p><a href="{{ url_for('download_file', key=key) }}">دانلود فایل ({{ file_path.split('_', 1)[-1] }})</a></p></div>{% endif %}{% if content %}<h3>محتوای متنی:</h3><div class="content-box">{{ content }}</div>{% endif %}<p style="margin-top: 20px;">⏱️ Remaining Expiry:<br>
    **{{ expiry_info_days }}** days, **{{ expiry_info_hours }}** hours, **{{ expiry_info_minutes }}** minutes</p><p><a href="{{ url_for('index') }}" style="margin-top: 20px; display: inline-block;">ایجاد یک کلیپ جدید</a></p>{% endif %}</div></body></html>
HTM_CLIPBOARD

# ============================================
# 6. Final Steps
# ============================================
print_status "6/6: Initializing Database and restarting service..."
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
echo "🎉 Installation Complete (Clipboard Server V7)"
echo "================================================"
echo "✅ Service Status: $(systemctl is-active clipboard.service)"
echo "🌐 Your Clipboard Server is running on port $PORT."
echo "------------------------------------------------"
echo "Status:   sudo systemctl status clipboard.service"
echo "Restart:  sudo systemctl restart clipboard.service"
echo "Logs:     sudo journalctl -u clipboard.service -f"
echo "================================================"
