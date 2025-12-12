#!/bin/bash
# Internet Clipboard Server Installer (Flask + Gunicorn + SQLite)
# V9 - Final: Added Admin Panel accessible ONLY from localhost (No password needed locally).

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
echo "📋 Internet Clipboard Server Installer (V9 - Local Admin Panel)"
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

# --- Create .env file (Admin password removed, Local access only) ---
cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
PORT=${PORT}
MAX_REMOTE_SIZE_MB=50
# Note: Admin access is now restricted to localhost (127.0.0.1) only, no password needed.
ENVEOF

# ============================================
# 3. Create app.py (V9 - Local Access Only Logic)
# ============================================
print_status "3/6: Creating app.py (V9 - Local Access Only Logic)..."
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
        db.row_factory = sqlite3.Row # Allows accessing columns by name
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
    wrap.__name__ = f.__name__ # Needed for flask routing
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
    
    # Process flash messages stored as query parameters on redirect
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
                continue # Skip malformed messages
            
    # Fallback for standard flash if needed (though redirect with args is used for form data continuity)
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
        flash('شما باید متن، فایل محلی یا لینک خارجی ارائه دهید.', 'error')
        return redirect(url_for('index'))

    # Prepare data for potential redirect
    form_data_for_flash = {'content': content, 'custom_key': custom_key, 'remote_url': remote_url}
    error_messages = []

    # 1. Key determination and validation
    key = None
    if custom_key:
        if not re.match(KEY_REGEX, custom_key):
            error_messages.append('error:لینک دلخواه باید فقط شامل حروف انگلیسی، اعداد، خط فاصله (-) یا زیرخط (_) باشد و طول آن بین 3 تا 64 کاراکتر باشد.')
            
        else:
            key = custom_key
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
            if cursor.fetchone():
                error_messages.append(f'error:❌ خطا: نام **{key}** قبلاً استفاده شده است. لطفاً نام دیگری انتخاب کنید.')
    
    if error_messages:
        # If there are key validation/collision errors, redirect back with form data
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
            error_messages.append('error:لینک خارجی معتبر نیست (باید با http:// یا https:// شروع شود).')
        else:
            download_result = download_remote_file(remote_url, key)
            
            if download_result.startswith("Error") or download_result.startswith("File size"):
                error_messages.append(f'error:❌ خطای دانلود فایل: {download_result}')
            else:
                file_path = download_result 

    if error_messages:
        # If there are file/download errors, redirect back with form data
        flash_args = "||".join([f'form_data:{str(form_data_for_flash)}'] + error_messages)
        return redirect(url_for('index', flash_messages=flash_args))

    if not content and file_path:
        content = f"File uploaded via link: {file_path.split('_', 1)[-1]}"

    if not content and not file_path:
        # Should be caught by initial check, but safety check
        error_messages.append('error:شما باید محتوایی برای ذخیره داشته باشید.')
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
        
        # Success, no need to pass form data back
        flash(f'✅ کلیپ‌بورد با موفقیت ایجاد شد! لینک: {url_for("view_clip", key=key, _external=True)}', 'success')
        return redirect(url_for('view_clip', key=key))
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash('❌ یک خطای داخلی هنگام ذخیره رخ داد.', 'error')
        return redirect(url_for('index'))


@app.route('/<key>')
def view_clip(key):
    # ... (View logic remains the same)
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
    # ... (Download logic remains the same)
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
        original_filename = filename_with_key.split('_', 1)[-1] 
        
        return send_from_directory(UPLOAD_FOLDER, 
                                   filename_with_key, 
                                   as_attachment=True, 
                                   download_name=original_filename)
    
    flash('فایلی برای این لینک وجود ندارد.', 'error')
    return redirect(url_for('view_clip', key=key))


# --- Admin Routes (Restricted to Localhost) ---

@app.route('/admin')
@local_access_only
def admin_panel():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, key, SUBSTR(content, 1, 50) as content_preview, file_path, created_at, expires_at FROM clips ORDER BY created_at DESC")
    clips = cursor.fetchall()
    
    # Calculate total uploaded file size
    total_size = 0
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), UPLOAD_FOLDER)
    for root, dirs, files in os.walk(upload_dir):
        for name in files:
            full_path = os.path.join(root, name)
            if os.path.exists(full_path):
                 total_size += os.path.getsize(full_path)
            
    # Format size in MB
    total_size_mb = total_size / (1024 * 1024) 
    
    return render_template('admin.html', clips=clips, total_size_mb=f"{total_size_mb:.2f}", server_port=PORT)


@app.route('/admin/delete/<int:clip_id>', methods=['POST'])
@local_access_only
def delete_clip(clip_id):
    db = get_db()
    cursor = db.cursor()

    # 1. Find the file path
    cursor.execute("SELECT file_path FROM clips WHERE id = ?", (clip_id,))
    clip = cursor.fetchone()
    
    if clip and clip['file_path']:
        file_path = clip['file_path']
        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
        if os.path.exists(full_path):
            try:
                os.remove(full_path)
                flash(f'فایل مربوط به ID {clip_id} حذف شد.', 'success')
            except OSError as e:
                flash(f'خطا در حذف فایل: {e}', 'error')
                return redirect(url_for('admin_panel'))

    # 2. Delete the database record
    cursor.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
    db.commit()
    flash(f'کلیپ با ID {clip_id} از دیتابیس حذف شد.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/edit/<int:clip_id>', methods=['GET', 'POST'])
@local_access_only
def edit_clip(clip_id):
    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        new_content = request.form.get('content')
        new_key = request.form.get('key').strip()
        
        # Check if new key already exists and is different from current clip's key
        cursor.execute("SELECT key FROM clips WHERE id = ?", (clip_id,))
        current_key = cursor.fetchone()['key']
        
        if new_key != current_key:
            if not re.match(KEY_REGEX, new_key):
                flash('لینک جدید معتبر نیست.', 'error')
                return redirect(url_for('edit_clip', clip_id=clip_id))
            
            cursor.execute("SELECT 1 FROM clips WHERE key = ? AND id != ?", (new_key, clip_id))
            if cursor.fetchone():
                flash(f'❌ خطا: نام **{new_key}** قبلاً استفاده شده است.', 'error')
                return redirect(url_for('edit_clip', clip_id=clip_id))

        # Update database
        cursor.execute(
            "UPDATE clips SET content = ?, key = ? WHERE id = ?",
            (new_content, new_key, clip_id)
        )
        db.commit()
        flash(f'کلیپ با ID {clip_id} با موفقیت ویرایش شد. لینک جدید: {new_key}', 'success')
        return redirect(url_for('admin_panel'))
    
    else: # GET request
        cursor.execute("SELECT id, key, content, file_path, created_at, expires_at FROM clips WHERE id = ?", (clip_id,))
        clip = cursor.fetchone()
        
        if not clip:
            flash('کلیپ مورد نظر یافت نشد.', 'error')
            return redirect(url_for('admin_panel'))
            
        return render_template('edit_clip.html', clip=clip)


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=True)
PYEOF

# ============================================
# 4. Create index.html (Adjusted to handle query param flashes)
# ============================================
print_status "4/6: Creating index.html..."
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
print_status "5/6: Creating clipboard.html..."
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
    **{{ expiry_info_days }}** days, **{{ expiry_info_hours }}** hours, **{{ expiry_info_minutes }}** minutes</p><p><a href="{{ url_for('index') }}" style="margin-top: 20px; display: inline-block;">ایجاد یک کلیپ جدید</a></p>
    
    <p style="margin-top: 20px; font-size: 0.8em; color: #999;">برای دسترسی به پنل مدیریت، از طریق SSH به سرور متصل شده و آدرس http://127.0.0.1:{{ server_port }}/admin را در مرورگر سرور باز کنید.</p>
    
{% endif %}</div></body></html>
HTM_CLIPBOARD

# ============================================
# 6. Create Admin Templates (admin.html and edit_clip.html)
# ============================================
print_status "6/6: Creating admin templates..."

# --- admin.html ---
cat > "$INSTALL_DIR/templates/admin.html" << 'HTM_ADMIN'
<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Admin Panel</title><style>body { font-family: Tahoma, sans-serif; background-color: #f4f4f4; color: #333; padding: 20px; }h2 { text-align: center; }table { width: 100%; border-collapse: collapse; margin-top: 20px; direction: rtl; }th, td { border: 1px solid #ddd; padding: 8px; text-align: right; }th { background-color: #f2f2f2; }a.button { display: inline-block; padding: 5px 10px; margin: 2px; text-decoration: none; color: white; border-radius: 4px; }a.edit { background-color: #ffc107; }form.delete-form { display: inline; }button.delete-btn { background-color: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; }span.file { background-color: #e9f7fe; padding: 3px 6px; border-radius: 3px; font-size: 0.9em; }.flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: right; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: right; }</style></head><body><h2>پنل مدیریت کلیپ‌بورد</h2>
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

<p style="text-align: right;">حجم کل فایل‌های آپلود شده: <b>{{ total_size_mb }} مگابایت</b></p>
<p style="text-align: right; color: #777;">این پنل فقط از طریق **localhost (http://127.0.0.1:{{ server_port }}/admin)** قابل دسترسی است.</p>

<table>
    <thead>
        <tr>
            <th>ID</th>
            <th>لینک (Key)</th>
            <th>محتوای متنی</th>
            <th>فایل</th>
            <th>تاریخ ایجاد</th>
            <th>تاریخ انقضا</th>
            <th>عملیات</th>
        </tr>
    </thead>
    <tbody>
        {% for clip in clips %}
        <tr>
            <td>{{ clip['id'] }}</td>
            <td><a href="{{ url_for('view_clip', key=clip['key']) }}" target="_blank">{{ clip['key'] }}</a></td>
            <td>{{ clip['content_preview'] }}{% if clip['content']|length > 50 %}...{% endif %}</td>
            <td>{% if clip['file_path'] %}<span class="file">{{ clip['file_path'].split('_', 1)[-1] }}</span>{% else %}ندارد{% endif %}</td>
            <td dir="ltr">{{ clip['created_at'].split(' ')[0] }}</td>
            <td dir="ltr">{{ clip['expires_at'].split(' ')[0] }}</td>
            <td>
                <a href="{{ url_for('edit_clip', clip_id=clip['id']) }}" class="button edit">ویرایش</a>
                <form class="delete-form" method="POST" action="{{ url_for('delete_clip', clip_id=clip['id']) }}" onsubmit="return confirm('آیا مطمئن هستید که می‌خواهید این کلیپ را حذف کنید؟ این عمل غیرقابل بازگشت است.');">
                    <button type="submit" class="delete-btn">حذف</button>
                </form>
            </td>
        </tr>
        {% else %}
        <tr>
            <td colspan="7" style="text-align: center;">هیچ کلیپی در دیتابیس موجود نیست.</td>
        </tr>
        {% endfor %}
    </tbody>
</table>

<p style="margin-top: 20px; text-align: right;"><a href="{{ url_for('index') }}">بازگشت به صفحه اصلی</a></p>
</body></html>
HTM_ADMIN

# --- edit_clip.html ---
cat > "$INSTALL_DIR/templates/edit_clip.html" << 'HTM_EDIT'
<!DOCTYPE html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Edit Clip</title><style>body { font-family: Tahoma, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }.container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }textarea, input[type="text"] { width: 95%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }input[type="submit"] { background-color: #28a745; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }input[type="submit"]:hover { background-color: #1e7e34; }.flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; text-align: right; }</style></head><body><div class="container"><h2>ویرایش کلیپ (ID: {{ clip['id'] }})</h2>
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

<p style="text-align: right;"><b>تاریخ انقضا:</b> {{ clip['expires_at'].split(' ')[0] }}</p>
{% if clip['file_path'] %}<p style="text-align: right;"><b>فایل ضمیمه:</b> <span style="background-color: #e9f7fe; padding: 3px 6px; border-radius: 3px;">{{ clip['file_path'].split('_', 1)[-1] }}</span></p>{% endif %}

<form method="POST" action="{{ url_for('edit_clip', clip_id=clip['id']) }}">
    <label for="key" style="display: block; text-align: right; margin-top: 10px;">لینک دلخواه (Key):</label>
    <input type="text" name="key" value="{{ clip['key'] }}" pattern="^[a-zA-Z0-9_-]{3,64}$" title="لینک دلخواه باید بین 3 تا 64 کاراکتر بوده و شامل حروف انگلیسی، اعداد، خط فاصله یا زیرخط باشد." required>
    
    <label for="content" style="display: block; text-align: right; margin-top: 10px;">محتوای متنی:</label>
    <textarea name="content" rows="10" placeholder="متن مورد نظر شما">{{ clip['content'] }}</textarea>
    
    <input type="submit" value="ذخیره تغییرات">
</form>
<p style="margin-top: 20px;"><a href="{{ url_for('admin_panel') }}">بازگشت به پنل مدیریت</a></p>
</div></body></html>
HTM_EDIT

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
echo "🎉 نصب نهایی کامل شد (Clipboard Server V9)"
echo "================================================"
echo "✅ وضعیت سرویس: $(systemctl is-active clipboard.service)"
echo "🌐 سرور شما روی پورت $PORT اجرا می‌شود."
echo "------------------------------------------------"
echo "🛑 نکته مهم: پنل مدیریت فقط از طریق SSH یا ترمینال سرور قابل دسترسی است."
echo "🔗 آدرس پنل مدیریت: http://127.0.0.1:${PORT}/admin"
echo "------------------------------------------------"
echo "Status:   sudo systemctl status clipboard.service"
echo "Restart:  sudo systemctl restart clipboard.service"
echo "Logs:     sudo journalctl -u clipboard.service -f"
echo "================================================"
