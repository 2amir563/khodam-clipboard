#!/bin/bash
# Internet Clipboard Server Installer (CLI Management + Full Web Submission)
# V29 - FINAL STABILITY FIX: Single Worker (V27) + No immediate cleanup (V28) + Improved CLI execution path.

set -e

# --- Configuration (Keep these consistent) ---
INSTALL_DIR="/opt/clipboard_server"
CLIPBOARD_PORT="3214" 
EXPIRY_DAYS="30"
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
    print_error "❌ لطفاً اسکریپت را با دسترسی root اجرا کنید: sudo bash install_clipboard.sh"
    exit 1
fi

echo "=================================================="
echo "📋 نصب‌کننده سرور کلیپ‌بورد اینترنتی (V29 - رفع نهایی پایداری)"
echo "=================================================="

# ============================================
# 1. System Setup & Venv
# ============================================
print_status "1/6: آماده‌سازی سیستم و محیط مجازی..."
apt update -y
apt install -y python3 python3-pip python3-venv curl wget

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
print_status "2/6: به‌روزرسانی پیکربندی و ساختار دایرکتوری..."

mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
# تنظیم دسترسی کامل برای اطمینان از رفع مشکل Permissions
chmod -R 777 "$INSTALL_DIR" 

# --- Create .env file ---
cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
CLIPBOARD_PORT=${CLIPBOARD_PORT}
MAX_REMOTE_SIZE_MB=50
DOTENV_FULL_PATH=${INSTALL_DIR}/.env
ENVEOF

# ============================================
# 3. Create web_service.py (V29: Improved DB connection logic)
# ============================================
print_status "3/6: ساخت web_service.py (V29 - رفع خطای خواندن)..."
cat > "$INSTALL_DIR/web_service.py" << 'PYEOF_WEB_SERVICE'
import os
import sqlite3
import re
import string
import random
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv, find_dotenv
from werkzeug.utils import secure_filename

# --- Configuration & Init ---
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', find_dotenv(usecwd=True))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db') 
UPLOAD_FOLDER = 'uploads'
CLIPBOARD_PORT = int(os.getenv('CLIPBOARD_PORT', '3214')) 
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
MAX_REMOTE_SIZE_BYTES = int(os.getenv('MAX_REMOTE_SIZE_MB', 50)) * 1024 * 1024 
KEY_REGEX = r'^[a-zA-Z0-9_-]{3,64}$'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar', '7z', 'mp3', 'mp4', 'exe', 'bin', 'iso'}

# --- Utility Functions ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        try:
            # V29: Using URI mode and check_same_thread=False for robustness.
            # Gunicorn is forced to 1 worker to eliminate concurrency locks.
            db = g._database = sqlite3.connect(
                f'file:{DATABASE_PATH}?mode=rw', 
                uri=True, 
                timeout=10, 
                check_same_thread=False 
            )
            db.row_factory = sqlite3.Row 
            db.execute('PRAGMA journal_mode=WAL') # Ensure WAL mode is active
            db.execute('PRAGMA foreign_keys=ON') 
        except sqlite3.OperationalError as e:
            # This block helps diagnose DB path/permission issues on first run
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
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    # Delete associated files
    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_utc,))
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
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    db.commit()

# --- Main Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    
    # 1. Handle form submission (POST)
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        custom_key = request.form.get('custom_key', '').strip()
        
        uploaded_files = request.files.getlist('files')
        has_content = content or any(f.filename for f in uploaded_files)
        
        if not has_content:
            flash('لطفاً محتوای متنی ارائه دهید یا حداقل یک فایل آپلود کنید.', 'error')
            return redirect(url_for('index'))

        key = custom_key or generate_key()
        
        # Validate key
        if custom_key and not re.match(KEY_REGEX, custom_key):
            flash('فرمت کلید سفارشی نامعتبر است.', 'error')
            return redirect(url_for('index'))
            
        # Check for key existence
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT 1 FROM clips WHERE key = ?", (key,))
            if cursor.fetchone():
                flash(f'کلید "{key}" قبلاً استفاده شده است. لطفاً کلید دیگری انتخاب کنید.', 'error')
                return redirect(url_for('index'))
        except RuntimeError:
            flash("خطای اتصال پایگاه داده.", 'error')
            return redirect(url_for('index'))
            
        # File Handling (Same as V28)
        file_paths = []
        try:
            for file in uploaded_files:
                if file and file.filename and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{key}_{filename}"
                    full_path = os.path.join(UPLOAD_FOLDER, unique_filename)
                    file.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), full_path))
                    file_paths.append(full_path)
                elif file.filename and not allowed_file(file.filename):
                     flash(f'نوع فایل مجاز نیست: {file.filename}', 'error')
                     return redirect(url_for('index'))
                     
        except Exception as e:
            flash(f'خطای آپلود فایل: {e}', 'error')
            for fp in file_paths:
                try: os.remove(os.path.join(os.path.dirname(os.path.abspath(__file__)), fp))
                except: pass
            return redirect(url_for('index'))
            
        # Database Insertion
        expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)
        file_path_string = ','.join(file_paths)
        
        try:
            cursor.execute(
                "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (key, content, file_path_string, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
            )
            db.commit()
            
            # Redirect to the newly created clip
            return redirect(url_for('view_clip', key=key))
            
        except sqlite3.OperationalError as e:
             print(f"SQLITE ERROR: {e}")
             flash("خطای پایگاه داده هنگام ایجاد کلیپ. لاگ‌های سرور را بررسی کنید.", 'error')
             return redirect(url_for('index'))


    # 2. Handle GET request (Display form)
    # Cleanup runs here on page load, NOT after form submission
    try:
        cleanup_expired_clips()
    except RuntimeError:
         flash("خطای اتصال به پایگاه داده در هنگام تمیزکاری. لطفاً CLI را اجرا کنید.", 'error')
    
    return render_template('index.html', EXPIRY_DAYS=EXPIRY_DAYS)


@app.route('/<key>')
def view_clip(key):
    try:
        cleanup_expired_clips()
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT content, file_path, expires_at FROM clips WHERE key = ?", (key,))
        clip = cursor.fetchone()
    except RuntimeError:
        return render_template('error.html', message="خطای پایگاه داده. پایگاه داده را توسط CLI بررسی کنید."), 500
    except sqlite3.OperationalError as e:
        print(f"SQLITE ERROR: {e}")
        return render_template('error.html', message="پایگاه داده راه‌اندازی نشده یا خراب است. ابزار CLI را اجرا کنید."), 500

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
                           server_port=CLIPBOARD_PORT)


@app.route('/download/<path:file_path>')
def download_file(file_path):
    # Same as V28
    if not file_path.startswith(UPLOAD_FOLDER + '/'):
         flash('درخواست دانلود نامعتبر.', 'error')
         return redirect(url_for('index'))
         
    filename_part = os.path.basename(file_path)
    try:
        key = filename_part.split('_', 1)[0]
    except IndexError:
        flash('فرمت مسیر فایل نامعتبر است.', 'error')
        return redirect(url_for('index'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        flash('فایل یافت نشد یا لینک منقضی شده است.', 'error')
        return redirect(url_for('index'))

    file_paths_string, expires_at_str = clip
    
    if file_path not in [p.strip() for p in file_paths_string.split(',')]:
        flash('فایل در کلیپ مرتبط یافت نشد.', 'error')
        return redirect(url_for('view_clip', key=key))


    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        cleanup_expired_clips()
        flash('فایل یافت نشد یا لینک منقضی شده است.', 'error')
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
# 4. Create clipboard_cli.py (The CLI Management Tool - V29: Simplified path)
# ============================================
print_status "4/6: ساخت clipboard_cli.py (ابزار CLI - مسیر اجرای ساده‌تر)..."
cat > "$INSTALL_DIR/clipboard_cli.py" << 'PYEOF_CLI_TOOL'
import os
import sqlite3
import random
import string
import re
import sys
import argparse
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv, find_dotenv

# --- Configuration & Init ---
# Load .env relative to the script location
DOTENV_PATH = os.getenv('DOTENV_FULL_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 
CLIPBOARD_PORT = os.getenv('CLIPBOARD_PORT', '3214')
BASE_URL = f"http://YOUR_IP:{CLIPBOARD_PORT}" 
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

# --- Database Management ---
def get_db_connection():
    # CLI tool is single-threaded, so standard connection is fine here
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
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL
        )
    """)
    # Set WAL mode for CLI as well for better compatibility
    cursor.execute('PRAGMA journal_mode=WAL')
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
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_utc,))
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
            
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    conn.commit()
    conn.close()

# --- Main CLI Functions ---

def create_new_clip():
    print(f"\n{Color.BLUE}{Color.BOLD}--- ایجاد کلیپ جدید (CLI){Color.END}")
    content = input("محتوای متنی را وارد کنید (اگر فقط Placeholder می‌سازید، خالی بگذارید): ").strip()
    custom_key = input("کلید لینک سفارشی را وارد کنید (اختیاری، برای کلید تصادفی خالی بگذارید): ").strip()

    key = None
    if custom_key:
        if not re.match(KEY_REGEX, custom_key):
            print(f"{Color.RED}خطا: کلید سفارشی نامعتبر است.{Color.END}")
            return
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM clips WHERE key = ?", (custom_key,))
        if cursor.fetchone():
            print(f"{Color.RED}خطا: کلید '{custom_key}' قبلاً گرفته شده است.{Color.END}")
            conn.close()
            return
        key = custom_key
    
    if not key:
        key = generate_key()

    if not content:
        content = f"کلیپ خالی توسط CLI ایجاد شد. کلید: {key}"

    expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key, content, "", datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        conn.close()
        
        print(f"\n{Color.GREEN}✅ موفقیت! کلیپ ایجاد شد:{Color.END}")
        print(f"   {Color.BOLD}کلید:{Color.END} {key}")
        print(f"   {Color.BOLD}لینک:{Color.END} {BASE_URL}/{key}")
        print(f"   {Color.BOLD}انقضا:{Color.END} {expires_at.strftime('%Y-%m-%d %H:%M:%S')} (در {EXPIRY_DAYS} روز)")
        
    except sqlite3.Error as e:
        print(f"{Color.RED}خطای پایگاه داده: {e}{Color.END}")
    except Exception as e:
        print(f"{Color.RED}خطای غیرمنتظره‌ای رخ داد: {e}{Color.END}")


def list_clips():
    cleanup_expired_clips()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, key, content, file_path, created_at, expires_at FROM clips ORDER BY id DESC")
    clips = cursor.fetchall()
    conn.close()

    if not clips:
        print(f"\n{Color.YELLOW}کلیپ فعالی یافت نشد.{Color.END}")
        return

    print(f"\n{Color.BLUE}{Color.BOLD}--- کلیپ‌های فعال ({len(clips)}) ---{Color.END}")
    print(f"{Color.CYAN}{'ID':<4} {'کلید':<20} {'پیش نمایش محتوا':<40} {'فایل‌ها':<10} {'انقضا':<10}{Color.END}")
    print("-" * 90)
    
    for clip in clips:
        content_preview = (clip['content'][:35] + '...') if clip['content'] and len(clip['content']) > 35 else (clip['content'] or "بدون محتوا")
        file_count = len([p for p in clip['file_path'].split(',') if p.strip()]) if clip['file_path'] else 0
        
        print(f"{clip['id']:<4} {Color.BOLD}{clip['key']:<20}{Color.END} {content_preview:<40} {file_count:<10} {clip['expires_at'].split(' ')[0]:<10}")
    print("-" * 90)


def delete_clip():
    list_clips()
    if not input(f"\n{Color.YELLOW}آیا با حذف ادامه می‌دهید؟ (بله/خیر): {Color.END}").lower().strip().startswith('ب'):
        print("حذف لغو شد.")
        return

    clip_id_or_key = input("ID یا کلید کلیپ برای حذف را وارد کنید: ").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if clip_id_or_key.isdigit():
        cursor.execute("SELECT id, key, file_path FROM clips WHERE id = ?", (int(clip_id_or_key),))
    else:
        cursor.execute("SELECT id, key, file_path FROM clips WHERE key = ?", (clip_id_or_key,))
    
    clip = cursor.fetchone()
    
    if not clip:
        print(f"{Color.RED}خطا: کلیپ با ID/Key '{clip_id_or_key}' یافت نشد.{Color.END}")
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
                print(f" - فایل حذف شد: {os.path.basename(file_path)}")
                
    cursor.execute("DELETE FROM clips WHERE id = ?", (clip_id,))
    conn.commit()
    conn.close()
    
    print(f"\n{Color.GREEN}✅ کلیپ با ID {clip_id} (کلید: {clip_key}) با موفقیت حذف شد.{Color.END}")


def edit_clip():
    list_clips()
    clip_id_or_key = input("\nID یا کلید کلیپ برای ویرایش را وارد کنید: ").strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    
    if clip_id_or_key.isdigit():
        cursor.execute("SELECT id, key, content FROM clips WHERE id = ?", (int(clip_id_or_key),))
    else:
        cursor.execute("SELECT id, key, content FROM clips WHERE key = ?", (clip_id_or_key,))
    
    clip = cursor.fetchone()
    
    if not clip:
        print(f"{Color.RED}خطا: کلیپ با ID/Key '{clip_id_or_key}' یافت نشد.{Color.END}")
        conn.close()
        return

    clip_id = clip['id']
    clip_key = clip['key']

    print(f"\n{Color.CYAN}--- ویرایش کلیپ ID {clip_id} (کلید: {clip_key}) ---{Color.END}")
    print(f"کلید فعلی: {Color.BOLD}{clip_key}{Color.END}")
    print("--------------------------------------------------")
    print(f"1. ویرایش کلید")
    print(f"2. ویرایش محتوا")
    print(f"0. لغو")
    
    choice = input("انتخاب خود را وارد کنید (1/2/0): ").strip()

    if choice == '1':
        new_key = input(f"کلید جدید را وارد کنید (فعلی: {clip_key}): ").strip()
        if not new_key or not re.match(KEY_REGEX, new_key):
            print(f"{Color.RED}خطا: کلید نامعتبر یا خالی.{Color.END}")
            conn.close()
            return
        
        if new_key != clip_key:
            cursor.execute("SELECT 1 FROM clips WHERE key = ? AND id != ?", (new_key, clip_id))
            if cursor.fetchone():
                print(f"{Color.RED}خطا: کلید '{new_key}' قبلاً گرفته شده است.{Color.END}")
                conn.close()
                return
        
        cursor.execute("UPDATE clips SET key = ? WHERE id = ?", (new_key, clip_id))
        conn.commit()
        print(f"\n{Color.GREEN}✅ کلید با موفقیت به {new_key} به‌روزرسانی شد.{Color.END}")
        
    elif choice == '2':
        print(f"\n{Color.YELLOW}--- محتوای فعلی ---{Color.END}")
        print(clip['content'] if clip['content'] else "(خالی)")
        print("---------------------------------------")
        print(f"محتوای جدید را تایپ کنید. برای ذخیره و پایان، {Color.BOLD}Ctrl+D{Color.END} (یا Ctrl+Z در ویندوز)، سپس Enter را فشار دهید.")
        
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
        print(f"\n{Color.GREEN}✅ محتوا با موفقیت به‌روزرسانی شد.{Color.END}")
    
    elif choice == '0':
        print("ویرایش لغو شد.")

    conn.close()

def main_menu():
    init_db()
    cleanup_expired_clips()
    
    # Check if run with the init-db flag
    if len(sys.argv) > 1 and sys.argv[1] == '--init-db':
        print(f"[{Color.GREEN}INFO{Color.END}] پایگاه داده با موفقیت بررسی/راه‌اندازی اولیه شد.")
        return

    while True:
        print(f"\n{Color.PURPLE}{Color.BOLD}========================================{Color.END}")
        print(f"{Color.PURPLE}{Color.BOLD}   مدیریت CLI کلیپ‌بورد (URL پایه: {BASE_URL}){Color.END}")
        print(f"{Color.PURPLE}{Color.BOLD}========================================{Color.END}")
        print(f"1. {Color.GREEN}ایجاد کلیپ جدید{Color.END} (فقط متن)")
        print(f"2. {Color.BLUE}لیست تمام کلیپ‌ها{Color.END}")
        print(f"3. {Color.CYAN}ویرایش کلیپ{Color.END} (کلید یا محتوا)")
        print(f"4. {Color.RED}حذف کلیپ{Color.END}")
        print("0. خروج")
        
        choice = input("انتخاب خود را وارد کنید: ").strip()

        if choice == '1':
            create_new_clip()
        elif choice == '2':
            list_clips()
        elif choice == '3':
            edit_clip()
        elif choice == '4':
            delete_clip()
        elif choice == '0':
            print(f"\n{Color.BOLD}خروج از مدیریت CLI. خداحافظ!{Color.END}")
            break
        else:
            print(f"{Color.RED}انتخاب نامعتبر است. لطفاً دوباره تلاش کنید.{Color.END}")

if __name__ == '__main__':
    main_menu()

PYEOF_CLI_TOOL

# ============================================
# 5. Create Minimal Templates (NO CHANGE)
# ============================================
print_status "5/6: ساخت قالب‌های HTML..."

# --- index.html ---
cat > "$INSTALL_DIR/templates/index.html" << 'INDEXEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internet Clipboard Server - Create</title>
    <style>
        body { font-family: sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 700px; margin: 20px auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #007bff; text-align: center; margin-bottom: 25px; }
        .flash { padding: 15px; border-radius: 8px; margin-bottom: 15px; font-weight: bold; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
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
    </style>
</head>
<body>
    <div class="container">
        <h1>📋 سرور کلیپ‌بورد اینترنتی (ایجاد کلیپ)</h1>
        
        <div class="flash error">
            {% for message in get_flashed_messages(category_filter=['error']) %}
                {{ message }}
            {% endfor %}
        </div>
        
        <form method="POST" enctype="multipart/form-data">
            <div>
                <label for="content">محتوای متنی (اختیاری):</label>
                <textarea id="content" name="content" placeholder="متن خود را اینجا بچسبانید..."></textarea>
            </div>
            
            <div>
                <label for="files">آپلود فایل (اختیاری - حداکثر 50 مگابایت):</label>
                <input type="file" id="files" name="files" multiple>
            </div>
            
            <div>
                <label for="custom_key">کلید لینک سفارشی (اختیاری، مثال: 'my-secret-key'):</label>
                <input type="text" id="custom_key" name="custom_key" placeholder="برای کلید تصادفی خالی بگذارید">
            </div>
            
            <input type="submit" value="ایجاد کلیپ (در {{ EXPIRY_DAYS }} روز منقضی می‌شود)">
        </form>
        
        <div class="cli-note">
            ⚠️ پنل مدیریت فقط از طریق واسط خط فرمان (CLI) در سرور قابل دسترسی است: 
            <code>sudo /opt/clipboard_server/clipboard_cli.sh</code>
        </div>
    </div>
</body>
</html>
INDEXEOF

# --- clipboard.html ---
cat > "$INSTALL_DIR/templates/clipboard.html" << 'CLIPBOARDEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clip: {{ key }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #007bff; text-align: center; margin-bottom: 20px; }
        pre { background-color: #eee; padding: 15px; border-radius: 8px; white-space: pre-wrap; word-wrap: break-word; overflow: auto; max-height: 400px; margin-bottom: 20px; border: 1px solid #ccc; position: relative; }
        .content-section { margin-bottom: 30px; }
        .files-section { margin-bottom: 30px; border-top: 1px solid #eee; padding-top: 20px; }
        .files-section h2 { color: #333; font-size: 1.2em; margin-bottom: 15px; }
        .file-item { display: flex; justify-content: space-between; align-items: center; background-color: #f0f8ff; padding: 10px 15px; border-radius: 6px; margin-bottom: 8px; border-left: 5px solid #007bff; }
        .file-item a { color: #007bff; text-decoration: none; font-weight: bold; }
        .file-item a:hover { text-decoration: underline; }
        .expiry-info { text-align: center; color: #d9534f; font-weight: bold; margin-bottom: 20px; }
        .back-link { display: block; text-align: center; margin-top: 30px; }
        .back-link a { color: #007bff; text-decoration: none; font-weight: bold; }
        .flash { padding: 15px; border-radius: 8px; margin-bottom: 15px; font-weight: bold; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .copy-button { background-color: #5cb85c; color: white; padding: 5px 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9em; float: right; margin-left: 10px; }
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
        
        {% if clip and content %}
            <h1>محتوای کلیپ برای: {{ key }}</h1>
            
            <div class="expiry-info">
                منقضی می‌شود در: {{ expiry_info_days }} روز، {{ expiry_info_hours }} ساعت، و {{ expiry_info_minutes }} دقیقه.
            </div>

            <div class="content-section">
                <h2>محتوای متنی</h2>
                <button class="copy-button" onclick="copyContent()">کپی متن</button>
                <pre id="text-content">{{ content }}</pre>
            </div>
        {% elif expired %}
            <h1>کلیپ یافت نشد</h1>
            <div class="expiry-info">این لینک کلیپ‌بورد منقضی شده است و محتوای آن حذف شده است.</div>
        {% else %}
             <h1>کلیپ یافت نشد</h1>
             <div class="expiry-info">کلیپ با کلید **{{ key }}** وجود ندارد.</div>
        {% endif %}
        
        {% if files_info %}
            <div class="files-section">
                <h2>فایل‌های ضمیمه ({{ files_info|length }})</h2>
                {% for file in files_info %}
                    <div class="file-item">
                        <span>{{ file.name }}</span>
                        <a href="{{ url_for('download_file', file_path=file.path) }}">دانلود</a>
                    </div>
                {% endfor %}
            </div>
        {% endif %}

        <div class="back-link">
            <a href="/">← ایجاد کلیپ جدید</a>
        </div>
    </div>

    <script>
        function copyContent() {
            const content = document.getElementById('text-content').innerText;
            navigator.clipboard.writeText(content).then(() => {
                alert('متن در کلیپ‌بورد کپی شد!');
            }).catch(err => {
                console.error('Could not copy text: ', err);
            });
        }
    </script>
</body>
</html>
CLIPBOARDEOF

# --- error.html ---
cat > "$INSTALL_DIR/templates/error.html" << 'ERROREOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error</title>
    <style>
        body { font-family: sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 50px; text-align: center;}
        .container { max-width: 600px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); }
        h1 { color: #dc3545; margin-bottom: 20px; }
        p { font-size: 1.1em; color: #555; }
        .error-message { margin-top: 30px; padding: 15px; background-color: #f8d7da; border: 1px solid #f5c6cb; border-radius: 8px; color: #721c24; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ خطای داخلی</h1>
        <div class="error-message">
            <p>{{ message }}</p>
        </div>
        <p>این احتمالاً یک مشکل پیکربندی سرور است.</p>
        <p>لطفاً لاگ‌های سرور (<code>sudo journalctl -u clipboard.service</code>) را بررسی کنید و مطمئن شوید که ابزار CLI حداقل یک بار اجرا شده است.</p>
    </div>
</body>
</html>
ERROREOF


# ============================================
# 6. Create Systemd Service (Workers set to 1)
# ============================================
print_status "6/7: ساخت سرویس Systemd برای وب سرور (کارگر: ۱)..."

# --- clipboard.service (Port 3214 - Runs web_service.py) ---
cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Web Server (Full Submission, CLI Management)
After=network.target

[Service]
Type=simple
User=root 
WorkingDirectory=${INSTALL_DIR}
# FIXED: Workers set to 1 to eliminate all SQLite locking issues.
ExecStart=${GUNICORN_VENV_PATH} --workers 1 --bind 0.0.0.0:${CLIPBOARD_PORT} web_service:app
Environment=DOTENV_FULL_PATH=${INSTALL_DIR}/.env
Restart=always
TimeoutSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF


# ============================================
# 7. Final Steps
# ============================================
print_status "7/7: راه‌اندازی پایگاه داده و شروع سرویس..."

# ایجاد یک اسکریپت ساده برای اجرای CLI که دسترسی محیط مجازی را مدیریت کند
cat > "$INSTALL_DIR/clipboard_cli.sh" << CLISHEOF
#!/bin/bash
source ${INSTALL_DIR}/venv/bin/activate
exec ${PYTHON_VENV_PATH} ${INSTALL_DIR}/clipboard_cli.py "\$@"
CLISHEOF
chmod +x "$INSTALL_DIR/clipboard_cli.sh"

# Initialize DB using the new wrapper script
"$INSTALL_DIR/clipboard_cli.sh" --init-db 

systemctl daemon-reload
systemctl enable clipboard.service
systemctl restart clipboard.service

echo ""
echo "================================================"
echo "🎉 نصب کامل شد (Clipboard Server V29 - پایدار)"
echo "================================================"
echo "✅ وضعیت سرویس وب (پورت ${CLIPBOARD_PORT}): $(systemctl is-active clipboard.service)"
echo "------------------------------------------------"
echo "🌐 ایجاد کلیپ (واسط وب): http://YOUR_IP:${CLIPBOARD_PORT}"
echo "------------------------------------------------"
echo "💻 مدیریت/ادمین (فقط CLI):"
echo -e "   ${BLUE}sudo ${INSTALL_DIR}/clipboard_cli.sh${NC}"
echo "------------------------------------------------"
echo "لاگ‌ها:     sudo journalctl -u clipboard.service -f"
echo "================================================"
