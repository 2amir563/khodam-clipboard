#!/bin/bash
# Internet Clipboard Service Installer (Gunicorn + Flask + SQLite)

set -e

# --- Configuration ---
INSTALL_DIR="/opt/clipboard_server"
PYTHON_BIN=$(which python3)
GUNICORN_BIN=$(which gunicorn)
PORT="3214"
EXPIRY_DAYS="30"
SECRET_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32) # Generates a strong secret key

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# Check root access
if [ "$EUID" -ne 0 ]; then
    print_error "Please run with root access: sudo bash install_clipboard.sh"
    exit 1
fi

echo "=================================================="
echo "📋 Internet Clipboard Server Installer (Port: $PORT)"
echo "=================================================="

# ============================================
# 1. System Update & Essential Tools
# ============================================
print_status "1/6: Updating system and installing essential tools (Python3, PIP, Gunicorn)..."
apt update -y
apt install -y python3 python3-pip python3-venv curl wget

# Create Virtual Environment and activate it
print_status "1/6: Creating Virtual Environment..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate

# ============================================
# 2. Install Python Packages
# ============================================
print_status "2/6: Installing Python packages (Flask, Gunicorn, dotenv)..."

cat > requirements.txt << 'REQEOF'
Flask
python-dotenv
gunicorn
REQEOF

pip install -r requirements.txt

# Deactivate the venv for now
deactivate
PYTHON_VENV_PATH="$INSTALL_DIR/venv/bin/python3"
GUNICORN_VENV_PATH="$INSTALL_DIR/venv/bin/gunicorn"

# ============================================
# 3. Create Project Structure and Files
# ============================================
print_status "3/6: Creating project directory structure and files..."
mkdir -p "$INSTALL_DIR/templates"
mkdir -p "$INSTALL_DIR/uploads"
chmod 777 "$INSTALL_DIR/uploads" # Ensure Gunicorn user can write files

# --- Create .env file ---
cat > "$INSTALL_DIR/.env" << ENVEOF
SECRET_KEY=${SECRET_KEY}
EXPIRY_DAYS=${EXPIRY_DAYS}
ENVEOF

# --- Create app.py ---
cat > "$INSTALL_DIR/app.py" << 'PYEOF'
import os
import sqlite3
import random
import string
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, g
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_strong_secret_key') 
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard.db')
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
EXPIRY_DAYS = int(os.getenv('EXPIRY_DAYS', '30')) 

# --- Database Management ---
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
    """Initializes the SQLite database structure."""
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

# --- Helper Functions ---
def generate_key(length=8):
    """Generates a unique random alphanumeric key."""
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
    """Deletes expired clips and their associated files."""
    db = get_db()
    cursor = db.cursor()
    
    now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    # Find expired entries
    cursor.execute("SELECT file_path FROM clips WHERE expires_at < ?", (now_utc,))
    expired_files = cursor.fetchall()

    # Delete files
    for file_path_tuple in expired_files:
        file_path = file_path_tuple[0]
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError as e:
                print(f"Error removing file {file_path}: {e}")
            
    # Delete database entries
    cursor.execute("DELETE FROM clips WHERE expires_at < ?", (now_utc,))
    db.commit()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Cleanup completed. Removed {len(expired_files)} expired entries/files.")


# --- Routes ---

@app.route('/')
def index():
    """Main page to create a new clipboard."""
    # Ensure cleanup runs occasionally (e.g., on index load)
    cleanup_expired_clips()
    return render_template('index.html', EXPIRY_DAYS=EXPIRY_DAYS)

@app.route('/create', methods=['POST'])
def create_clip():
    """Handles the creation of the new clip from form submission."""
    content = request.form.get('content')
    uploaded_file = request.files.get('file')

    if not content and (not uploaded_file or not uploaded_file.filename):
        flash('You must provide text or a file.', 'error')
        return redirect(url_for('index'))

    key = generate_key()
    file_path = None
    
    # Handle file upload
    if uploaded_file and uploaded_file.filename:
        filename = uploaded_file.filename
        file_path = os.path.join(UPLOAD_FOLDER, f"{key}_{filename}")
        # Securely save the file
        uploaded_file.save(os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path))
        
    # Calculate expiry date (UTC)
    expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRY_DAYS)

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO clips (key, content, file_path, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (key, content, file_path, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), expires_at.strftime('%Y-%m-%d %H:%M:%S'))
        )
        db.commit()
        flash(f'Clipboard created successfully! Share this link: {url_for("view_clip", key=key, _external=True)}', 'success')
        return redirect(url_for('view_clip', key=key))
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        flash('An internal error occurred during creation.', 'error')
        return redirect(url_for('index'))


@app.route('/<key>')
def view_clip(key):
    """Displays the content of the clipboard or file link."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT content, file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        return render_template('clipboard.html', clip=None, key=key)

    content, file_path, expires_at_str = clip
    
    # Check expiry
    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    now_utc = datetime.now(timezone.utc)
    
    if expires_at < now_utc:
        # If expired, run immediate cleanup and show expired message
        cleanup_expired_clips()
        return render_template('clipboard.html', clip=None, key=key, expired=True)

    # Format remaining time
    time_left = expires_at - now_utc
    days = time_left.days
    hours = time_left.seconds // 3600
    minutes = (time_left.seconds % 3600) // 60
    
    expiry_info = f"{days} days, {hours} hours, {minutes} minutes"

    return render_template('clipboard.html', 
                           key=key, 
                           content=content, 
                           file_path=file_path, 
                           expiry_info=expiry_info)


@app.route('/download/<key>')
def download_file(key):
    """Handles file download."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT file_path, expires_at FROM clips WHERE key = ?", (key,))
    clip = cursor.fetchone()

    if not clip:
        flash('File not found or link expired.', 'error')
        return redirect(url_for('index'))

    file_full_path, expires_at_str = clip
    
    # Check expiry
    expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        cleanup_expired_clips()
        flash('File not found or link expired.', 'error')
        return redirect(url_for('index'))
    
    if file_full_path:
        # Extract filename from path (e.g., uploads/key_filename.ext -> filename.ext)
        filename_with_key = os.path.basename(file_full_path)
        # Original filename is needed for download prompt (after the key_)
        original_filename = filename_with_key.split('_', 1)[1] if '_' in filename_with_key else filename_with_key
        
        # Send the file from the UPLOAD_FOLDER
        return send_from_directory(os.path.join(os.path.dirname(os.path.abspath(__file__)), UPLOAD_FOLDER), 
                                   filename_with_key, 
                                   as_attachment=True, 
                                   download_name=original_filename)
    
    flash('No file associated with this link.', 'error')
    return redirect(url_for('view_clip', key=key))


if __name__ == '__main__':
    # Initialize DB outside of Gunicorn start for first run
    init_db()
    app.run(host='0.0.0.0', port=PORT, debug=True)
PYEOF

# --- Create index.html ---
cat > "$INSTALL_DIR/templates/index.html" << 'HTM_INDEX'
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Internet Clipboard - کلیپ‌بورد اینترنتی</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }
        .container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }
        textarea, input[type="file"] { width: 95%; padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .flash-success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; }
        .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Clipboard Server</h2>
        <p>متن یا فایل مورد نظر خود را برای انتقال بین دستگاه‌ها قرار دهید.</p>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                <ul style="list-style: none; padding: 0;">
                    {% for category, message in messages %}
                        <li class="flash-{{ category }}">{{ message | safe }}</li>
                    {% endfor %}
                </ul>
            {% endif %}
        {% endwith %}

        <form method="POST" action="{{ url_for('create_clip') }}" enctype="multipart/form-data">
            <textarea name="content" rows="6" placeholder="متن مورد نظر شما"></textarea>
            <p>یا</p>
            <input type="file" name="file">
            <input type="submit" value="ایجاد لینک">
        </form>
        <p>فایل/متن به صورت خودکار پس از **{{ EXPIRY_DAYS }} روز** پاک خواهد شد.</p>
    </div>
</body>
</html>
HTM_INDEX

# --- Create clipboard.html ---
cat > "$INSTALL_DIR/templates/clipboard.html" << 'HTM_CLIPBOARD'
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Clipboard - {{ key }}</title>
    <style>
        body { font-family: Tahoma, sans-serif; background-color: #f4f4f4; color: #333; text-align: center; padding: 50px 10px; }
        .container { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); max-width: 600px; margin: 0 auto; }
        .content-box { border: 1px solid #ccc; background-color: #eee; padding: 15px; margin-top: 15px; text-align: right; white-space: pre-wrap; word-wrap: break-word; border-radius: 4px; }
        a { color: #007bff; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .flash-error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px; }
        .file-info { background-color: #e9f7fe; padding: 15px; border-radius: 4px; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>کلیپ‌بورد: {{ key }}</h2>
        
        {% if clip is none %}
            <div class="flash-error">
                {% if expired %}
                    ❌ این لینک منقضی شده و محتوای آن پاک شده است.
                {% else %}
                    ❌ محتوایی با این آدرس یافت نشد.
                {% endif %}
            </div>
            <p><a href="{{ url_for('index') }}">بازگشت به صفحه اصلی</a></p>
        {% else %}
            {% if file_path %}
                <div class="file-info">
                    <h3>فایل ضمیمه:</h3>
                    <p>برای دانلود فایل زیر کلیک کنید:</p>
                    <p><a href="{{ url_for('download_file', key=key) }}">دانلود فایل ({{ file_path.split('/')[-1].split('_', 1)[1] }})</a></p>
                </div>
            {% endif %}

            {% if content %}
                <h3>محتوای متنی:</h3>
                <div class="content-box">{{ content }}</div>
            {% endif %}
            
            <p style="margin-top: 20px;">⏱️ انقضا: محتوای باقی مانده: **{{ expiry_info }}**</p>
            <p><a href="{{ url_for('index') }}" style="margin-top: 20px; display: inline-block;">ایجاد یک کلیپ جدید</a></p>
        {% endif %}
    </div>
</body>
</html>
HTM_CLIPBOARD

# --- Initialize DB ---
print_status "4/6: Initializing SQLite database..."
$PYTHON_VENV_PATH -c "from app import init_db; init_db()"

# ============================================
# 5. Create Systemd Service
# ============================================
print_status "5/6: Creating systemd service for persistent running..."

cat > /etc/systemd/system/clipboard.service << SERVICEEOF
[Unit]
Description=Flask Clipboard Service
After=network.target

[Service]
Type=simple
# Using root is fine for this utility script, but typically a dedicated user is recommended
User=root 
WorkingDirectory=${INSTALL_DIR}
# Gunicorn command: 4 workers, binding to all interfaces on the specified port
ExecStart=${GUNICORN_VENV_PATH} --workers 4 --bind 0.0.0.0:${PORT} app:app
Restart=always
TimeoutSec=30

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable clipboard.service

# ============================================
# 6. Start Service
# ============================================
print_status "6/6: Starting the Clipboard service on port $PORT..."
systemctl start clipboard.service
sleep 5

# ============================================
# FINAL INSTRUCTIONS
# ============================================
echo ""
echo "================================================"
echo "🎉 Installation Complete (Clipboard Server)"
echo "================================================"
echo "✅ Service Status: $(systemctl is-active clipboard.service)"
echo "🌐 Your Clipboard Server is running on port $PORT."
echo "🔗 Access URL (Replace IP with your server's public IP):"
echo "   http://YOUR_SERVER_IP:$PORT/"
echo ""
echo "⚙️ Management Commands:"
echo "------------------------------------------------"
echo "Status:   systemctl status clipboard.service"
echo "Restart:  systemctl restart clipboard.service"
echo "Logs:     journalctl -u clipboard.service -f"
echo "------------------------------------------------"
echo "⚠️ Expiry: All files/texts are set to expire and be deleted after $EXPIRY_DAYS days."
echo "================================================"
