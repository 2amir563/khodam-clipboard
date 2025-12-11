#!/bin/bash
# Telegram Media Downloader Bot - Complete Unified Installer (V30 - Final Production Ready)

set -e

# --- Configuration ---
INSTALL_DIR="/opt/telegram-media-bot"
PORT="3214" # Port is not used for this script but keeping consistent with project style
EXPIRY_DAYS="2"
MAX_FILE_SIZE="2000" # Max file size in MB

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

# Check root access
if [ "$EUID" -ne 0 ]; then
    print_error "Please run with root access: sudo bash install_bot_final.sh"
    exit 1
fi

echo "=================================================="
echo "🤖 Telegram Downloader Bot Installer (V30)"
echo "=================================================="

# --- User Input ---
echo "🔑 Enter your Telegram Bot Token from @BotFather:"
read -p "📝 Bot Token: " BOT_TOKEN

if [ -z "$BOT_TOKEN" ]; then
    print_error "Bot Token is required!"
    exit 1
fi

echo "🌐 Enter an optional Proxy URL (e.g., socks5://user:pass@host:port). Leave blank if none:"
read -p "📝 Proxy URL: " PROXY_URL


# ============================================
# 1. System Update & Essential Tools
# ============================================
print_status "1/7: Updating system and installing essential tools (Python3, PIP, FFmpeg)..."
apt update -y
apt install -y python3 python3-pip ffmpeg curl wget nano git build-essential

# Remove old/system packages to prevent conflicts
print_status "1/7: Removing system yt-dlp packages to ensure latest version is used..."
apt remove -y youtube-dl yt-dlp 2>/dev/null || true

# ============================================
# 2. Create Project Structure and Venv
# ============================================
print_status "2/7: Creating project directory structure and Virtual Environment..."
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

mkdir -p downloads logs cookies tmp
chmod -R 777 downloads logs cookies tmp

# Create Virtual Environment and activate it
python3 -m venv venv
source venv/bin/activate

PYTHON_VENV_PATH="$INSTALL_DIR/venv/bin/python3"

# ============================================
# 3. Install Python Packages
# ============================================
print_status "3/7: Installing Python packages (yt-dlp, python-telegram-bot, dotenv)..."

cat > requirements.txt << 'REQEOF'
python-telegram-bot>=20.7
python-dotenv>=1.0.0
yt-dlp>=2024.4.9
aiofiles>=23.2.1
requests>=2.31.0
psutil>=5.9.8
REQEOF

pip install --upgrade pip
pip install -r requirements.txt

# Deactivate the venv for now
deactivate

# ============================================
# 4. Create Configuration (.env)
# ============================================
print_status "4/7: Creating configuration file (.env)..."

PROXY_LINE=""
if [ -n "$PROXY_URL" ]; then
    PROXY_LINE="PROXY_URL=\"${PROXY_URL}\""
    print_status "Proxy URL added to .env"
else
    PROXY_LINE="PROXY_URL="
fi

cat > "$INSTALL_DIR/.env" << ENVEOF
BOT_TOKEN=${BOT_TOKEN}
MAX_FILE_SIZE=${MAX_FILE_SIZE}
DELETE_AFTER_MINUTES=${EXPIRY_DAYS}
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
${PROXY_LINE}
ENVEOF

# ============================================
# 5. Create Bot File (bot.py - V30)
# ============================================
print_status "5/7: Creating main bot file (bot.py - V30 - English Code)..."

cat > "$INSTALL_DIR/bot.py" << 'PYEOF'
#!/usr/bin/env python3
"""
Telegram Media Downloader Bot - V30 (Production Ready)
"""

import os
import sys
import logging
import subprocess
import asyncio
import re
import json
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, unquote

from telegram import Update
from telegram.ext import (
    Application, 
    CommandHandler, 
    MessageHandler, 
    filters, 
    ContextTypes
)
from telegram.constants import ParseMode
from dotenv import load_dotenv

load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
DELETE_AFTER = int(os.getenv("DELETE_AFTER_MINUTES", "2"))
MAX_SIZE_MB = int(os.getenv("MAX_FILE_SIZE", "2000"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
PROXY_URL = os.getenv("PROXY_URL", "")

if not BOT_TOKEN:
    print("ERROR: BOT_TOKEN is missing in .env file.")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def clean_url(text):
    if not text: return None
    text = text.strip()
    url_pattern = r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+\.[a-z]{2,})'
    matches = re.findall(url_pattern, text, re.IGNORECASE)
    if matches:
        url = matches[0]
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        url = re.sub(r'[.,;:!?]+$', '', url)
        return unquote(url)
    return None

def format_size(bytes_val):
    if bytes_val is None: return "Unknown"
    try:
        bytes_val = float(bytes_val)
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"
    except:
        return "Unknown"

def build_common_cmd(url, output_path=None, dump_json=False):
    """Builds the common yt-dlp command list, applying proxy and cookies."""
    cmd = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "venv/bin/python3"), # Use venv python
        "-m", "yt_dlp",
        "--user-agent", USER_AGENT,
        "--no-warnings",
        "--ignore-errors",
        "--no-playlist",
        "--force-ipv4",
        "--add-header", "Accept-Language: en-US,en;q=0.5",
        "--add-header", "X-Requested-With: XMLHttpRequest",
        url
    ]
    
    if dump_json:
        cmd.extend(["--dump-json", "--skip-download"])
    elif output_path:
        cmd.extend([
            "-f", "bestvideo[ext=mp4]+bestaudio[ext=m4a]/bestvideo[ext=mp4]/best",
            "-o", output_path,
            "--concurrent-fragments", "4",
            "--limit-rate", "10M",
            "--retries", "10",               
            "--fragment-retries", "10",      
            "--no-check-certificate", 
            "--referer", "https://google.com/",
            "--http-chunk-size", "10M",
            "--force-overwrite"
        ])

    if PROXY_URL:
        cmd.extend(["--proxy", PROXY_URL])
        
    cookies_file = Path(os.path.dirname(os.path.abspath(__file__))) / "cookies" / "cookies.txt"
    if cookies_file.exists():
        cmd.extend(["--cookies", str(cookies_file)])
        
    return cmd

async def get_video_info(url):
    cmd = build_common_cmd(url, dump_json=True)
        
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30) 
        
        if process.returncode == 0:
            try:
                info = json.loads(stdout.decode('utf-8').strip().split('\n')[-1])
                return info.get('title', 'N/A')
            except json.JSONDecodeError:
                logger.error("Failed to decode JSON from yt-dlp info.")
                return "N/A"
        else:
            error_output = stderr.decode('utf-8', errors='ignore').strip().splitlines()[0] if stderr else "Unknown Error"
            logger.warning(f"Info fetch failed (Code {process.returncode}): {error_output}")
            
            if "logged-in" in error_output or "HTTP Error 404" in error_output:
                return "N/A (Access/Login Required)"
            
            return f"N/A (Error: {error_output.replace('ERROR: ', '')})"
        
    except Exception as e:
        logger.error(f"Error fetching video info: {e}")
        return "N/A (Internal Error)"

async def download_video(url, output_path):
    cmd = build_common_cmd(url, output_path=output_path)
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=480) 
        
        if process.returncode == 0:
            return True, "Success"
        else:
            error_output = stderr.decode('utf-8', errors='ignore')
            raw_error_line = error_output.strip().splitlines()[0] if error_output.strip() else "Unknown/Empty Error"

            if "HTTP Error 404" in error_output or "Private video" in error_output or "logged-in" in error_output:
                return False, f"Download failed. Access/Login Required. Please use cookies."
            
            if "HTTP Error 412" in error_output or "HTTP Error 403" in error_output:
                 return False, f"Download failed. Potential Geo-Block or Security Error. Try a proxy or cookies."

            logger.error(f"yt-dlp error output (Code {process.returncode}): {error_output[:500]}...")
            return False, f"Download failed: Check URL, Access, or Geo-Block. (Code: {process.returncode}). Raw Error: {raw_error_line}"
            
    except asyncio.TimeoutError:
        return False, "Download Timeout (8 minutes)."
    except Exception as e:
        return False, f"Internal Error: {str(e)}"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome = f"""
🤖 *UNIVERSAL Media Downloader Bot - V30*

📝 *How to Use:*
1. Send any media URL (Pinterest, Vimeo, Bilibili, etc.).
2. The bot will download and send the file with the video title in the caption.

⚠️ If you encounter 'Access/Login Required' errors, you must provide a valid `cookies.txt` file.
"""
    await update.message.reply_text(welcome, parse_mode=ParseMode.MARKDOWN)

async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    original_url = update.message.text
    url = clean_url(original_url)
    
    if not url:
        await update.message.reply_text("❌ *Invalid URL*", parse_mode=ParseMode.MARKDOWN)
        return
    
    msg = await update.message.reply_text(f"🔗 *Processing URL...*\n\nFetching video details...", parse_mode=ParseMode.MARKDOWN)
    video_title = await get_video_info(url)
    
    try:
        parsed = urlparse(url)
        site = parsed.netloc.split('.')[-2] if parsed.netloc.count('.') >= 2 else parsed.netloc.split('.')[0]
        site = site.replace('www.', '').split(':')[0].upper()
    except:
        site = "UNKNOWN"
        
    await msg.edit_text(f"📥 *Downloading...* (Title: {video_title[:50]}...)", parse_mode=ParseMode.MARKDOWN)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{site}_{timestamp}"
    output_template = f"downloads/{filename}.%(ext)s"
    
    success, result = await download_video(url, output_template)
    
    if not success:
        await msg.edit_text(f"❌ *Download Failed*\n\nError: `{result}`", parse_mode=ParseMode.MARKDOWN)
        return
    
    downloaded_files = list(Path(os.path.dirname(os.path.abspath(__file__))) / "downloads" / f"{filename}.*")
    downloaded_files.sort(key=lambda p: p.stat().st_size, reverse=True)
    
    if not downloaded_files:
        await msg.edit_text("❌ Download complete, but final file not found.", parse_mode=ParseMode.MARKDOWN)
        return
    
    file_path = downloaded_files[0]
    file_size = file_path.stat().st_size
    
    if file_size > (MAX_SIZE_MB * 1024 * 1024):
        file_path.unlink() 
        await msg.edit_text(f"❌ *File size exceeds limit:* {format_size(file_size)}", parse_mode=ParseMode.MARKDOWN)
        return
    
    await msg.edit_text(f"📤 *Uploading...*\n\nSize: {format_size(file_size)}", parse_mode=ParseMode.MARKDOWN)
    
    try:
        with open(file_path, 'rb') as file:
            file_ext = file_path.suffix.lower()
            
            caption_text = (
                f"**{video_title}**\n\n"
                f"✅ Download Complete!\n"
                f"Size: {format_size(file_size)}\n"
                f"Original URL: [Link]({url})"
            )
            
            if file_ext in ['.mp3', '.m4a', '.wav']:
                await update.message.reply_audio(audio=file, caption=caption_text, parse_mode=ParseMode.MARKDOWN)
            else: 
                await update.message.reply_video(
                    video=file, 
                    caption=caption_text, 
                    parse_mode=ParseMode.MARKDOWN,
                    supports_streaming=True
                )
        
        await msg.edit_text("🎉 *Success!*", parse_mode=ParseMode.MARKDOWN)
        
        async def delete_file_task():
            await asyncio.sleep(DELETE_AFTER * 60)
            if file_path.exists():
                try:
                    file_path.unlink()
                except Exception:
                    pass
        asyncio.create_task(delete_file_task())
        
    except Exception as upload_error:
        await msg.edit_text(f"❌ *Upload Failed*\n\nError: {str(upload_error)[:100]}", parse_mode=ParseMode.MARKDOWN)

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url))
    
    try:
        print("✅ Bot started polling...")
        app.run_polling(drop_pending_updates=True)
    except Exception as e:
        print(f"Bot failed to start polling: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
PYEOF

# --- Set executable permission
chmod +x "$INSTALL_DIR/bot.py"

# ============================================
# 6. Create Systemd Service
# ============================================
print_status "6/7: Creating systemd service for persistent running..."

cat > /etc/systemd/system/telegram-media-bot.service << SERVICEEOF
[Unit]
Description=Telegram Media Downloader Bot
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=10
User=root
WorkingDirectory=${INSTALL_DIR}
# ExecStart points to the python executable inside the VENV
ExecStart=${PYTHON_VENV_PATH} ${INSTALL_DIR}/bot.py
StandardOutput=append:/opt/telegram-media-bot/logs/bot.log
StandardError=append:/opt/telegram-media-bot/logs/bot-error.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload
systemctl enable telegram-media-bot.service

# ============================================
# 7. Start Service and Final Instructions
# ============================================
print_status "7/7: Starting the bot service..."
systemctl start telegram-media-bot.service
sleep 5

echo ""
echo "================================================"
echo "🎉 Installation Complete (Telegram Bot V30)"
echo "================================================"
echo "✅ Service Status: $(systemctl is-active telegram-media-bot.service)"
echo "⚠️ CRITICAL: To handle Access/Login errors, place your 'cookies.txt' file here:"
echo "   /opt/telegram-media-bot/cookies/cookies.txt"
echo "🌐 Proxy URL (if entered) is set in /opt/telegram-media-bot/.env"
echo "------------------------------------------------"
echo "Management Commands:"
echo "Status:   sudo systemctl status telegram-media-bot.service"
echo "Restart:  sudo systemctl restart telegram-media-bot.service"
echo "Logs:     sudo journalctl -u telegram-media-bot.service -f"
echo "================================================"
