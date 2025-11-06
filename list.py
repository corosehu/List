#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional Link & Group Saver Bot - Phase 3
Enhanced with Telegram Account Integration & Advanced Features

Features:
- Complete Telegram account login system with step-by-step flow
- Export all joined groups with detailed reporting
- Advanced duplicate tracking with separate export files
- Smart error handling for empty files
- Database stability improvements
- Crash-proof architecture

Contact Support:
- Owner: @Corose
- Support: @fxeeo

Author: Enhanced Version
"""

import asyncio
import csv
import datetime as dt
from datetime import timezone
import os
import re
import sqlite3
import json
import traceback
import logging
from pathlib import Path
from typing import Optional, Tuple, Dict, List, Any
from enum import Enum

from telegram import (
    Update,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    InputFile,
)
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ConversationHandler,
    filters,
    ContextTypes,
)

try:
    from telethon import TelegramClient
    from telethon.errors import (
        FloodWaitError, 
        AuthKeyUnregisteredError,
        PhoneCodeInvalidError,
        PhoneNumberInvalidError,
        SessionPasswordNeededError,
        PasswordHashInvalidError
    )
    from telethon.sessions import StringSession
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("Warning: Telethon not installed. Group export features will be disabled.")

# =========================
# === CONFIGURATION =======
# =========================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot_activity.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "8118285986:AAGFGuH_-i3y24Ig5j84eloIIpqFyBCXz9Y")
ADMIN_IDS = {6827291977}  # Your Telegram user IDs

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DEFAULT_FILE_FORMAT = os.getenv("FILE_FORMAT", "txt").lower()
MAX_LINKS_PER_FILE = int(os.getenv("MAX_LINKS_PER_FILE", "80000"))
MAX_BYTES_PER_FILE = int(os.getenv("MAX_BYTES_PER_FILE", str(50 * 1024 * 1024)))

# Login States
class LoginState(Enum):
    IDLE = 0
    # Phone-based login
    WAITING_API_ID = 1
    WAITING_API_HASH = 2
    WAITING_PHONE = 3
    WAITING_CODE = 4
    WAITING_2FA = 5
    LOGGED_IN = 6
    # Session-based login
    SESSION_WAITING_API_ID = 7
    SESSION_WAITING_API_HASH = 8
    SESSION_WAITING_STRING = 9

# Regex patterns
URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|www\d{0,3}[.]|t\.me/|telegram\.me/|[a-z0-9.\-]+\.[a-z]{2,})(?:[^\s<>"]+))'
)
USERNAME_REGEX = re.compile(r'@([a-zA-Z0-9_]{5,32})')
TELEGRAM_LINK_REGEX = re.compile(r'(https?://)?(www\.)?(t\.me|telegram\.me)/([a-zA-Z0-9_]{5,32})/?')

# =========================
# === DATABASE SETUP ======
# =========================

def ensure_chat_dirs(chat_id: int) -> Path:
    """Create necessary directories for a chat."""
    chat_dir = DATA_DIR / str(chat_id)
    chat_dir.mkdir(parents=True, exist_ok=True)
    for subdir in ["files", "duplicates", "exports", "failed", "reports"]:
        (chat_dir / subdir).mkdir(exist_ok=True)
    return chat_dir

def db_path(chat_id: int) -> Path:
    return ensure_chat_dirs(chat_id) / "store.sqlite3"

def migrate_database(conn: sqlite3.Connection) -> None:
    """Migrate database schema to latest version."""
    # Check and add missing columns to user_sessions table
    cursor = conn.cursor()
    
    # Get existing columns in user_sessions table
    cursor.execute("PRAGMA table_info(user_sessions)")
    existing_columns = {col[1] for col in cursor.fetchall()}
    
    # Required columns for user_sessions
    required_columns = {
        'user_id': 'INTEGER PRIMARY KEY',
        'api_id': 'TEXT',
        'api_hash': 'TEXT',
        'session_string': 'TEXT',
        'phone_number': 'TEXT',
        'login_state': 'TEXT',
        'created_at': 'TEXT',
        'last_used': 'TEXT'
    }
    
    # Add missing columns
    for col_name, col_type in required_columns.items():
        if col_name not in existing_columns and col_name != 'user_id':
            try:
                conn.execute(f"ALTER TABLE user_sessions ADD COLUMN {col_name} {col_type}")
                print(f"✅ Added missing column: {col_name}")
            except sqlite3.OperationalError:
                pass  # Column might already exist
    
    conn.commit()

def connect_db(chat_id: int) -> sqlite3.Connection:
    """Connect to database with proper schema and migration."""
    conn = sqlite3.connect(db_path(chat_id))
    conn.execute("PRAGMA journal_mode=WAL;")
    
    # Create tables with proper schema
    conn.execute("""
        CREATE TABLE IF NOT EXISTS links (
            content TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            added_at TEXT NOT NULL
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS duplicates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            type TEXT NOT NULL,
            seen_at TEXT NOT NULL,
            duplicate_count INTEGER DEFAULT 1
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            k TEXT PRIMARY KEY,
            v INTEGER NOT NULL
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            link_count INTEGER NOT NULL DEFAULT 0,
            bytes INTEGER NOT NULL DEFAULT 0,
            format TEXT NOT NULL
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            user_id INTEGER PRIMARY KEY,
            api_id TEXT,
            api_hash TEXT,
            session_string TEXT,
            phone_number TEXT,
            login_state TEXT,
            created_at TEXT NOT NULL,
            last_used TEXT
        )
    """)
    
    conn.execute("""
        CREATE TABLE IF NOT EXISTS export_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            export_date TEXT NOT NULL,
            groups_count INTEGER,
            success_count INTEGER,
            failed_count INTEGER,
            export_file TEXT,
            failed_file TEXT,
            links_file TEXT
        )
    """)
    
    conn.commit()
    
    # Run migrations to add any missing columns
    migrate_database(conn)
    
    return conn

# =========================
# === HELPER FUNCTIONS ====
# =========================

def get_stat(conn: sqlite3.Connection, key: str) -> int:
    cur = conn.execute("SELECT v FROM stats WHERE k=?", (key,))
    row = cur.fetchone()
    return int(row[0]) if row else 0

def incr_stat(conn: sqlite3.Connection, key: str, delta: int = 1) -> None:
    current = get_stat(conn, key)
    conn.execute("INSERT OR REPLACE INTO stats(k,v) VALUES(?,?)", (key, current + delta))

def set_current_file(chat_id: int, path: Path, fmt: str) -> None:
    ensure_chat_dirs(chat_id)
    meta_path = ensure_chat_dirs(chat_id) / "current_meta.txt"
    meta_path.write_text(f"{path.name}|{fmt}", encoding="utf-8")

def read_current_file(chat_id: int) -> Tuple[Optional[Path], str]:
    meta_path = ensure_chat_dirs(chat_id) / "current_meta.txt"
    fmt = DEFAULT_FILE_FORMAT
    if meta_path.exists():
        try:
            raw = meta_path.read_text(encoding="utf-8").strip()
            if "|" in raw:
                name, fmt = raw.split("|", 1)
                p = (ensure_chat_dirs(chat_id) / "files" / name).resolve()
                if p.exists():
                    return p, fmt
        except Exception:
            pass
    return None, fmt

def next_file_name(chat_id: int, fmt: str) -> Path:
    files_dir = ensure_chat_dirs(chat_id) / "files"
    existing = sorted(files_dir.glob(f"links_*.{fmt}"))
    next_idx = 1
    if existing:
        try:
            last = existing[-1].stem
            next_idx = int(last.split("_")[1]) + 1
        except Exception:
            next_idx = len(existing) + 1
    return files_dir / f"links_{next_idx:03d}.{fmt}"

def ensure_file_not_empty(file_path: Path, fmt: str) -> None:
    """Ensure file is not empty to avoid Telegram upload errors."""
    if not file_path.exists() or file_path.stat().st_size == 0:
        with file_path.open("w", encoding="utf-8") as f:
            if fmt == "csv":
                writer = csv.writer(f)
                writer.writerow(["content", "type", "added_at"])
                writer.writerow(["[Empty File]", "placeholder", dt.datetime.now(dt.timezone.utc).isoformat()])
            else:
                f.write("# Links and Usernames File\n")
                f.write(f"# Created: {dt.datetime.now(dt.timezone.utc).isoformat()}\n")
                f.write("# No content yet\n")

def write_content_to_file(path: Path, content: str, content_type: str, fmt: str) -> int:
    """Write content to file and return bytes written."""
    if fmt == "csv":
        new_file = not path.exists() or path.stat().st_size == 0
        with path.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["content", "type", "added_at"])
            ts = dt.datetime.now(dt.timezone.utc).isoformat()
            w.writerow([content, content_type, ts])
            return len(content) + len(content_type) + len(ts) + 10
    else:
        line = f"{content} ({content_type}) - {dt.datetime.now(dt.timezone.utc).isoformat()}\n"
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
        return len(line.encode("utf-8"))

def save_duplicate(chat_id: int, content: str, content_type: str, conn: sqlite3.Connection) -> None:
    """Save duplicate to database and file."""
    # Save to database
    conn.execute(
        "INSERT INTO duplicates(content, type, seen_at, duplicate_count) VALUES(?,?,?,1)",
        (content, content_type, dt.datetime.now(dt.timezone.utc).isoformat())
    )
    
    # Save to duplicate file
    _, fmt = read_current_file(chat_id)
    dup_path = ensure_chat_dirs(chat_id) / "duplicates" / f"duplicates.{fmt}"
    
    if fmt == "csv":
        new_file = not dup_path.exists() or dup_path.stat().st_size == 0
        with dup_path.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["content", "type", "duplicate_found_at"])
            w.writerow([content, content_type, dt.datetime.now(dt.timezone.utc).isoformat()])
    else:
        with dup_path.open("a", encoding="utf-8") as f:
            f.write(f"{content} ({content_type}) - Duplicate at {dt.datetime.now(dt.timezone.utc).isoformat()}\n")

def format_bytes(n: int) -> str:
    """Format bytes to human readable."""
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"

# =========================
# === ACCESS CONTROL ======
# =========================

def is_admin(user_id: Optional[int]) -> bool:
    return user_id in ADMIN_IDS

async def admin_guard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    uid = update.effective_user.id if update.effective_user else None
    if not is_admin(uid):
        await update.effective_message.reply_text(
            "❌ **Access Denied**\n\n"
            "This is an admin-only bot.\n\n"
            "**Contact Support:**\n"
            "Owner: @Corose\n"
            "Support: @fxeeo",
            parse_mode=ParseMode.MARKDOWN
        )
        return False
    return True

# =========================
# === UI KEYBOARDS ========
# =========================

def main_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton("📤 Upload Current File", callback_data="upload_file")],
        [InlineKeyboardButton("📥 Download Current File", callback_data="dl_current")],
        [
            InlineKeyboardButton("📄 New File", callback_data="new_file"),
            InlineKeyboardButton("📊 Statistics", callback_data="stats")
        ],
        [
            InlineKeyboardButton("📋 Use CSV", callback_data="fmt_csv"),
            InlineKeyboardButton("📝 Use TXT", callback_data="fmt_txt")
        ],
        [
            InlineKeyboardButton("🔄 Download Duplicates", callback_data="dl_duplicates"),
            InlineKeyboardButton("🧹 Clean Duplicates", callback_data="clean_duplicates")
        ],
        [InlineKeyboardButton("👤 Telegram Account Login", callback_data="tg_login")]
    ]
    
    return InlineKeyboardMarkup(buttons)

def login_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔐 Start Login Process", callback_data="start_login")],
        [InlineKeyboardButton("🔑 Login with Session String", callback_data="session_login")],
        [InlineKeyboardButton("📋 Check Login Status", callback_data="login_status")],
        [InlineKeyboardButton("🔄 Reset Login", callback_data="reset_login")],
        [InlineKeyboardButton("◀️ Back to Main", callback_data="back_main")]
    ])

def export_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📥 Import My Groups", callback_data="import_groups")],
        [InlineKeyboardButton("📊 Export History", callback_data="export_history")],
        [InlineKeyboardButton("📥 Download Exports", callback_data="dl_exports")],
        [InlineKeyboardButton("◀️ Back to Main", callback_data="back_main")]
    ])

# =========================
# === LOGIN SYSTEM ========
# =========================

async def save_user_credentials(chat_id: int, user_id: int, data: Dict[str, Any]) -> None:
    """Save user credentials and session."""
    conn = connect_db(chat_id)
    conn.execute(
        """INSERT OR REPLACE INTO user_sessions
           (user_id, api_id, api_hash, session_string, phone_number, login_state, created_at, last_used)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            user_id,
            data.get('api_id'),
            data.get('api_hash'),
            data.get('session_string'),
            data.get('phone_number'),
            data.get('login_state', LoginState.IDLE.name),
            data.get('created_at', dt.datetime.now(dt.timezone.utc).isoformat()),
            dt.datetime.now(dt.timezone.utc).isoformat()
        )
    )
    conn.commit()
    conn.close()

async def get_user_session(chat_id: int, user_id: int) -> Optional[Dict[str, Any]]:
    """Get user session data."""
    conn = connect_db(chat_id)
    cur = conn.execute(
        "SELECT api_id, api_hash, session_string, phone_number, login_state FROM user_sessions WHERE user_id=?",
        (user_id,)
    )
    row = cur.fetchone()
    conn.close()
    
    if row:
        return {
            'api_id': row[0],
            'api_hash': row[1],
            'session_string': row[2],
            'phone_number': row[3],
            'login_state': row[4]
        }
    return None

async def handle_login_process(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle step-by-step login process."""
    if not await admin_guard(update, context):
        return
    
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    text = update.effective_message.text.strip()
    
    # Get current login state
    login_state = context.user_data.get('login_state', LoginState.IDLE)
    
    try:
        if login_state == LoginState.WAITING_API_ID:
            # Validate API ID
            if not text.isdigit():
                await update.message.reply_text("❌ Invalid API ID. Please enter numbers only.")
                return
            
            context.user_data['api_id'] = text
            context.user_data['login_state'] = LoginState.WAITING_API_HASH
            
            await update.message.reply_text(
                "✅ API ID saved.\n\n"
                "Now enter your **API Hash**:\n"
                "(32-character string from my.telegram.org)",
                parse_mode=ParseMode.MARKDOWN
            )
            
        elif login_state == LoginState.WAITING_API_HASH:
            # Validate API Hash
            if len(text) != 32:
                await update.message.reply_text("❌ Invalid API Hash. It should be exactly 32 characters.")
                return
            
            context.user_data['api_hash'] = text
            context.user_data['login_state'] = LoginState.WAITING_PHONE
            
            await update.message.reply_text(
                "✅ API Hash saved.\n\n"
                "Now enter your **Phone Number**:\n"
                "(Include country code, e.g., +1234567890)",
                parse_mode=ParseMode.MARKDOWN
            )
            
        elif login_state == LoginState.WAITING_PHONE:
            # Validate phone number
            if not text.startswith('+'):
                await update.message.reply_text(
                    "❌ Please include country code.\n"
                    "Example: +1234567890"
                )
                return
            
            context.user_data['phone_number'] = text
            context.user_data['login_state'] = LoginState.WAITING_CODE
            
            # Initialize Telethon client
            if not TELETHON_AVAILABLE:
                await update.message.reply_text(
                    "❌ Telethon library not installed.\n"
                    "Please install: pip install telethon"
                )
                context.user_data.clear()
                return
            
            try:
                api_id = int(context.user_data['api_id'])
                api_hash = context.user_data['api_hash']
                
                client = TelegramClient(StringSession(), api_id, api_hash)
                await client.connect()
                
                result = await client.send_code_request(text)
                context.user_data['phone_code_hash'] = result.phone_code_hash
                context.user_data['temp_client'] = client
                
                await update.message.reply_text(
                    "✅ Code sent to your phone!\n\n"
                    "Enter the **verification code** you received:",
                    parse_mode=ParseMode.MARKDOWN
                )
                
            except PhoneNumberInvalidError:
                await update.message.reply_text("❌ Invalid phone number. Please try again.")
                context.user_data['login_state'] = LoginState.WAITING_PHONE
            except Exception as e:
                await update.message.reply_text(f"❌ Error: {str(e)}")
                context.user_data.clear()
                
        elif login_state == LoginState.WAITING_CODE:
            # Handle verification code
            client = context.user_data.get('temp_client')
            if not client:
                await update.message.reply_text("❌ Session expired. Please restart login.")
                context.user_data.clear()
                return
            
            try:
                phone = context.user_data['phone_number']
                await client.sign_in(phone, text)
                
                # Login successful
                session_string = client.session.save()
                
                # Save credentials
                await save_user_credentials(chat_id, user_id, {
                    'api_id': context.user_data['api_id'],
                    'api_hash': context.user_data['api_hash'],
                    'session_string': session_string,
                    'phone_number': phone,
                    'login_state': LoginState.LOGGED_IN.name
                })
                
                await client.disconnect()
                context.user_data.clear()
                
                await update.message.reply_text(
                    "✅ **Login Successful!**\n\n"
                    "Your session has been saved.\n"
                    "You can now export your groups.\n\n"
                    "Use the buttons below to proceed:",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
                
            except SessionPasswordNeededError:
                # 2FA required
                context.user_data['login_state'] = LoginState.WAITING_2FA
                await update.message.reply_text(
                    "🔐 **Two-Factor Authentication Required**\n\n"
                    "Please enter your 2FA password:",
                    parse_mode=ParseMode.MARKDOWN
                )
                
            except PhoneCodeInvalidError:
                await update.message.reply_text(
                    "❌ Invalid code. Please try again.\n"
                    "Enter the correct verification code:"
                )
                
            except Exception as e:
                await update.message.reply_text(f"❌ Login failed: {str(e)}")
                context.user_data.clear()
                
        elif login_state == LoginState.WAITING_2FA:
            # Handle 2FA password
            client = context.user_data.get('temp_client')
            if not client:
                await update.message.reply_text("❌ Session expired. Please restart login.")
                context.user_data.clear()
                return
            
            try:
                await client.sign_in(password=text)
                
                # Login successful
                session_string = client.session.save()
                
                # Save credentials
                await save_user_credentials(chat_id, user_id, {
                    'api_id': context.user_data['api_id'],
                    'api_hash': context.user_data['api_hash'],
                    'session_string': session_string,
                    'phone_number': context.user_data['phone_number'],
                    'login_state': LoginState.LOGGED_IN.name
                })
                
                await client.disconnect()
                context.user_data.clear()
                
                await update.message.reply_text(
                    "✅ **Login Successful with 2FA!**\n\n"
                    "Your session has been saved.\n"
                    "You can now export your groups.",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
                
            except PasswordHashInvalidError:
                await update.message.reply_text(
                    "❌ Invalid 2FA password. Please try again.\n"
                    "Enter your correct 2FA password:"
                )
                
            except Exception as e:
                await update.message.reply_text(f"❌ 2FA login failed: {str(e)}")
                context.user_data.clear()

        # --- Session String Login Flow ---
        elif login_state == LoginState.SESSION_WAITING_API_ID:
            if not text.isdigit():
                await update.message.reply_text("❌ Invalid API ID. Please enter numbers only.")
                return
            context.user_data['api_id'] = text
            context.user_data['login_state'] = LoginState.SESSION_WAITING_API_HASH
            await update.message.reply_text(
                "✅ API ID saved.\n\n"
                "Step 2/3: **API Hash**\n\n"
                "Now enter your API Hash:",
                parse_mode=ParseMode.MARKDOWN
            )

        elif login_state == LoginState.SESSION_WAITING_API_HASH:
            if len(text) != 32:
                await update.message.reply_text("❌ Invalid API Hash. It should be 32 characters.")
                return
            context.user_data['api_hash'] = text
            context.user_data['login_state'] = LoginState.SESSION_WAITING_STRING
            await update.message.reply_text(
                "✅ API Hash saved.\n\n"
                "Step 3/3: **Session String**\n\n"
                "Now paste your full Telethon session string:",
                parse_mode=ParseMode.MARKDOWN
            )

        elif login_state == LoginState.SESSION_WAITING_STRING:
            session_string = text
            api_id = context.user_data.get('api_id')
            api_hash = context.user_data.get('api_hash')

            if not all([api_id, api_hash, session_string]):
                await update.message.reply_text("❌ Session validation failed: Missing credentials. Please restart.")
                context.user_data.clear()
                return

            client = TelegramClient(StringSession(session_string), int(api_id), api_hash)
            try:
                await client.connect()
                if not await client.is_user_authorized():
                    await update.message.reply_text(
                        "❌ **Session Invalid or Expired**\n\nPlease check your session string and try again.",
                        parse_mode=ParseMode.MARKDOWN,
                        reply_markup=login_keyboard()
                    )
                    context.user_data.clear()
                    return

                me = await client.get_me()
                phone = me.phone
                username = me.username or "N/A"

                await save_user_credentials(chat_id, user_id, {
                    'api_id': api_id,
                    'api_hash': api_hash,
                    'session_string': session_string,
                    'phone_number': phone,
                    'login_state': LoginState.LOGGED_IN.name
                })

                await update.message.reply_text(
                    f"✅ **Session Login Successful!**\n\n"
                    f"Logged in as:\n"
                    f"• User: @{username}\n"
                    f"• Phone: +{phone}\n\n"
                    "You can now export your groups.",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )

            except Exception as e:
                await update.message.reply_text(
                    f"❌ **Session Validation Failed**\n\nError: `{str(e)}`\n\nPlease check your credentials and session string.",
                    parse_mode=ParseMode.MARKDOWN
                )
            finally:
                if client.is_connected():
                    await client.disconnect()
                context.user_data.clear()
                
    except Exception as e:
        await update.message.reply_text(f"❌ Unexpected error: {str(e)}")
        print(f"Login error: {traceback.format_exc()}")
        context.user_data.clear()

# =========================
# === GROUP IMPORT ========
# =========================

async def import_user_groups(chat_id: int, user_id: int, progress_callback: Optional[callable] = None) -> Dict[str, Any]:
    """Scans all user's groups and saves public links/usernames to the database."""
    result = {
        "success": False,
        "groups_count": 0,
        "added": 0,
        "skipped": 0,
        "failed_count": 0,
        "error": None
    }
    
    try:
        session_data = await get_user_session(chat_id, user_id)
        if not session_data or not session_data.get('session_string'):
            result["error"] = "No active session. Please login first."
            return result
        
        api_id = int(session_data['api_id'])
        api_hash = session_data['api_hash']
        session_string = session_data['session_string']
        
        client = TelegramClient(StringSession(session_string), api_id, api_hash)
        await client.connect()
        
        if not await client.is_user_authorized():
            result["error"] = "Session expired. Please login again."
            await client.disconnect()
            return result
        
        conn = connect_db(chat_id)
        current_file, current_fmt = read_current_file(chat_id)
        if not current_file:
            current_file = next_file_name(chat_id, current_fmt)
            set_current_file(chat_id, current_file, current_fmt)

        dialogs = await client.get_dialogs()
        total_dialogs = len(dialogs)
        
        for i, dialog in enumerate(dialogs):
            result["groups_count"] += 1
            try:
                if (dialog.is_group or dialog.is_channel) and dialog.entity.username:
                    username = dialog.entity.username
                    
                    # Add both @username and t.me/ link to ensure comprehensive capture
                    # The _add_content_to_db function will handle normalization and prevent duplicates
                    
                    # Add as link
                    a, s = _add_content_to_db(conn, chat_id, current_file, current_fmt, f"https://t.me/{username}", "link")
                    result["added"] += a
                    result["skipped"] += s
                    
                    # Add as username
                    a, s = _add_content_to_db(conn, chat_id, current_file, current_fmt, username, "username")
                    result["added"] += a
                    result["skipped"] += s

                    await asyncio.sleep(0.05) # Small delay to be safe
                    
            except Exception as e:
                logger.warning(f"Could not process group '{dialog.name}': {e}")
                result["failed_count"] += 1

            # Update progress
            if progress_callback and (i + 1) % 10 == 0:
                await progress_callback(i + 1, total_dialogs)

        # Final progress update
        if progress_callback:
            await progress_callback(total_dialogs, total_dialogs)

        conn.commit()
        conn.close()
        await client.disconnect()

        # Log this import event to history for tracking
        history_conn = connect_db(chat_id)
        try:
             history_conn.execute(
                """INSERT INTO export_history 
                   (user_id, export_date, groups_count, success_count, failed_count)
                   VALUES (?,?,?,?,?)""",
                (
                    user_id,
                    dt.datetime.now(dt.timezone.utc).isoformat(),
                    result["groups_count"],
                    result["added"], # Using success_count to store 'added'
                    result["failed_count"]
                )
            )
             history_conn.commit()
        except Exception as e:
            logger.error(f"Failed to save import history: {e}")
        finally:
            history_conn.close()

        result["success"] = True
        
    except Exception as e:
        result["error"] = f"Import failed: {str(e)}"
        logger.error(f"Group import error: {traceback.format_exc()}")
    
    return result

# =========================
# === COMMAND HANDLERS ====
# =========================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return
    
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    # Check for existing session
    session_status = ""
    session_data = await get_user_session(chat_id, user_id)
    if session_data and session_data.get('session_string'):
        try:
            # Quick session validation
            api_id = int(session_data['api_id'])
            api_hash = session_data['api_hash']
            session_string = session_data['session_string']
            
            client = TelegramClient(StringSession(session_string), api_id, api_hash)
            await client.connect()
            is_authorized = await client.is_user_authorized()
            await client.disconnect()
            
            if is_authorized:
                session_status = "\n\n✅ **Active Session Found!**\nYou can directly export groups."
        except:
            pass
    
    welcome_text = (
        "🚀 **Professional Link & Group Saver Bot**\n\n"
        "**Features:**\n"
        "• Save links and @usernames automatically\n"
        "• Advanced duplicate detection system\n"
        "• Multiple file formats (CSV/TXT)\n"
        "• Telegram account integration\n"
        "• Export all joined groups\n"
        "• Create links file from groups\n"
        "• Professional data management\n\n"
        "Send messages with links or @usernames to start."
        f"{session_status}\n\n"
        "**Support:** @Corose | @fxeeo"
    )
    
    await update.message.reply_text(
        welcome_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard()
    )

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return
    
    help_text = (
        "📚 **Bot Commands**\n\n"
        "**Basic:**\n"
        "/start - Start the bot\n"
        "/help - Show this help\n"
        "/stats - View statistics\n\n"
        "**File Management:**\n"
        "/newfile - Create new file\n"
        "/download - Download current file\n"
        "/duplicates - Download duplicate records\n\n"
        "**Format:**\n"
        "/usecsv - Switch to CSV format\n"
        "/usetxt - Switch to TXT format\n\n"
        "**Account Features:**\n"
        "/login - Telegram account login\n"
        "/import - Import your groups\n\n"
        "**Support:** @Corose | @fxeeo"
    )
    
    await update.message.reply_text(
        help_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard()
    )

async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return
    
    chat_id = update.effective_chat.id
    conn = connect_db(chat_id)
    
    total_content = get_stat(conn, "content_total")
    dups = get_stat(conn, "dups_total")
    files_total = get_stat(conn, "files_total")
    links_saved = get_stat(conn, "links_saved")
    usernames_saved = get_stat(conn, "usernames_saved")
    
    # Get export history count
    cur = conn.execute("SELECT COUNT(*) FROM export_history")
    export_count = cur.fetchone()[0]
    
    conn.close()
    
    stats_text = (
        f"📊 **Bot Statistics**\n\n"
        f"**Content:**\n"
        f"• Total saved: {total_content:,}\n"
        f"• Links: {links_saved:,}\n"
        f"• Usernames: {usernames_saved:,}\n"
        f"• Duplicates: {dups:,}\n\n"
        f"**Files:**\n"
        f"• Generated: {files_total:,}\n"
        f"• Exports: {export_count}\n\n"
        f"**Support:** @Corose | @fxeeo"
    )
    
    await update.message.reply_text(
        stats_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=main_keyboard()
    )

# =========================
# === CALLBACK HANDLERS ===
# =========================

async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return
    
    q = update.callback_query
    await q.answer()
    data = q.data
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    
    try:
        if data == "upload_file":
            await q.edit_message_text(
                "📤 **Upload & Restore**\n\n"
                "This feature allows you to restore links and usernames from a previously exported `.txt` or `.csv` file.\n\n"
                "**How it works:**\n"
                "1. Send a file containing links or @usernames.\n"
                "2. The bot will read the file and add all unique entries to the main database.\n"
                "3. Duplicates will be automatically skipped.\n\n"
                "⚠️ **Important:** This does not import or join groups. It only restores individual links and usernames to the bot's saved collection.\n\n"
                "Please send your file now.",
                parse_mode=ParseMode.MARKDOWN
            )
            # Set a state to expect file
            context.user_data["expecting_upload"] = True

        elif data == "tg_login":
            await q.edit_message_text(
                "👤 **Telegram Account Login**\n\n"
                "Login with your Telegram account to:\n"
                "• Export all joined groups\n"
                "• Get detailed group information\n"
                "• Create links file from groups\n\n"
                "Your credentials are securely stored.",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=login_keyboard()
            )
            
        elif data == "start_login":
            context.user_data['login_state'] = LoginState.WAITING_API_ID
            await q.edit_message_text(
                "🔐 **Phone Login Process**\n\n"
                "Step 1/3: **API ID**\n\n"
                "Please enter your API ID:\n"
                "(Get it from https://my.telegram.org)",
                parse_mode=ParseMode.MARKDOWN
            )

        elif data == "session_login":
            context.user_data['login_state'] = LoginState.SESSION_WAITING_API_ID
            await q.edit_message_text(
                "🔑 **Session String Login**\n\n"
                "Step 1/3: **API ID**\n\n"
                "Please enter your API ID:",
                parse_mode=ParseMode.MARKDOWN
            )
            
        elif data == "login_status":
            session_data = await get_user_session(chat_id, user_id)
            if session_data and session_data.get('session_string'):
                # Test if session is still valid
                try:
                    api_id = int(session_data['api_id'])
                    api_hash = session_data['api_hash']
                    session_string = session_data['session_string']
                    
                    client = TelegramClient(StringSession(session_string), api_id, api_hash)
                    await client.connect()
                    is_authorized = await client.is_user_authorized()
                    await client.disconnect()
                    
                    if is_authorized:
                        status_text = (
                            "✅ **Login Status: Active**\n\n"
                            f"Phone: {session_data.get('phone_number', 'N/A')}\n"
                            f"Session: Valid ✓\n\n"
                            "**You can now:**\n"
                            "• Export all your groups\n"
                            "• Create links file\n"
                            "• Access export history\n\n"
                            "Session will persist even after bot restart."
                        )
                        await q.edit_message_text(
                            status_text,
                            parse_mode=ParseMode.MARKDOWN,
                            reply_markup=export_keyboard()
                        )
                    else:
                        status_text = (
                            "⚠️ **Session Expired**\n\n"
                            "Your saved session has expired.\n"
                            "Please login again to continue."
                        )
                        await q.edit_message_text(
                            status_text,
                            parse_mode=ParseMode.MARKDOWN,
                            reply_markup=login_keyboard()
                        )
                except Exception as e:
                    status_text = (
                        "❌ **Session Check Failed**\n\n"
                        f"Error: {str(e)}\n\n"
                        "Please try logging in again."
                    )
                    await q.edit_message_text(
                        status_text,
                        parse_mode=ParseMode.MARKDOWN,
                        reply_markup=login_keyboard()
                    )
            else:
                status_text = (
                    "❌ **Login Status: Not Logged In**\n\n"
                    "Please use 'Start Login Process' to begin."
                )
                await q.edit_message_text(
                    status_text,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=login_keyboard()
                )
            
        elif data == "reset_login":
            conn = connect_db(chat_id)
            conn.execute("DELETE FROM user_sessions WHERE user_id=?", (user_id,))
            conn.commit()
            conn.close()
            context.user_data.clear()
            
            await q.edit_message_text(
                "🔄 **Login Reset Complete**\n\n"
                "All saved credentials have been cleared.\n"
                "You can start a fresh login process.",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=login_keyboard()
            )
            
        elif data == "import_groups":
            # Check if user is logged in first
            session_data = await get_user_session(chat_id, user_id)
            if not session_data or not session_data.get('session_string'):
                await q.edit_message_text(
                    "❌ **Not Logged In**\n\n"
                    "Please login first using the 'Telegram Account Login' option.",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=main_keyboard()
                )
                return
            
            processing_message = await q.edit_message_text("🔄 Processing... Please wait.")
            
            async def progress_callback(current, total):
                percentage = (current / total) * 100
                try:
                    await processing_message.edit_text(f"🔄 Processing... {percentage:.1f}%")
                except Exception: # Ignore potential "message not modified" errors
                    pass

            result = await import_user_groups(chat_id, user_id, progress_callback)
            
            if not result["success"]:
                await processing_message.edit_text(
                    f"❌ **Import Failed**\n\n{result['error']}",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
            else:
                conn = connect_db(chat_id)
                total_content = get_stat(conn, "content_total")
                conn.close()

                status_text = (
                    f"✅ **Import Complete!**\n\n"
                    f"**Scan Summary:**\n"
                    f"• Groups Scanned: {result['groups_count']:,}\n"
                    f"• New Items Added: {result['added']:,}\n"
                    f"• Duplicates Found: {result['skipped']:,}\n\n"
                    f"**Database Status:**\n"
                    f"• Total Saved Items: {total_content:,}\n"
                )
                
                if result['failed_count'] > 0:
                    status_text += f"\n⚠️ Encountered errors with {result['failed_count']} groups. Check logs for details."

                await q.edit_message_text(
                    status_text,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
                    
        elif data == "export_history":
            conn = connect_db(chat_id)
            cur = conn.execute(
                """SELECT export_date, groups_count, success_count, failed_count 
                   FROM export_history WHERE user_id=? ORDER BY id DESC LIMIT 5""",
                (user_id,)
            )
            history = cur.fetchall()
            conn.close()
            
            if history:
                history_text = "📊 **Import History**\n\n"
                for row in history:
                    date = dt.datetime.fromisoformat(row[0]).strftime("%Y-%m-%d %H:%M")
                    history_text += (
                        f"**{date}**\n"
                        f"• Groups Scanned: {row[1]}\n"
                        f"• New Items Added: {row[2]}\n"
                        f"• Errors: {row[3]}\n\n"
                    )
            else:
                history_text = "📊 **Import History**\n\nNo imports yet."
            
            await q.edit_message_text(
                history_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=export_keyboard()
            )
        
        elif data == "dl_exports":
            export_dir = ensure_chat_dirs(chat_id) / "exports"
            export_files = sorted(export_dir.glob("*.csv"), key=lambda x: x.stat().st_mtime, reverse=True)[:3]
            
            if not export_files:
                await q.edit_message_text(
                    "📁 No export files found.",
                    reply_markup=export_keyboard()
                )
            else:
                await q.edit_message_text("📤 Sending export files...")
                for file_path in export_files:
                    ensure_file_not_empty(file_path, "csv")
                    await q.message.reply_document(
                        document=InputFile(file_path.open("rb"), filename=file_path.name),
                        caption=f"📋 Export: {file_path.name}"
                    )
                    
        elif data == "dl_duplicates":
            _, fmt = read_current_file(chat_id)
            dup_path = ensure_chat_dirs(chat_id) / "duplicates" / f"duplicates.{fmt}"
            
            if not dup_path.exists():
                await q.edit_message_text("No duplicates file found.", reply_markup=main_keyboard())
            else:
                ensure_file_not_empty(dup_path, fmt)
                await q.message.reply_document(
                    document=InputFile(dup_path.open("rb"), filename=dup_path.name),
                    caption=f"🔄 Duplicates: {dup_path.name}"
                )
                
        elif data == "back_main":
            await q.edit_message_text(
                "🏠 **Main Menu**\n\nChoose an option below:",
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=main_keyboard()
            )
            
        else:
            # Handle other existing callbacks
            conn = connect_db(chat_id)
            
            if data == "dl_current":
                processing_message = await q.edit_message_text("🔄 Processing... Please wait.")

                export_dir = ensure_chat_dirs(chat_id) / "exports"
                fmt = "csv"  # Force CSV format for this export
                timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                export_file = export_dir / f"Full_Export_{timestamp}.{fmt}"

                all_content = conn.execute("SELECT content, type FROM links ORDER BY added_at ASC").fetchall()
                total = len(all_content)

                if not all_content:
                    await processing_message.edit_text("❌ No data found in the database to export.")
                    return

                # Write directly to CSV format
                with export_file.open("w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["content", "type"])
                    for i, (content, ctype) in enumerate(all_content):
                        writer.writerow([content, ctype])
                        if (i + 1) % 100 == 0:
                            percentage = ((i + 1) / total) * 100
                            try:
                                await processing_message.edit_text(f"🔄 Processing... {percentage:.1f}%")
                            except Exception: pass

                await q.message.reply_document(
                    document=InputFile(export_file.open("rb"), filename=f"Full_Data_Export.{fmt}"),
                    caption=f"✅ **Full Data Export**\n\n"
                            f"• Total Items: {total:,}\n"
                            f"• Format: {fmt.upper()}",
                    parse_mode=ParseMode.MARKDOWN
                )
                await processing_message.delete()

            elif data == "new_file":
                _, fmt = read_current_file(chat_id)
                p = next_file_name(chat_id, fmt)
                p.touch(exist_ok=True)
                ensure_file_not_empty(p, fmt)
                set_current_file(chat_id, p, fmt)
                
                conn.execute(
                    "INSERT INTO files(path, created_at, link_count, bytes, format) VALUES(?,?,?,?,?)",
                    (str(p), dt.datetime.now(dt.timezone.utc).isoformat(), 0, 0, fmt)
                )
                incr_stat(conn, "files_total", 1)
                conn.commit()
                
                await q.edit_message_text(
                    f"📄 **New File Created**\n\nFile: {p.name}\nFormat: {fmt.upper()}",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=main_keyboard()
                )
                
            elif data == "stats":
                total_content = get_stat(conn, "content_total")
                dups = get_stat(conn, "dups_total")
                files_total = get_stat(conn, "files_total")
                
                await q.edit_message_text(
                    f"📊 **Statistics**\n\n"
                    f"Total saved: {total_content:,}\n"
                    f"Duplicates: {dups:,}\n"
                    f"Files: {files_total:,}",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=main_keyboard()
                )
                
            elif data == "fmt_csv" or data == "fmt_txt":
                fmt = "csv" if data == "fmt_csv" else "txt"
                p = next_file_name(chat_id, fmt)
                p.touch(exist_ok=True)
                ensure_file_not_empty(p, fmt)
                set_current_file(chat_id, p, fmt)
                
                conn.execute(
                    "INSERT INTO files(path, created_at, link_count, bytes, format) VALUES(?,?,?,?,?)",
                    (str(p), dt.datetime.now(dt.timezone.utc).isoformat(), 0, 0, fmt)
                )
                incr_stat(conn, "files_total", 1)
                conn.commit()
                
                await q.edit_message_text(
                    f"✅ **Format Changed**\n\nFormat: {fmt.upper()}\nFile: {p.name}",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=main_keyboard()
                )

            elif data == "clean_duplicates":
                await q.edit_message_text("🔄 Scanning database and cleaning duplicates... This may take a moment.")
                
                # Use a separate connection for the cleanup process
                cleanup_conn = connect_db(chat_id)
                try:
                    all_entries = cleanup_conn.execute("SELECT content, type FROM links").fetchall()

                    seen = set()
                    duplicates_to_delete = []

                    initial_count = len(all_entries)

                    for content, ctype in all_entries:
                        # Normalize the content to find true duplicates
                        normalized_content = content.lower().lstrip('@')
                        match = TELEGRAM_LINK_REGEX.match(content)
                        if match:
                            normalized_content = match.group(4).lower()

                        if normalized_content in seen:
                            duplicates_to_delete.append(content)
                        else:
                            seen.add(normalized_content)

                    if duplicates_to_delete:
                        cleanup_conn.executemany("DELETE FROM links WHERE content = ?", [(d,) for d in duplicates_to_delete])
                        cleanup_conn.commit()

                    # Recalculate stats
                    remaining_entries = cleanup_conn.execute("SELECT type FROM links").fetchall()
                    new_total = len(remaining_entries)
                    new_links = sum(1 for row in remaining_entries if row[0] == 'link')
                    new_usernames = new_total - new_links

                    cleanup_conn.execute("INSERT OR REPLACE INTO stats(k, v) VALUES(?, ?)", ("content_total", new_total))
                    cleanup_conn.execute("INSERT OR REPLACE INTO stats(k, v) VALUES(?, ?)", ("links_saved", new_links))
                    cleanup_conn.execute("INSERT OR REPLACE INTO stats(k, v) VALUES(?, ?)", ("usernames_saved", new_usernames))
                    cleanup_conn.commit()

                    removed_count = initial_count - new_total

                    await q.edit_message_text(
                        f"✅ **Cleanup Complete!**\n\n"
                        f"• Duplicates Removed: {removed_count:,}\n"
                        f"• New Total Unique Items: {new_total:,}",
                        parse_mode=ParseMode.MARKDOWN,
                        reply_markup=main_keyboard()
                    )

                except Exception as e:
                    logger.error(f"Duplicate cleaning failed: {traceback.format_exc()}")
                    await q.edit_message_text(f"❌ Cleanup failed: {e}", reply_markup=main_keyboard())
                finally:
                    cleanup_conn.close()

            conn.close()
            
    except Exception as e:
        print(f"Callback error: {traceback.format_exc()}")
        await q.edit_message_text(
            f"❌ Error: {str(e)}\n\nPlease try again.",
            reply_markup=main_keyboard()
        )

# =========================
# === MESSAGE HANDLER =====
# =========================

async def handle_document_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the file upload process with robust logging and cleanup."""
    if not await admin_guard(update, context) or not context.user_data.get("expecting_upload"):
        return

    document = update.effective_message.document
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id

    # --- 1. Initial Validation ---
    if not document:
        logger.warning(f"User {user_id} triggered document handler with no document.")
        await update.message.reply_text("❌ Please send a valid file.")
        return

    file_name = document.file_name
    file_ext = Path(file_name).suffix.lower()
    logger.info(f"Received file '{file_name}' from user {user_id} in chat {chat_id}.")

    if file_ext not in (".txt", ".csv"):
        logger.warning(f"User {user_id} uploaded unsupported file type: {file_ext}")
        await update.message.reply_text("❌ Only `.txt` or `.csv` files are supported.")
        return

    # --- 2. Setup and Pre-processing ---
    processing_message = await update.message.reply_text("🔄 Processing... Please wait.")
    conn = None
    temp_path = None

    try:
        conn = connect_db(chat_id)
        logger.info(f"Database connection established for chat {chat_id}.")

        # --- 3. File Download ---
        logger.info(f"Downloading file '{file_name}' from Telegram.")
        file = await document.get_file()
        temp_path = DATA_DIR / f"temp_upload_{chat_id}_{document.file_unique_id}{file_ext}"
        await file.download_to_drive(temp_path)
        logger.info(f"File downloaded successfully to '{temp_path}'.")

        # --- 4. File and Database Preparation ---
        current_file, current_fmt = read_current_file(chat_id)
        if not current_file:
            current_file = next_file_name(chat_id, current_fmt)
            set_current_file(chat_id, current_file, current_fmt)

        current_file.touch(exist_ok=True)
        ensure_file_not_empty(current_file, current_fmt)

        added, skipped, processed = 0, 0, 0
        parsing_mode = "Generic Text File"
        title = "File Restore Complete"

        # --- 5. File Parsing ---
        logger.info(f"Starting to parse '{file_name}' (extension: {file_ext}).")
        with temp_path.open("r", encoding="utf-8", newline="") as f:
            if not f.read(1): # Check if file is empty
                raise ValueError("File is empty or could not be read.")
            f.seek(0)

            if file_ext == ".csv":
                try:
                    # Sniff to detect CSV dialect
                    dialect = csv.Sniffer().sniff(f.read(1024))
                    f.seek(0)
                    reader = csv.reader(f, dialect)

                    parsing_mode = "Generic CSV"
                    title = "CSV Import Complete"
                    added, skipped, processed = await _parse_generic_csv(reader, conn, chat_id, current_file, current_fmt, processing_message)

                except csv.Error:
                    # If it's a malformed CSV, treat it as a text file
                    f.seek(0)
                    lines = f.readlines()
                    parsing_mode = "Malformed CSV (as Text)"
                    added, skipped, processed = await _parse_generic_text_file(lines, conn, chat_id, current_file, current_fmt, processing_message)
            else: # .txt file
                lines = f.readlines()
                added, skipped, processed = await _parse_generic_text_file(lines, conn, chat_id, current_file, current_fmt, processing_message)

        logger.info(f"Parsing complete. Mode: '{parsing_mode}'. Added: {added}, Skipped: {skipped}, Processed: {processed}.")

        # --- 6. Finalize and Report ---
        logger.info("Committing changes to the database.")
        conn.commit()
        total = get_stat(conn, "content_total")
        logger.info(f"Database commit successful. New total: {total}.")

        if parsing_mode == "Bot Data File" and added == 0 and skipped > 0:
            final_message = (
                f"✅ **Restore Complete**\n\n"
                f"The file was successfully processed. All {skipped:,} items in the file were found to be duplicates that already exist in the database.\n\n"
                f"**No new items were added.**\n\n"
                f"**Database Status:**\n"
                f"• Total Saved Items: {total:,}"
            )
        else:
            final_message = (
                f"✅ **{title}**\n\n"
                f"**File Summary:**\n"
                f"• Parsing Mode: `{parsing_mode}`\n"
                f"• Lines/Rows Processed: {processed:,}\n"
                f"• New Items Added: {added:,}\n"
                f"• Duplicates Skipped: {skipped:,}\n\n"
                f"**Database Status:**\n"
                f"• Total Saved Items: {total:,}\n\n"
                f"Current file `{current_file.name}` has been updated."
            )

        await processing_message.edit_text(
            final_message,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard()
        )
        logger.info(f"Final success message sent to user {user_id}.")

    except Exception as e:
        logger.error(f"Upload failed for user {user_id} with file '{file_name}': {traceback.format_exc()}")
        await processing_message.edit_text(
            f"❌ **Upload Failed**\n\nAn unexpected error occurred: `{str(e)}`\n\nPlease check the bot logs for more details.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard()
        )

    finally:
        # --- 7. Guaranteed Cleanup ---
        if conn:
            conn.close()
            logger.info(f"Database connection closed for chat {chat_id}.")
        if temp_path and temp_path.exists():
            temp_path.unlink(missing_ok=True)
            logger.info(f"Temporary file '{temp_path}' deleted.")
        context.user_data["expecting_upload"] = False
        logger.info(f"Reset 'expecting_upload' flag for user {user_id}.")

def _add_content_to_db(conn, chat_id, current_file, current_fmt, content, ctype):
    """Normalizes content and adds it to the DB, returning (added, skipped)."""
    if not content:
        return 0, 0

    # --- Normalization Logic ---
    original_content = content

    # If it's a link, check if it's a Telegram username link
    if ctype == "link":
        match = TELEGRAM_LINK_REGEX.match(content)
        if match:
            content = match.group(4).lower() # Extract username
            ctype = "username"
            logger.info(f"Normalized link '{original_content}' to username '{content}'")
        elif content.lower().startswith("www."):
            content = "https://" + content

    # If it's a username, ensure it's clean
    elif ctype == "username":
        content = content.lower().lstrip('@')

    try:
        conn.execute(
            "INSERT INTO links(content, type, added_at) VALUES(?,?,?)",
            (content, ctype, dt.datetime.now(dt.timezone.utc).isoformat())
        )
        write_content_to_file(current_file, content, ctype, current_fmt)
        incr_stat(conn, "content_total", 1)
        if ctype == "link":
            incr_stat(conn, "links_saved", 1)
        else:
            incr_stat(conn, "usernames_saved", 1)
        return 1, 0
    except sqlite3.IntegrityError:
        save_duplicate(chat_id, content, ctype, conn)
        incr_stat(conn, "dups_total", 1)
        return 0, 1

async def _parse_generic_csv(reader, conn, chat_id, current_file, current_fmt, message) -> Tuple[int, int, int]:
    """Parses a generic CSV file by scanning every field for links/usernames."""
    added, skipped, processed = 0, 0, 0
    logger.info("Parsing file as a Generic CSV.")

    # Read all rows into memory to get a total count for progress reporting
    rows = list(reader)
    total_rows = len(rows)

    for i, row in enumerate(rows):
        processed += 1
        # In a generic CSV, we don't know the column names, so we check all values
        for field in row:
            if not field:  # Skip empty fields
                continue

            # Find all potential links and usernames in the current field
            links = [m.group(1) for m in URL_REGEX.finditer(field)]
            usernames = [m.group(1) for m in USERNAME_REGEX.finditer(field)]

            for link in links:
                a, s = _add_content_to_db(conn, chat_id, current_file, current_fmt, link, "link")
                added += a
                skipped += s

            for username in usernames:
                a, s = _add_content_to_db(conn, chat_id, current_file, current_fmt, username, "username")
                added += a
                skipped += s

        # --- Progress Update ---
        # Update every 20 rows or on the last row to avoid hitting API limits
        if (i + 1) % 20 == 0 or (i + 1) == total_rows:
            percentage = ((i + 1) / total_rows) * 100
            try:
                await message.edit_text(f"🔄 Processing... {percentage:.1f}%")
            except Exception:  # Ignore "message not modified" errors
                pass

    return added, skipped, processed

async def _parse_generic_text_file(lines, conn, chat_id, current_file, current_fmt, message) -> Tuple[int, int, int]:
    """Parses a generic text file line by line using regex."""
    added, skipped, processed = 0, 0, 0
    logger.info("Parsing file with line-by-line regex mode.")
    total = len(lines)
    for i, line in enumerate(lines):
        processed += 1
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        contents_to_add = []
        links = [m.group(1) for m in URL_REGEX.finditer(line)]
        usernames = [m.group(1) for m in USERNAME_REGEX.finditer(line)]

        for link in links:
            contents_to_add.append((link, "link"))
        for username in usernames:
            contents_to_add.append((username, "username"))

        if not links and not usernames:
            potential_username = line.lstrip('@')
            if ' ' not in potential_username and '.' not in potential_username and '/' not in potential_username and ':' not in potential_username:
                if 5 <= len(potential_username) <= 32 and all(c.isalnum() or c == '_' for c in potential_username):
                    contents_to_add.append((potential_username, "username"))

        if not contents_to_add:
            logger.warning(f"Line {i+1}: Could not parse content from line: '{line}'")
            continue

        for content, ctype in contents_to_add:
            a, s = _add_content_to_db(conn, chat_id, current_file, current_fmt, content, ctype)
            added += a
            skipped += s

        if (i + 1) % 20 == 0:
            percentage = ((i + 1) / total) * 100
            try:
                await message.edit_text(f"🔄 Processing... {percentage:.1f}%")
            except Exception: pass

    return added, skipped, processed

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_guard(update, context):
        return
    
    # Check if we're in login process
    login_state = context.user_data.get('login_state')
    if login_state and login_state != LoginState.IDLE:
        await handle_login_process(update, context)
        return
    
    # Handle regular content
    chat_id = update.effective_chat.id
    text = update.effective_message.text or update.effective_message.caption or ""
    if not text:
        return
    
    # Extract links and usernames
    links = [m.group(1) for m in URL_REGEX.finditer(text)]
    usernames = [m.group(1) for m in USERNAME_REGEX.finditer(text)]
    
    all_content = []
    for link in links:
        all_content.append((link, "link"))
    for username in usernames:
        all_content.append((username, "username"))
    
    if not all_content:
        return
    
    conn = connect_db(chat_id)
    
    # Get or create current file
    p, fmt = read_current_file(chat_id)
    if not p:
        fmt = fmt if fmt in ("txt", "csv") else DEFAULT_FILE_FORMAT
        p = next_file_name(chat_id, fmt)
        p.touch(exist_ok=True)
        ensure_file_not_empty(p, fmt)
        set_current_file(chat_id, p, fmt)
        conn.execute(
            "INSERT INTO files(path, created_at, link_count, bytes, format) VALUES(?,?,?,?,?)",
            (str(p), dt.datetime.now(dt.timezone.utc).isoformat(), 0, 0, fmt)
        )
    
    added = 0
    skipped = 0
    
    for content, content_type in all_content:
        a, s = _add_content_to_db(conn, chat_id, p, fmt, content, content_type)
        added += a
        skipped += s
    
    conn.commit()
    
    # After processing, decide which message to send
    if len(all_content) == 1 and skipped == 1:
        # Case: A single item was sent and it was a duplicate.
        content, _ = all_content[0]
        conn.close() # Close connection before sending reply
        await update.effective_message.reply_text(
            f"❌ **Duplicate Entry**\n\nThe item `{content}` already exists in the database and was not added.",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard()
        )
    else:
        # Case: Bulk message OR single/multiple successful additions.
        total_content = get_stat(conn, "content_total")
        dups = get_stat(conn, "dups_total")
        conn.close()

        # Don't show the summary if nothing was processed in this message.
        if added == 0 and skipped == 0:
            return

        status_text = (
            f"✅ **Processing Complete**\n\n"
            f"**This Message:**\n"
            f"• Added: {added}\n"
            f"• Duplicates: {skipped}\n\n"
            f"**Total Statistics:**\n"
            f"• Saved: {total_content:,}\n"
            f"• Duplicates: {dups:,}\n\n"
            f"Current file: `{p.name}`"
        )
        await update.effective_message.reply_text(
            status_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard()
        )

# =========================
# === MAIN ENTRY POINT ====
# =========================

def main():
    """Main entry point."""
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ Error: Please set BOT_TOKEN")
        return
    
    if not ADMIN_IDS:
        print("❌ Error: Please set ADMIN_IDS")
        return
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    print("🔄 Checking database schema...")
    # Test database migration on startup
    try:
        test_conn = connect_db(0)  # Use chat_id 0 for test
        test_conn.close()
        print("✅ Database schema verified and migrated if needed")
    except Exception as e:
        print(f"⚠️ Database setup warning: {e}")
    
    # Build application
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    
    # Command handlers
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(CommandHandler("stats", stats_cmd))
    
    # Callback handler
    app.add_handler(CallbackQueryHandler(on_callback))
    
    # Message handler
    app.add_handler(MessageHandler(filters.TEXT | filters.CAPTION, handle_message))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document_upload))
    
    print("✅ Professional Link & Group Saver Bot is running...")
    print("📞 Support: @Corose | @fxeeo")
    print("🔐 Session persistence enabled - login survives restarts")
    print("Press Ctrl+C to stop.")
    
    try:
        app.run_polling(drop_pending_updates=True)
    except KeyboardInterrupt:
        print("\n👋 Bot stopped.")

if __name__ == "__main__":
    main()