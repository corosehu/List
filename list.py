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
import os
import re
import sqlite3
import json
import traceback
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

BOT_TOKEN = os.getenv("BOT_TOKEN", "8118285986:AAGFGuH_-i3y24Ig5j84eloIIpqFyBCXz9Y")
ADMIN_IDS = {6827291977}  # Your Telegram user IDs

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DEFAULT_FILE_FORMAT = os.getenv("FILE_FORMAT", "txt").lower()
MAX_LINKS_PER_FILE = int(os.getenv("MAX_LINKS_PER_FILE", "80000"))
MAX_BYTES_PER_FILE = int(os.getenv("MAX_BYTES_PER_FILE", str(50 * 1024 * 1024)))

# Login States
class LoginState(Enum):
    IDLE = 0
    WAITING_API_ID = 1
    WAITING_API_HASH = 2
    WAITING_PHONE = 3
    WAITING_CODE = 4
    WAITING_2FA = 5
    LOGGED_IN = 6

# Regex patterns
URL_REGEX = re.compile(
    r'(?i)\b((?:https?://|www\d{0,3}[.]|t\.me/|telegram\.me/|[a-z0-9.\-]+\.[a-z]{2,})(?:[^\s<>"]+))'
)
USERNAME_REGEX = re.compile(r'@([a-zA-Z0-9_]{5,32})')

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
                writer.writerow(["[Empty File]", "placeholder", dt.datetime.utcnow().isoformat()])
            else:
                f.write("# Links and Usernames File\n")
                f.write(f"# Created: {dt.datetime.utcnow().isoformat()}\n")
                f.write("# No content yet\n")

def write_content_to_file(path: Path, content: str, content_type: str, fmt: str) -> int:
    """Write content to file and return bytes written."""
    if fmt == "csv":
        new_file = not path.exists() or path.stat().st_size == 0
        with path.open("a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["content", "type", "added_at"])
            ts = dt.datetime.utcnow().isoformat()
            w.writerow([content, content_type, ts])
            return len(content) + len(content_type) + len(ts) + 10
    else:
        line = f"{content} ({content_type}) - {dt.datetime.utcnow().isoformat()}\n"
        with path.open("a", encoding="utf-8") as f:
            f.write(line)
        return len(line.encode("utf-8"))

def save_duplicate(chat_id: int, content: str, content_type: str, conn: sqlite3.Connection) -> None:
    """Save duplicate to database and file."""
    # Save to database
    conn.execute(
        "INSERT INTO duplicates(content, type, seen_at, duplicate_count) VALUES(?,?,?,1)",
        (content, content_type, dt.datetime.utcnow().isoformat())
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
            w.writerow([content, content_type, dt.datetime.utcnow().isoformat()])
    else:
        with dup_path.open("a", encoding="utf-8") as f:
            f.write(f"{content} ({content_type}) - Duplicate at {dt.datetime.utcnow().isoformat()}\n")

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
        [InlineKeyboardButton("🔄 Download Duplicates", callback_data="dl_duplicates")],
        [InlineKeyboardButton("👤 Telegram Account Login", callback_data="tg_login")]
    ]
    
    return InlineKeyboardMarkup(buttons)

def login_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔐 Start Login Process", callback_data="start_login")],
        [InlineKeyboardButton("📋 Check Login Status", callback_data="login_status")],
        [InlineKeyboardButton("🔄 Reset Login", callback_data="reset_login")],
        [InlineKeyboardButton("◀️ Back to Main", callback_data="back_main")]
    ])

def export_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("📤 Export Groups", callback_data="export_groups")],
        [InlineKeyboardButton("📝 Create Links File", callback_data="create_links_file")],
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
            data.get('created_at', dt.datetime.utcnow().isoformat()),
            dt.datetime.utcnow().isoformat()
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
                
    except Exception as e:
        await update.message.reply_text(f"❌ Unexpected error: {str(e)}")
        print(f"Login error: {traceback.format_exc()}")
        context.user_data.clear()

# =========================
# === GROUP EXPORT ========
# =========================

async def export_user_groups(chat_id: int, user_id: int) -> Dict[str, Any]:
    """Export all user's groups and create links file."""
    result = {
        "success": False,
        "groups_count": 0,
        "success_count": 0,
        "failed_count": 0,
        "export_file": None,
        "failed_file": None,
        "links_file": None,
        "error": None
    }
    
    try:
        # Get user session
        session_data = await get_user_session(chat_id, user_id)
        if not session_data or not session_data.get('session_string'):
            result["error"] = "No active session. Please login first."
            return result
        
        api_id = int(session_data['api_id'])
        api_hash = session_data['api_hash']
        session_string = session_data['session_string']
        
        # Connect with Telethon
        client = TelegramClient(StringSession(session_string), api_id, api_hash)
        await client.connect()
        
        if not await client.is_user_authorized():
            result["error"] = "Session expired. Please login again."
            return result
        
        # Get all dialogs
        dialogs = await client.get_dialogs()
        groups = []
        failed_groups = []
        all_links = []  # Store all links and usernames
        
        for dialog in dialogs:
            try:
                if dialog.is_group or dialog.is_channel:
                    # Extract group info
                    entity = dialog.entity
                    username = getattr(entity, 'username', None)
                    
                    group_info = {
                        "name": dialog.name,
                        "username": username or '',
                        "id": dialog.id,
                        "members_count": getattr(entity, 'participants_count', 'N/A'),
                        "type": "Channel" if dialog.is_channel else "Group",
                        "is_public": bool(username),
                        "exported_at": dt.datetime.utcnow().isoformat()
                    }
                    groups.append(group_info)
                    result["success_count"] += 1
                    
                    # Collect links and usernames
                    if username:
                        all_links.append(f"https://t.me/{username}")
                        all_links.append(f"@{username}")
                    
                    # Small delay to avoid rate limits
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                failed_info = {
                    "name": getattr(dialog, 'name', 'Unknown'),
                    "id": getattr(dialog, 'id', 'Unknown'),
                    "error": str(e),
                    "failed_at": dt.datetime.utcnow().isoformat()
                }
                failed_groups.append(failed_info)
                result["failed_count"] += 1
        
        await client.disconnect()
        
        # Save successful exports
        timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        export_dir = ensure_chat_dirs(chat_id) / "exports"
        
        if groups:
            export_file = export_dir / f"groups_export_{timestamp}.csv"
            
            with export_file.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, 
                    fieldnames=["name", "username", "id", "members_count", "type", "is_public", "exported_at"]
                )
                writer.writeheader()
                writer.writerows(groups)
            
            # Ensure file is not empty
            ensure_file_not_empty(export_file, "csv")
            result["export_file"] = export_file
        
        # Create links file from groups
        if all_links:
            links_file = export_dir / f"group_links_{timestamp}.txt"
            with links_file.open("w", encoding="utf-8") as f:
                f.write("# Group Links and Usernames Export\n")
                f.write(f"# Exported: {dt.datetime.utcnow().isoformat()}\n")
                f.write(f"# Total Groups: {result['success_count']}\n")
                f.write("#" + "="*50 + "\n\n")
                
                for link in all_links:
                    f.write(f"{link}\n")
            
            result["links_file"] = links_file
        
        # Save failed exports
        if failed_groups:
            failed_dir = ensure_chat_dirs(chat_id) / "failed"
            timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            failed_file = failed_dir / f"failed_groups_{timestamp}.csv"
            
            with failed_file.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=["name", "id", "error", "failed_at"]
                )
                writer.writeheader()
                writer.writerows(failed_groups)
            
            result["failed_file"] = failed_file
        
        result["groups_count"] = result["success_count"] + result["failed_count"]
        result["success"] = True
        
        # Save export history with links file
        conn = connect_db(chat_id)
        try:
            conn.execute(
                """INSERT INTO export_history 
                   (user_id, export_date, groups_count, success_count, failed_count, export_file, failed_file, links_file)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    user_id,
                    dt.datetime.utcnow().isoformat(),
                    result["groups_count"],
                    result["success_count"],
                    result["failed_count"],
                    str(result["export_file"]) if result["export_file"] else None,
                    str(result["failed_file"]) if result["failed_file"] else None,
                    str(result["links_file"]) if result["links_file"] else None
                )
            )
        except sqlite3.OperationalError:
            # If links_file column doesn't exist, add it
            conn.execute("ALTER TABLE export_history ADD COLUMN links_file TEXT")
            conn.execute(
                """INSERT INTO export_history 
                   (user_id, export_date, groups_count, success_count, failed_count, export_file, failed_file, links_file)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    user_id,
                    dt.datetime.utcnow().isoformat(),
                    result["groups_count"],
                    result["success_count"],
                    result["failed_count"],
                    str(result["export_file"]) if result["export_file"] else None,
                    str(result["failed_file"]) if result["failed_file"] else None,
                    str(result["links_file"]) if result["links_file"] else None
                )
            )
        conn.commit()
        conn.close()
        
    except Exception as e:
        result["error"] = f"Export failed: {str(e)}"
        print(f"Export error: {traceback.format_exc()}")
    
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
        "/export - Export your groups\n\n"
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
                "📤 **Upload Current File**\n"
                "Please send a `.txt` or `.csv` file that was previously exported by this bot.\n"
                "The bot will restore all links/usernames into the current database and file.",
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
                "🔐 **Login Process Started**\n\n"
                "Step 1/5: **API ID**\n\n"
                "Please enter your API ID:\n"
                "(Get it from https://my.telegram.org)",
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
            
        elif data == "export_groups":
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
            
            await q.edit_message_text("📤 Exporting groups... Please wait.")
            
            result = await export_user_groups(chat_id, user_id)
            
            if not result["success"]:
                await q.edit_message_text(
                    f"❌ **Export Failed**\n\n{result['error']}",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
            else:
                status_text = (
                    f"✅ **Export Complete!**\n\n"
                    f"**Summary:**\n"
                    f"• Total groups: {result['groups_count']}\n"
                    f"• Successfully exported: {result['success_count']}\n"
                    f"• Failed: {result['failed_count']}\n\n"
                    f"**Files Created:**\n"
                )
                
                if result['export_file']:
                    status_text += f"✅ Groups CSV file\n"
                if result['links_file']:
                    status_text += f"✅ Links TXT file (usernames & links)\n"
                if result['failed_file']:
                    status_text += f"⚠️ Failed groups log\n"
                
                await q.edit_message_text(
                    status_text,
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
                
                # Send the files
                if result['export_file']:
                    await q.message.reply_document(
                        document=InputFile(result['export_file'].open("rb"), filename=result['export_file'].name),
                        caption=f"✅ Groups Export: {result['success_count']} groups"
                    )
                
                if result['links_file']:
                    await q.message.reply_document(
                        document=InputFile(result['links_file'].open("rb"), filename=result['links_file'].name),
                        caption=f"📋 Links File: All group links and @usernames"
                    )
                
                if result['failed_file']:
                    await q.message.reply_document(
                        document=InputFile(result['failed_file'].open("rb"), filename=result['failed_file'].name),
                        caption=f"⚠️ Failed Groups: {result['failed_count']} groups"
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
                history_text = "📊 **Export History**\n\n"
                for row in history:
                    date = dt.datetime.fromisoformat(row[0]).strftime("%Y-%m-%d %H:%M")
                    history_text += (
                        f"**{date}**\n"
                        f"• Total: {row[1]} | Success: {row[2]} | Failed: {row[3]}\n\n"
                    )
            else:
                history_text = "📊 **Export History**\n\nNo exports yet."
            
            await q.edit_message_text(
                history_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=export_keyboard()
            )
            
        elif data == "create_links_file":
            # Check if user is logged in
            session_data = await get_user_session(chat_id, user_id)
            if not session_data or not session_data.get('session_string'):
                await q.edit_message_text(
                    "❌ **Not Logged In**\n\n"
                    "Please login first to create links file.",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=main_keyboard()
                )
                return
            
            await q.edit_message_text("📝 Creating links file from your groups...")
            
            # Use export function but only for links extraction
            result = await export_user_groups(chat_id, user_id)
            
            if not result["success"]:
                await q.edit_message_text(
                    f"❌ **Failed to create links file**\n\n{result['error']}",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
            elif result.get('links_file'):
                await q.edit_message_text(
                    f"✅ **Links File Created!**\n\n"
                    f"• Groups processed: {result['success_count']}\n"
                    f"• Links and usernames extracted\n"
                    f"• File ready for download",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=export_keyboard()
                )
                
                # Send the links file
                await q.message.reply_document(
                    document=InputFile(result['links_file'].open("rb"), filename=result['links_file'].name),
                    caption=f"📝 Links File: All group links and @usernames from {result['success_count']} groups"
                )
            else:
                await q.edit_message_text(
                    "⚠️ No public groups found to extract links from.",
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
                p, fmt = read_current_file(chat_id)
                if not p or not p.exists():
                    await q.edit_message_text("No current file available.")
                else:
                    ensure_file_not_empty(p, fmt)
                    await q.message.reply_document(
                        document=InputFile(p.open("rb"), filename=p.name),
                        caption=f"📄 Current file: {p.name}"
                    )
                    
            elif data == "new_file":
                _, fmt = read_current_file(chat_id)
                p = next_file_name(chat_id, fmt)
                p.touch(exist_ok=True)
                ensure_file_not_empty(p, fmt)
                set_current_file(chat_id, p, fmt)
                
                conn.execute(
                    "INSERT INTO files(path, created_at, link_count, bytes, format) VALUES(?,?,?,?,?)",
                    (str(p), dt.datetime.utcnow().isoformat(), 0, 0, fmt)
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
                    (str(p), dt.datetime.utcnow().isoformat(), 0, 0, fmt)
                )
                incr_stat(conn, "files_total", 1)
                conn.commit()
                
                await q.edit_message_text(
                    f"✅ **Format Changed**\n\nFormat: {fmt.upper()}\nFile: {p.name}",
                    parse_mode=ParseMode.MARKDOWN,
                    reply_markup=main_keyboard()
                )
                
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
    if not await admin_guard(update, context):
        return

    if not context.user_data.get("expecting_upload"):
        return  # Ignore random docs

    document = update.effective_message.document
    if not document:
        await update.message.reply_text("❌ Please send a valid file.")
        return

    file_ext = Path(document.file_name).suffix.lower()
    if file_ext not in (".txt", ".csv"):
        await update.message.reply_text("❌ Only `.txt` or `.csv` files are supported.")
        return

    chat_id = update.effective_chat.id
    conn = connect_db(chat_id)
    try:
        # Get file
        file = await document.get_file()
        temp_path = DATA_DIR / f"temp_upload_{chat_id}_{document.file_unique_id}{file_ext}"
        await file.download_to_drive(temp_path)

        current_file, current_fmt = read_current_file(chat_id)
        current_fmt = current_fmt if current_fmt in ("txt", "csv") else "txt"
        if not current_file:
            current_file = next_file_name(chat_id, current_fmt)
            set_current_file(chat_id, current_file, current_fmt)

        current_file.touch(exist_ok=True)
        ensure_file_not_empty(current_file, current_fmt)

        added = 0
        skipped = 0

        if file_ext == ".csv":
            with temp_path.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    content = row.get("content", "").strip()
                    ctype = row.get("type", "").strip()
                    if not content or ctype not in ("link", "username"):
                        continue
                    if ctype == "username":
                        content = content.lower()
                    try:
                        conn.execute(
                            "INSERT INTO links(content, type, added_at) VALUES(?,?,?)",
                            (content, ctype, dt.datetime.utcnow().isoformat())
                        )
                        write_content_to_file(current_file, content, ctype, current_fmt)
                        incr_stat(conn, "content_total", 1)
                        if ctype == "link":
                            incr_stat(conn, "links_saved", 1)
                        else:
                            incr_stat(conn, "usernames_saved", 1)
                        added += 1
                    except sqlite3.IntegrityError:
                        save_duplicate(chat_id, content, ctype, conn)
                        incr_stat(conn, "dups_total", 1)
                        skipped += 1
        else:  # .txt
            with temp_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Try to parse: "content (type) - timestamp"
                    if " (" in line and ") - " in line:
                        try:
                            content_part, rest = line.split(" (", 1)
                            ctype_part, _ = rest.split(") - ", 1)
                            content = content_part
                            ctype = ctype_part
                            if ctype not in ("link", "username"):
                                continue
                            if ctype == "username":
                                content = content.lower()
                            try:
                                conn.execute(
                                    "INSERT INTO links(content, type, added_at) VALUES(?,?,?)",
                                    (content, ctype, dt.datetime.utcnow().isoformat())
                                )
                                write_content_to_file(current_file, content, ctype, current_fmt)
                                incr_stat(conn, "content_total", 1)
                                if ctype == "link":
                                    incr_stat(conn, "links_saved", 1)
                                else:
                                    incr_stat(conn, "usernames_saved", 1)
                                added += 1
                            except sqlite3.IntegrityError:
                                save_duplicate(chat_id, content, ctype, conn)
                                incr_stat(conn, "dups_total", 1)
                                skipped += 1
                        except Exception:
                            continue  # Skip malformed lines

        conn.commit()
        conn.close()
        temp_path.unlink(missing_ok=True)
        context.user_data["expecting_upload"] = False

        total = get_stat(connect_db(chat_id), "content_total")

        await update.message.reply_text(
            f"✅ **Upload Complete**\n"
            f"• Added: {added}\n"
            f"• Duplicates: {skipped}\n"
            f"• Total Saved Now: {total:,}\n"
            f"Current file updated: `{current_file.name}`",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=main_keyboard()
        )

    except Exception as e:
        print(f"Upload error: {traceback.format_exc()}")
        await update.message.reply_text(
            f"❌ Upload failed: {str(e)}",
            reply_markup=main_keyboard()
        )
        if "temp_path" in locals():
            temp_path.unlink(missing_ok=True)
        context.user_data["expecting_upload"] = False
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
    _, fmt = read_current_file(chat_id)
    fmt = fmt if fmt in ("txt", "csv") else DEFAULT_FILE_FORMAT
    
    # Get or create current file
    p = next_file_name(chat_id, fmt)
    if not p.exists():
        p.touch(exist_ok=True)
        ensure_file_not_empty(p, fmt)
        set_current_file(chat_id, p, fmt)
        conn.execute(
            "INSERT INTO files(path, created_at, link_count, bytes, format) VALUES(?,?,?,?,?)",
            (str(p), dt.datetime.utcnow().isoformat(), 0, 0, fmt)
        )
    
    added = 0
    skipped = 0
    
    for content, content_type in all_content:
        # Normalize content
        if content_type == "link" and content.lower().startswith("www."):
            content = "https://" + content
        elif content_type == "username":
            content = content.lower()
        
        try:
            conn.execute(
                "INSERT INTO links(content, type, added_at) VALUES(?,?,?)",
                (content, content_type, dt.datetime.utcnow().isoformat())
            )
            
            # Write to file
            bytes_written = write_content_to_file(p, content, content_type, fmt)
            
            # Update stats
            incr_stat(conn, "content_total", 1)
            if content_type == "link":
                incr_stat(conn, "links_saved", 1)
            else:
                incr_stat(conn, "usernames_saved", 1)
            
            added += 1
            
        except sqlite3.IntegrityError:
            # Duplicate found
            save_duplicate(chat_id, content, content_type, conn)
            incr_stat(conn, "dups_total", 1)
            skipped += 1
    
    conn.commit()
    
    # Send status
    total_content = get_stat(conn, "content_total")
    dups = get_stat(conn, "dups_total")
    
    conn.close()
    
    status_text = (
        f"✅ **Processing Complete**\n\n"
        f"**This Message:**\n"
        f"• Added: {added}\n"
        f"• Duplicates: {skipped}\n\n"
        f"**Total Statistics:**\n"
        f"• Saved: {total_content:,}\n"
        f"• Duplicates: {dups:,}\n\n"
        f"Current file: {p.name}"
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
        app.run_polling()
    except KeyboardInterrupt:
        print("\n👋 Bot stopped.")

if __name__ == "__main__":
    main()