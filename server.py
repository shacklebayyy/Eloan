import base64
import hashlib
import hmac
import http.cookies
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import threading
import time
import uuid
from contextlib import contextmanager
from email.message import EmailMessage
from email.utils import parseaddr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("EMOLA_DB_PATH", ROOT / "emola.sqlite3"))
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
ADMIN_TOKEN = os.environ.get("EMOLA_ADMIN_TOKEN") or "admin123"


@contextmanager
def connect_db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_setting(key, default=None):
    try:
        with connect_db() as db:
            row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default
    except Exception:
        return default


def set_setting(key, value):
    with connect_db() as db:
        db.execute(
            """INSERT INTO settings (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, str(value)),
        )


def telegram_bot_token():
    return get_setting("telegram_bot_token") or os.environ.get("EMOLA_TELEGRAM_BOT_TOKEN", "").strip()


def telegram_admin_chat_id():
    return get_setting("telegram_admin_chat_id") or os.environ.get("EMOLA_TELEGRAM_CHAT_ID", "").strip()


def telegram_bot_username():
    configured = get_setting("telegram_bot_username") or os.environ.get("EMOLA_TELEGRAM_BOT_USERNAME", "shacklebaybot")
    return configured.strip().lstrip("@")


def initialize_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as db:
        db.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                access_token_hash TEXT NOT NULL UNIQUE,
                username TEXT,
                email TEXT,
                password_hash TEXT,
                must_change_password INTEGER NOT NULL DEFAULT 1,
                telegram_chat_id TEXT,
                telegram_pair_token_hash TEXT,
                telegram_pair_expires_at REAL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS applications (
                id TEXT PRIMARY KEY,
                submission_id TEXT NOT NULL UNIQUE,
                agent_id TEXT REFERENCES agents(id),
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                loan_type TEXT NOT NULL,
                loan_amount INTEGER NOT NULL,
                term_months INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                employment TEXT NOT NULL,
                annual_income REAL NOT NULL,
                agent_contact_consent INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS telegram_outbox (
                id TEXT PRIMARY KEY,
                application_id TEXT NOT NULL UNIQUE REFERENCES applications(id),
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at REAL NOT NULL DEFAULT 0,
                last_error TEXT,
                sent_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS telegram_agent_outbox (
                id TEXT PRIMARY KEY,
                application_id TEXT NOT NULL UNIQUE REFERENCES applications(id),
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at REAL NOT NULL DEFAULT 0,
                last_error TEXT,
                sent_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS verifications (
                id TEXT PRIMARY KEY,
                application_id TEXT NOT NULL REFERENCES applications(id),
                step TEXT NOT NULL,
                zip_code TEXT,
                phone TEXT,
                id_number TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                reject_reason TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS agent_sessions (
                token_hash TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                expires_at REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS agent_email_otps (
                token_hash TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                code_hash TEXT NOT NULL,
                expires_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        agent_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(agents)").fetchall()
        }
        if "telegram_chat_id" not in agent_columns:
            db.execute("ALTER TABLE agents ADD COLUMN telegram_chat_id TEXT")
        if "telegram_pair_token_hash" not in agent_columns:
            db.execute("ALTER TABLE agents ADD COLUMN telegram_pair_token_hash TEXT")
        if "telegram_pair_expires_at" not in agent_columns:
            db.execute("ALTER TABLE agents ADD COLUMN telegram_pair_expires_at REAL")
        if "username" not in agent_columns:
            db.execute("ALTER TABLE agents ADD COLUMN username TEXT")
        if "email" not in agent_columns:
            db.execute("ALTER TABLE agents ADD COLUMN email TEXT")
        if "password_hash" not in agent_columns:
            db.execute("ALTER TABLE agents ADD COLUMN password_hash TEXT")
        if "must_change_password" not in agent_columns:
            db.execute(
                "ALTER TABLE agents ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 1"
            )
        if "referral_code" not in agent_columns:
            db.execute("ALTER TABLE agents ADD COLUMN referral_code TEXT")
        application_columns = {
            row["name"] for row in db.execute("PRAGMA table_info(applications)").fetchall()
        }
        if "status" not in application_columns:
            db.execute(
                "ALTER TABLE applications ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
            )
        db.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_telegram_chat_id
               ON agents (telegram_chat_id) WHERE telegram_chat_id IS NOT NULL"""
        )
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_username ON agents (lower(username)) WHERE username IS NOT NULL"
        )
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_email ON agents (lower(email)) WHERE email IS NOT NULL"
        )
        db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('signing_key', ?)",
            (secrets.token_urlsafe(48),),
        )
        seed_agents(db)


def seed_agents(db=None):
    if db is None:
        with connect_db() as connection:
            seed_agents(connection)
        return

    agents_to_seed = []

    # 1. Load from agents_seed.json if present
    seed_file = os.environ.get("EMOLA_AGENTS_SEED_FILE")
    if not seed_file:
        seed_file = os.path.join(ROOT, "agents_seed.json")
    if os.path.exists(seed_file):
        try:
            with open(seed_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    agents_to_seed.extend(data)
                elif isinstance(data, dict):
                    agents_to_seed.append(data)
        except Exception as e:
            print(f"Warning: Failed to load agents_seed.json: {e}")

    # 2. Load from EMOLA_SEED_AGENTS environment variable
    env_seeds = os.environ.get("EMOLA_SEED_AGENTS", "").strip()
    if env_seeds:
        if env_seeds.startswith("[") or env_seeds.startswith("{"):
            try:
                parsed = json.loads(env_seeds)
                if isinstance(parsed, list):
                    agents_to_seed.extend(parsed)
                elif isinstance(parsed, dict):
                    agents_to_seed.append(parsed)
            except Exception as e:
                print(f"Warning: Failed to parse EMOLA_SEED_AGENTS as JSON: {e}")
        else:
            entries = [e.strip() for e in env_seeds.replace(",", ";").split(";") if e.strip()]
            for entry in entries:
                parts = [p.strip() for p in entry.split(":")]
                if parts and parts[0]:
                    agents_to_seed.append({
                        "name": parts[0],
                        "telegram_chat_id": parts[1] if len(parts) > 1 and parts[1] else None,
                        "referral_code": parts[2] if len(parts) > 2 and parts[2] else parts[0],
                        "email": parts[3] if len(parts) > 3 and parts[3] else None,
                    })

    # Process each agent
    for entry in agents_to_seed:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("display_name") or entry.get("name") or "").strip()
        if not name:
            continue
        agent_id = str(entry.get("id") or "").strip() or None
        username = str(entry.get("username") or name).strip().lower()
        ref_code = str(entry.get("referral_code") or entry.get("referralCode") or name).strip()
        chat_id = entry.get("telegram_chat_id") or entry.get("telegramChatId")
        if chat_id is not None:
            chat_id = str(chat_id).strip()
            if not chat_id or not chat_id.lstrip("-").isdigit():
                chat_id = None
        email = str(entry.get("email") or "").strip() or None

        try:
            existing = None
            if agent_id:
                existing = db.execute("SELECT id FROM agents WHERE id = ?", (agent_id,)).fetchone()
            if not existing and username:
                existing = db.execute("SELECT id FROM agents WHERE lower(username) = lower(?)", (username,)).fetchone()
            if not existing and ref_code:
                existing = db.execute("SELECT id FROM agents WHERE lower(referral_code) = lower(?)", (ref_code,)).fetchone()
            if not existing and name:
                existing = db.execute("SELECT id FROM agents WHERE lower(display_name) = lower(?)", (name,)).fetchone()
            if not existing and chat_id:
                existing = db.execute("SELECT id FROM agents WHERE telegram_chat_id = ?", (chat_id,)).fetchone()

            if existing:
                db.execute(
                    """UPDATE agents
                       SET display_name = COALESCE(?, display_name),
                           referral_code = COALESCE(?, referral_code),
                           telegram_chat_id = COALESCE(?, telegram_chat_id),
                           email = COALESCE(?, email),
                           status = 'active'
                       WHERE id = ?""",
                    (name, ref_code, chat_id, email, existing["id"]),
                )
            else:
                new_id = agent_id or str(uuid.uuid4())
                token_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
                db.execute(
                    """INSERT INTO agents (
                        id, display_name, access_token_hash, username, email,
                        status, referral_code, telegram_chat_id
                    ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
                    (new_id, name, token_hash, username, email, ref_code, chat_id),
                )
                print(f"[Seed] Successfully seeded agent: {name} (ref: {ref_code})")
        except sqlite3.Error as e:
            print(f"[Seed] Warning: Could not seed agent {name}: {e}")



def valid_email_address(email):
    if not isinstance(email, str) or len(email) > 254:
        return False
    return parseaddr(email)[1] == email and email.count("@") == 1 and " " not in email


def masked_email(email):
    local_part, domain = email.split("@", 1)
    return f"{local_part[:1]}***@{domain}"


def send_agent_otp(email, code):
    host = os.environ.get("EMOLA_SMTP_HOST", "").strip()
    username = os.environ.get("EMOLA_SMTP_USERNAME", "").strip()
    password = os.environ.get("EMOLA_SMTP_PASSWORD", "")
    sender = os.environ.get("EMOLA_SMTP_FROM", username).strip()
    port = int(os.environ.get("EMOLA_SMTP_PORT", "587"))
    if not all((host, username, password, sender)):
        raise RuntimeError("Email OTP is not configured")
    message = EmailMessage()
    message["Subject"] = "Your E-Mola agent login code"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your E-Mola login code is {code}. It expires in 5 minutes. "
        "If you did not request this code, you can ignore this email."
    )
    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as client:
            client.login(username, password)
            client.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=20) as client:
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
            client.login(username, password)
            client.send_message(message)


def signing_key():
    configured = os.environ.get("EMOLA_SIGNING_KEY")
    if configured:
        if len(configured) < 32:
            raise RuntimeError("EMOLA_SIGNING_KEY must be at least 32 characters")
        return configured.encode("utf-8")
    with connect_db() as db:
        return db.execute(
            "SELECT value FROM settings WHERE key = 'signing_key'"
        ).fetchone()["value"].encode("utf-8")


def b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def create_referral_token(agent_id):
    with connect_db() as db:
        agent = db.execute(
            "SELECT id, username, referral_code FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
        if agent and agent["referral_code"]:
            return agent["referral_code"]
        candidate = (
            agent["username"]
            if agent and agent["username"] and len(agent["username"]) <= 20
            else None
        )
        if not candidate:
            candidate = secrets.token_hex(4)
        existing = db.execute(
            "SELECT id FROM agents WHERE lower(referral_code) = lower(?) AND id != ?",
            (candidate, agent_id),
        ).fetchone()
        if existing:
            candidate = f"{candidate[:8]}_{secrets.token_hex(2)}"
        db.execute(
            "UPDATE agents SET referral_code = ? WHERE id = ?", (candidate, agent_id)
        )
        return candidate


def resolve_referral_token(token):
    if not token or not isinstance(token, str):
        return None
    cleaned = token.strip()
    with connect_db() as db:
        agent = db.execute(
            """SELECT id FROM agents
               WHERE (lower(referral_code) = lower(?) OR lower(username) = lower(?) OR id = ?)
                 AND status = 'active'""",
            (cleaned, cleaned, cleaned),
        ).fetchone()
        if agent:
            return agent["id"]

    try:
        if "." in cleaned:
            encoded, provided_signature = cleaned.split(".", 1)
            expected = b64url(
                hmac.new(signing_key(), encoded.encode("ascii"), hashlib.sha256).digest()
            )
            if hmac.compare_digest(provided_signature, expected):
                payload_text = encoded + "=" * (-len(encoded) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_text))
                if int(payload["expires"]) >= int(time.time()):
                    with connect_db() as db:
                        row = db.execute(
                            "SELECT id FROM agents WHERE id = ? AND status = 'active'",
                            (payload["agent_id"],),
                        ).fetchone()
                        if row:
                            return row["id"]
    except Exception:
        pass
    return None


def clean_text(value, field, maximum, minimum=1):
    if not isinstance(value, str):
        raise ValueError(f"{field} is required")
    result = value.strip()
    if not minimum <= len(result) <= maximum:
        raise ValueError(f"{field} is invalid")
    return result


def validated_application(data):
    first_name = clean_text(data.get("firstName"), "firstName", 100)
    last_name = clean_text(data.get("lastName"), "lastName", 100)
    phone = data.get("phone")
    if not isinstance(phone, str) or not re.fullmatch(r"8[2-7]\d{7}", phone.strip()):
        raise ValueError("phone is invalid")
    loan_types = {
        "Empréstimo Comercial",
        "Empréstimo Pessoal",
        "Empréstimo Agrícola",
    }
    loan_type = data.get("loanType")
    if not isinstance(loan_type, str) or loan_type not in loan_types:
        raise ValueError("loanType is invalid")
    try:
        amount = int(data.get("loanAmount"))
        term = int(data.get("termMonths"))
        income = float(data.get("annualIncome"))
    except (TypeError, ValueError, OverflowError):
        raise ValueError("loan or income values are invalid") from None
    if not 10_000 <= amount <= 100_000 or amount != data.get("loanAmount"):
        raise ValueError("loanAmount is invalid")
    if term not in {12, 24, 36, 48}:
        raise ValueError("termMonths is invalid")
    if not 0 < income <= 1_000_000_000_000:
        raise ValueError("annualIncome is invalid")
    employment = data.get("employment")
    if not isinstance(employment, str) or employment not in {
        "Autónomo", "Empregado", "Empresário", "Estudante"
    }:
        raise ValueError("employment is invalid")
    purpose = clean_text(data.get("purpose"), "purpose", 2_000, 2)
    submission_id = data.get("submissionId")
    try:
        submission_id = str(uuid.UUID(submission_id))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("submissionId is invalid") from None
    consent = data.get("consentToAgentContact") is True
    referral_token = data.get("referralToken")
    if referral_token is not None and not isinstance(referral_token, str):
        raise ValueError("referralToken is invalid")
    agent_id = resolve_referral_token(referral_token) if referral_token else None
    if referral_token and agent_id is None:
        raise ValueError("referralToken is invalid or expired")
    return {
        "id": str(uuid.uuid4()),
        "submission_id": submission_id,
        "agent_id": agent_id,
        "first_name": first_name,
        "last_name": last_name,
        "phone": phone.strip(),
        "loan_type": loan_type,
        "loan_amount": amount,
        "term_months": term,
        "purpose": purpose,
        "employment": employment,
        "annual_income": income,
        "agent_contact_consent": int(consent),
    }


def telegram_api(method, payload):
    token = telegram_bot_token()
    if not token:
        raise RuntimeError("Telegram bot token is not configured")
    request = Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=35) as response:
        result = json.loads(response.read())
    if not result.get("ok"):
        raise RuntimeError("Telegram API rejected the request")
    return result.get("result")


def send_telegram_message(chat_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return telegram_api("sendMessage", payload)


def answer_telegram_callback(callback_query_id, text=None):
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
    return telegram_api("answerCallbackQuery", payload)


def edit_telegram_message(chat_id, message_id, text, reply_markup=None):
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    return telegram_api("editMessageText", payload)


def stage_buttons(app_id, current_stage):
    current = (current_stage or "pending").lower()
    stages = [
        ("under_review", "🔍 Under Review"),
        ("approved", "✅ Approve Loan"),
        ("rejected", "❌ Reject"),
    ]
    buttons = []
    for key, label in stages:
        text = f"• {label} •" if key == current else label
        buttons.append({"text": text, "callback_data": f"stage:{key}:{app_id}"})
    return {"inline_keyboard": [buttons]}


def pair_telegram_agent(pairing_code, chat_id):
    if not isinstance(pairing_code, str) or not 16 <= len(pairing_code) <= 64:
        return None
    token_hash = hashlib.sha256(pairing_code.encode("utf-8")).hexdigest()
    try:
        with connect_db() as db:
            agent = db.execute(
                """SELECT id, display_name FROM agents
                   WHERE telegram_pair_token_hash = ?
                     AND telegram_pair_expires_at > ? AND status = 'active'""",
                (token_hash, time.time()),
            ).fetchone()
            if not agent:
                return None
            db.execute(
                """UPDATE agents
                   SET telegram_chat_id = ?, telegram_pair_token_hash = NULL,
                       telegram_pair_expires_at = NULL
                   WHERE id = ?""",
                (chat_id, agent["id"]),
            )
            return agent["display_name"]
    except sqlite3.IntegrityError:
        return None


def handle_telegram_message(message):
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    text = message.get("text", "")
    if not chat_id or not text:
        return
    parts = text.split()
    command = parts[0].split("@", 1)[0].lower()
    configured_chat = telegram_admin_chat_id()
    pairing_code = None
    if command == "/link" and len(parts) == 2:
        pairing_code = parts[1]
    elif command == "/start" and len(parts) == 2 and parts[1].startswith("link_"):
        pairing_code = parts[1][5:]
    if pairing_code:
        if chat.get("type") != "private":
            reply = "Open the agent pairing link in a private chat with this bot."
        else:
            agent_name = pair_telegram_agent(pairing_code, chat_id)
            reply = (
                f"Telegram connected to agent account: {agent_name}. "
                "Application alerts will be sent here directly."
                if agent_name
                else "This pairing link is invalid, expired, or already used. Ask the admin for a new link."
            )
    elif command in {"/start", "/help", "/chatid", "/id"}:
        if configured_chat and chat_id == configured_chat:
            reply = (
                "E-Mola admin bot connected. Admin alerts are enabled.\n"
                f"Chat ID: {chat_id}\nCommands: /start, /help, /chatid"
            )
        elif command == "/chatid" or not configured_chat:
            reply = (
                f"E-Mola bot is running. Chat ID: {chat_id}\n\n"
                "👉 Send this Chat ID to your admin to receive your personal referral link.\n"
                "All applications submitted via your link will arrive here directly."
            )
        else:
            reply = (
                f"E-Mola bot is running. Chat ID: {chat_id}\n\n"
                "👉 Send this Chat ID to your admin to receive your personal referral link.\n"
                "All applications submitted via your link will arrive here directly."
            )
    else:
        return
    send_telegram_message(chat_id, reply)


def handle_telegram_callback(callback_query):
    query_id = callback_query.get("id")
    data = callback_query.get("data", "")
    message = callback_query.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    message_id = message.get("message_id")

    if data.startswith("verify:"):
        handle_verify_callback(query_id, data, chat_id, message_id, message)
        return

    if not data.startswith("stage:"):
        answer_telegram_callback(query_id, text="Ação desconhecida.")
        return

    parts = data.split(":")
    if len(parts) != 3:
        answer_telegram_callback(query_id, text="Dados inválidos.")
        return

    _, new_stage, app_id = parts
    stage_names = {
        "pending": "Pendente",
        "under_review": "Em Análise",
        "approved": "Aprovado",
        "rejected": "Rejeitado",
    }
    if new_stage not in stage_names:
        answer_telegram_callback(query_id, text="Estágio inválido.")
        return

    with connect_db() as db:
        app = db.execute("SELECT id, status FROM applications WHERE id = ?", (app_id,)).fetchone()
        if not app:
            answer_telegram_callback(query_id, text="Candidatura não encontrada.")
            return
        db.execute("UPDATE applications SET status = ? WHERE id = ?", (new_stage, app_id))

    display_names = {
        "pending": "Pendente",
        "under_review": "🔍 Em Análise",
        "approved": "✅ Aprovado",
        "rejected": "❌ Rejeitado",
    }
    display_name = display_names[new_stage]
    try:
        answer_telegram_callback(query_id, text=f"Decisão registada: {display_name}")
    except Exception:
        pass

    if chat_id and message_id:
        existing_text = message.get("text", "")
        lines = existing_text.splitlines()
        new_lines = []
        for line in lines:
            if line.startswith("Status:") or line.startswith("📊 Estágio") or line.startswith("📋 Decisão:"):
                continue
            new_lines.append(line)
        new_lines.append(f"\n📋 Decisão: {display_name}")

        # Remove buttons once approved or rejected so it's clear the action completed
        reply_markup = (
            {"inline_keyboard": []}
            if new_stage in ("approved", "rejected")
            else stage_buttons(app_id, new_stage)
        )
        try:
            edit_telegram_message(
                chat_id,
                message_id,
                "\n".join(new_lines),
                reply_markup=reply_markup,
            )
        except Exception:
            pass


def handle_verify_callback(query_id, data, chat_id, message_id, message):
    """Handle verify:approve:<vid> and verify:reject:<vid> Telegram callbacks."""
    parts = data.split(":")
    if len(parts) != 3:
        answer_telegram_callback(query_id, text="Dados inválidos.")
        return

    _, action, verification_id = parts
    if action not in ("approve", "reject"):
        answer_telegram_callback(query_id, text="Ação inválida.")
        return

    new_status = "approved" if action == "approve" else "rejected"
    reject_reason = "Dados não correspondem aos registos." if action == "reject" else None

    with connect_db() as db:
        ver = db.execute(
            "SELECT id, application_id, step, status FROM verifications WHERE id = ?",
            (verification_id,),
        ).fetchone()
        if not ver:
            answer_telegram_callback(query_id, text="Verificação não encontrada.")
            return
        if ver["status"] != "pending":
            answer_telegram_callback(query_id, text="Esta verificação já foi processada.")
            return
        db.execute(
            "UPDATE verifications SET status = ?, reject_reason = ? WHERE id = ?",
            (new_status, reject_reason, verification_id),
        )

    label = "✅ Aprovado" if action == "approve" else "❌ Rejeitado"
    step_label = "PIN + Telefone" if ver["step"] == "zip_phone" else "Documento de ID"
    try:
        answer_telegram_callback(query_id, text=f"Verificação {step_label}: {label}")
    except Exception:
        pass

    if chat_id and message_id:
        existing_text = (message.get("text") or "") + f"\n\n📋 Decisão: {label}"
        try:
            edit_telegram_message(chat_id, message_id, existing_text, reply_markup={"inline_keyboard": []})
        except Exception:
            pass


def telegram_update_loop():
    offset = None
    while True:
        try:
            payload = {"timeout": 25, "allowed_updates": ["message", "callback_query"]}
            if offset is not None:
                payload["offset"] = offset
            updates = telegram_api("getUpdates", payload) or []
            for update in updates:
                if "message" in update:
                    handle_telegram_message(update.get("message") or {})
                elif "callback_query" in update:
                    handle_telegram_callback(update.get("callback_query") or {})
                offset = max(offset or 0, int(update.get("update_id", 0)) + 1)
        except Exception as error:
            error_details = str(error)
            if hasattr(error, "read"):
                try:
                    error_details += " - " + error.read().decode()
                except Exception:
                    pass
            print(f"Telegram update polling failed ({type(error).__name__}: {error_details}); retrying.")
            time.sleep(5)


_telegram_threads_active = False
_telegram_lock = threading.Lock()


def ensure_telegram_threads_running():
    global _telegram_threads_active
    token = telegram_bot_token()
    if not token:
        return False
    with _telegram_lock:
        if not _telegram_threads_active:
            threading.Thread(target=telegram_update_loop, daemon=True).start()
            threading.Thread(target=telegram_notification_loop, daemon=True).start()
            _telegram_threads_active = True
            print("Telegram bot polling and notification workers started.")
        return True


def hash_agent_password(password):
    salt = secrets.token_bytes(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join(
        (
            "pbkdf2_sha256",
            str(iterations),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        )
    )


def verify_agent_password(password, stored_hash):
    try:
        algorithm, iterations, salt_text, digest_text = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def telegram_notification_loop():
    while True:
        try:
            with connect_db() as db:
                agent_event = db.execute(
                    """SELECT o.id AS event_id, a.id, a.first_name, a.last_name,
                              a.phone, a.loan_type, a.loan_amount, a.term_months,
                              a.purpose, a.employment, a.annual_income, a.status,
                              g.telegram_chat_id
                       FROM telegram_agent_outbox o
                       JOIN applications a ON a.id = o.application_id
                       JOIN agents g ON g.id = a.agent_id
                       WHERE o.sent_at IS NULL AND o.next_attempt_at <= ?
                         AND g.telegram_chat_id IS NOT NULL
                       ORDER BY o.created_at LIMIT 1""",
                    (time.time(),),
                ).fetchone()
                admin_event = None
                if agent_event is None:
                    admin_event = db.execute(
                          """SELECT o.id AS event_id, a.id, a.first_name, a.last_name,
                              a.phone, a.loan_type, a.loan_amount, a.term_months,
                              a.purpose, a.employment, a.annual_income, a.agent_id,
                              a.agent_contact_consent, a.status
                       FROM telegram_outbox o
                       JOIN applications a ON a.id = o.application_id
                       WHERE o.sent_at IS NULL AND o.next_attempt_at <= ?
                       ORDER BY o.created_at LIMIT 1""",
                        (time.time(),),
                    ).fetchone()
            event = agent_event or admin_event
            if event is None:
                time.sleep(2)
                continue
            if agent_event:
                destination = event["telegram_chat_id"]
                current_status = (event["status"] or "pending").lower()
                status_label = {
                    "pending": "Pending",
                    "under_review": "Under Review",
                    "approved": "Approved",
                    "rejected": "Rejected",
                }.get(current_status, current_status.title())
                text = (
                    "New E-Mola application\n"
                    f"Applicant: {event['first_name']} {event['last_name']}\n"
                    f"Phone: +258 {event['phone']}\n"
                    f"Loan: {event['loan_type']}\n"
                    f"Amount: MTS {event['loan_amount']:,}\n"
                    f"Term: {event['term_months']} months\n"
                    f"Application reference: {event['id']}\n"
                    f"Status: {status_label}"
                )
                outbox_table = "telegram_agent_outbox"
                reply_markup = stage_buttons(event['id'], current_status)
            else:
                agent = event["agent_id"] or "Direct"
                consent = "Yes" if event["agent_contact_consent"] else "No"
                destination = telegram_admin_chat_id()
                current_status = (event["status"] or "pending").lower()
                status_label = {
                    "pending": "Pending",
                    "under_review": "Under Review",
                    "approved": "Approved",
                    "rejected": "Rejected",
                }.get(current_status, current_status.title())
                text = (
                    "New E-Mola application\n"
                    f"Application reference: {event['id']}\n"
                    f"Loan type: {event['loan_type']}\n"
                    f"Loan amount: MTS {event['loan_amount']:,}\n"
                    f"Term: {event['term_months']} months\n"
                    f"Purpose: {event['purpose']}\n"
                    f"Employment: {event['employment']}\n"
                    f"Annual income: MTS {event['annual_income']:,.0f}\n"
                    f"Referral agent ID: {agent}\n"
                    f"Agent contact authorized: {consent}\n"
                    f"Status: {status_label}"
                )
                outbox_table = "telegram_outbox"
                reply_markup = stage_buttons(event['id'], current_status)
            try:
                if reply_markup is not None:
                    send_telegram_message(
                        destination,
                        text,
                        reply_markup=reply_markup,
                    )
                else:
                    send_telegram_message(destination, text)
            except Exception as error:
                with connect_db() as db:
                    current = db.execute(
                        f"SELECT attempts FROM {outbox_table} WHERE id = ?",
                        (event["event_id"],),
                    ).fetchone()
                    attempt_count = current["attempts"] + 1
                    delay = min(2 ** min(attempt_count, 12), 3600)
                    db.execute(
                        f"""UPDATE {outbox_table}
                            SET attempts = ?, next_attempt_at = ?, last_error = ?
                            WHERE id = ?""",
                        (
                            attempt_count,
                            time.time() + delay,
                            type(error).__name__,
                            event["event_id"],
                        ),
                    )
            else:
                with connect_db() as db:
                    db.execute(
                        f"UPDATE {outbox_table} SET sent_at = CURRENT_TIMESTAMP, last_error = NULL WHERE id = ?",
                        (event["event_id"],),
                    )
        except Exception as error:
            print(f"Telegram notification worker failed ({type(error).__name__}); retrying.")
            time.sleep(5)


class Handler(BaseHTTPRequestHandler):
    server_version = "EmolaReferral/1.0"

    def send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        for header, value in extra_headers or []:
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Content-Type must be application/json")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 32_768:
            raise ValueError("Request body size is invalid")
        return json.loads(self.rfile.read(length))

    def authorized(self, token):
        header = self.headers.get("Authorization", "")
        scheme, _, provided = header.partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(provided, token)

    def agent_session(self):
        try:
            cookies = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        session_cookie = cookies.get("emola_agent_session")
        if not session_cookie:
            return None
        token_hash = hashlib.sha256(session_cookie.value.encode("utf-8")).hexdigest()
        with connect_db() as db:
            return db.execute(
                """SELECT a.id, a.username, a.must_change_password, s.token_hash
                   FROM agent_sessions s JOIN agents a ON a.id = s.agent_id
                   WHERE s.token_hash = ? AND s.expires_at > ? AND a.status = 'active'""",
                (token_hash, time.time()),
            ).fetchone()

    def session_cookie(self, token, max_age):
        secure = "; Secure" if os.environ.get("EMOLA_COOKIE_SECURE") == "1" else ""
        return (
            f"emola_agent_session={token}; Path=/; Max-Age={max_age}; "
            f"HttpOnly; SameSite=Strict{secure}"
        )

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/health":
            return self.send_json(200, {"status": "ok"})
        if path == "/api/agent/leads":
            return self.agent_leads()
        if path == "/api/agent/me":
            session = self.agent_session()
            if not session:
                return self.send_json(401, {"error": "Please log in"})
            return self.send_json(
                200,
                {
                    "username": session["username"],
                    "mustChangePassword": bool(session["must_change_password"]),
                },
            )
        if path == "/api/admin/settings":
            return self.get_admin_settings()
        if path == "/api/admin/agents":
            return self.list_agents()
        if path == "/api/admin/applications":
            return self.list_applications()
        if path.startswith("/api/applications/") and path.endswith("/status"):
            parts = path.split("/")
            if len(parts) == 5:
                return self.application_status(parts[3])
        if path.startswith("/api/applications/") and path.endswith("/verification"):
            parts = path.split("/")
            if len(parts) == 5:
                return self.get_verification_status(parts[3])

        if path.startswith("/r/"):
            code = path[3:].strip()
            if code:
                self.send_response(302)
                self.send_header("Location", f"/?ref={code}")
                self.end_headers()
                return

        pages = {
            "/": "e-mola-loan-flow (1).html",
            "/admin": "admin.html",
            "/agent": "agent.html",
        }
        filename = pages.get(path)
        if filename:
            try:
                body = (ROOT / filename).read_bytes()
            except OSError:
                return self.send_error(404)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(body)
        if path == "/language.js":
            try:
                body = (ROOT / "language.js").read_bytes()
            except OSError:
                return self.send_error(404)
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            return self.wfile.write(body)
        return self.send_error(404)

    def do_POST(self):
        path = urlsplit(self.path).path
        try:
            data = self.read_json()
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {"error": "Invalid JSON request"})
        if path == "/api/admin/settings":
            return self.update_admin_settings(data)
        if path == "/api/admin/agents":
            return self.create_agent(data)
        if path == "/api/admin/agents/message":
            return self.message_agents(data)
        if path == "/api/admin/applications/stage":
            return self.update_application_stage(data)
        if path == "/api/agent/login":
            return self.agent_login(data)
        if path == "/api/agent/verify-otp":
            return self.verify_agent_otp(data)
        if path == "/api/agent/password":
            return self.change_agent_password(data)
        if path == "/api/agent/logout":
            return self.agent_logout()
        if path == "/api/applications":
            return self.create_application(data)
        if path.startswith("/api/applications/") and path.endswith("/verify"):
            parts = path.split("/")
            if len(parts) == 5:
                return self.submit_verification(parts[3], data)
        return self.send_json(404, {"error": "Not found"})

    def get_admin_settings(self):
        if not self.authorized(ADMIN_TOKEN):
            return self.send_json(401, {"error": "Unauthorized"})
        token = telegram_bot_token()
        masked_token = (token[:6] + "..." + token[-4:]) if len(token) > 10 else ("Configured" if token else "")
        return self.send_json(
            200,
            {
                "hasBotToken": bool(token),
                "maskedBotToken": masked_token,
                "adminChatId": telegram_admin_chat_id(),
                "botUsername": telegram_bot_username(),
                "botRunning": _telegram_threads_active,
            },
        )

    def update_admin_settings(self, data):
        if not self.authorized(ADMIN_TOKEN):
            return self.send_json(401, {"error": "Unauthorized"})
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid settings data"})
        bot_token = data.get("botToken")
        admin_chat_id = data.get("adminChatId")
        bot_username = data.get("botUsername")

        if bot_token is not None and str(bot_token).strip():
            set_setting("telegram_bot_token", str(bot_token).strip())
        if admin_chat_id is not None:
            set_setting("telegram_admin_chat_id", str(admin_chat_id).strip())
        if bot_username is not None and str(bot_username).strip():
            clean_username = str(bot_username).strip().lstrip("@")
            set_setting("telegram_bot_username", clean_username)

        running = ensure_telegram_threads_running()
        return self.send_json(200, {"ok": True, "botRunning": running or _telegram_threads_active})

    def list_agents(self):
        if not self.authorized(ADMIN_TOKEN):
            return self.send_json(401, {"error": "Unauthorized"})
        with connect_db() as db:
            rows = db.execute(
                """SELECT a.id, a.display_name, a.username, a.email,
                          a.telegram_chat_id, a.status, a.created_at,
                          COUNT(app.id) AS lead_count
                   FROM agents a
                   LEFT JOIN applications app ON app.agent_id = a.id
                   GROUP BY a.id
                   ORDER BY a.created_at DESC"""
            ).fetchall()
        host = self.headers.get("Host", f"{HOST}:{PORT}")
        agents = []
        for r in rows:
            token = create_referral_token(r["id"])
            agents.append({
                "id": r["id"],
                "displayName": r["display_name"],
                "username": r["username"],
                "email": r["email"],
                "telegramChatId": r["telegram_chat_id"],
                "status": r["status"],
                "createdAt": r["created_at"],
                "leadCount": r["lead_count"],
                "referralUrl": f"http://{host}/?ref={token}",
            })
        return self.send_json(200, {"agents": agents})

    def list_applications(self):
        if not self.authorized(ADMIN_TOKEN):
            return self.send_json(401, {"error": "Unauthorized"})
        with connect_db() as db:
            rows = db.execute(
                """SELECT a.id, a.first_name, a.last_name, a.phone,
                          a.loan_type, a.loan_amount, a.term_months,
                          a.purpose, a.employment, a.annual_income,
                          a.status, a.created_at, a.agent_id,
                          g.display_name AS agent_name, g.telegram_chat_id AS agent_chat_id
                   FROM applications a
                   LEFT JOIN agents g ON g.id = a.agent_id
                   ORDER BY a.created_at DESC LIMIT 100"""
            ).fetchall()
        return self.send_json(200, {"applications": [dict(r) for r in rows]})

    def update_application_stage(self, data):
        if not self.authorized(ADMIN_TOKEN):
            return self.send_json(401, {"error": "Unauthorized"})
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid request"})
        app_id = data.get("applicationId")
        new_stage = data.get("stage")
        valid_stages = {"pending", "under_review", "approved", "rejected"}
        if not app_id or new_stage not in valid_stages:
            return self.send_json(400, {"error": "Invalid application ID or stage"})
        with connect_db() as db:
            app = db.execute(
                """SELECT a.id, a.first_name, a.last_name, a.loan_amount,
                          a.agent_id, g.telegram_chat_id
                   FROM applications a
                   LEFT JOIN agents g ON g.id = a.agent_id
                   WHERE a.id = ?""",
                (app_id,),
            ).fetchone()
            if not app:
                return self.send_json(404, {"error": "Application not found"})
            db.execute("UPDATE applications SET status = ? WHERE id = ?", (new_stage, app_id))

        stage_labels = {
            "pending": "Pendente",
            "under_review": "Em Análise",
            "approved": "Aprovado",
            "rejected": "Rejeitado",
        }
        if app["telegram_chat_id"] and telegram_bot_token():
            try:
                msg = (
                    f"📢 Atualização de Estágio / Stage Update:\n"
                    f"Ref: {app_id}\n"
                    f"Candidato: {app['first_name']} {app['last_name']}\n"
                    f"Novo Estágio: {stage_labels.get(new_stage, new_stage)}"
                )
                send_telegram_message(app["telegram_chat_id"], msg)
            except Exception:
                pass
        return self.send_json(200, {"ok": True, "stage": new_stage})

    def application_status(self, app_id):
        try:
            val_uuid = str(uuid.UUID(app_id))
        except (ValueError, TypeError, AttributeError):
            return self.send_json(400, {"error": "Invalid application ID"})
        with connect_db() as db:
            row = db.execute(
                """SELECT id, status, loan_amount, term_months, purpose, created_at
                   FROM applications WHERE id = ?""",
                (val_uuid,),
            ).fetchone()
            if not row:
                return self.send_json(404, {"error": "Application not found"})
            verifications = db.execute(
                """SELECT id, step, status, reject_reason, created_at
                   FROM verifications WHERE application_id = ?
                   ORDER BY created_at DESC""",
                (val_uuid,),
            ).fetchall()
        ver_list = [dict(v) for v in verifications]
        return self.send_json(
            200,
            {
                "id": row["id"],
                "status": row["status"],
                "amount": row["loan_amount"],
                "loanAmount": row["loan_amount"],
                "termMonths": row["term_months"],
                "purpose": row["purpose"],
                "createdAt": row["created_at"],
                "verifications": ver_list,
            },
        )

    def get_verification_status(self, app_id):
        try:
            val_uuid = str(uuid.UUID(app_id))
        except (ValueError, TypeError, AttributeError):
            return self.send_json(400, {"error": "Invalid application ID"})
        with connect_db() as db:
            app = db.execute("SELECT id, status FROM applications WHERE id = ?", (val_uuid,)).fetchone()
            if not app:
                return self.send_json(404, {"error": "Application not found"})
            verifications = db.execute(
                """SELECT id, step, status, reject_reason, created_at
                   FROM verifications WHERE application_id = ?
                   ORDER BY created_at DESC""",
                (val_uuid,),
            ).fetchall()
        return self.send_json(200, {
            "applicationStatus": app["status"],
            "verifications": [dict(v) for v in verifications],
        })

    def submit_verification(self, app_id, data):
        try:
            val_uuid = str(uuid.UUID(app_id))
        except (ValueError, TypeError, AttributeError):
            return self.send_json(400, {"error": "Invalid application ID"})
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid verification data"})
        step = data.get("step")
        if step not in ("zip_phone", "id_document"):
            return self.send_json(400, {"error": "Invalid verification step"})

        with connect_db() as db:
            app = db.execute(
                """SELECT a.id, a.first_name, a.last_name, a.phone, a.status,
                          a.agent_id, g.telegram_chat_id
                   FROM applications a
                   LEFT JOIN agents g ON g.id = a.agent_id
                   WHERE a.id = ?""",
                (val_uuid,),
            ).fetchone()
            if not app:
                return self.send_json(404, {"error": "Application not found"})
            if app["status"] != "approved":
                return self.send_json(400, {"error": "Application must be approved before verification"})

            # Check for pending verification of same step
            pending = db.execute(
                """SELECT id FROM verifications
                   WHERE application_id = ? AND step = ? AND status = 'pending'""",
                (val_uuid, step),
            ).fetchone()
            if pending:
                return self.send_json(409, {"error": "A verification for this step is already pending"})

            ver_id = str(uuid.uuid4())
            zip_code = None
            phone = None
            id_number = None

            if step == "zip_phone":
                zip_code = str(data.get("zipCode", "")).strip()
                phone = str(data.get("phone", "")).strip()
                if not zip_code or not phone:
                    return self.send_json(400, {"error": "PIN and phone number are required"})
            elif step == "id_document":
                id_number = str(data.get("idNumber", "")).strip()
                if not id_number:
                    return self.send_json(400, {"error": "ID number is required"})

            db.execute(
                """INSERT INTO verifications (id, application_id, step, zip_code, phone, id_number)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (ver_id, val_uuid, step, zip_code, phone, id_number),
            )

        # Send verification data to agent's Telegram
        agent_chat = app["telegram_chat_id"]
        if agent_chat and telegram_bot_token():
            step_label = "📍 PIN + Telefone" if step == "zip_phone" else "🪪 Documento de Identidade"
            lines = [
                f"📋 Verificação de Identidade — {step_label}",
                f"Ref: {val_uuid}",
                f"Candidato: {app['first_name']} {app['last_name']}",
            ]
            if step == "zip_phone":
                lines.append(f"PIN: {zip_code}")
                lines.append(f"Telefone: +258 {phone}")
            elif step == "id_document":
                lines.append(f"Nº de Identificação (BI): {id_number}")
            lines.append(f"Estágio: Aguardando Verificação")

            buttons = {
                "inline_keyboard": [[
                    {"text": "✅ Approve", "callback_data": f"verify:approve:{ver_id}"},
                    {"text": "❌ Reject", "callback_data": f"verify:reject:{ver_id}"},
                ]]
            }
            try:
                send_telegram_message(agent_chat, "\n".join(lines), reply_markup=buttons)
            except Exception:
                pass

        return self.send_json(201, {"verificationId": ver_id, "step": step, "status": "pending"})

    def create_agent(self, data):
        if not self.authorized(ADMIN_TOKEN):
            return self.send_json(401, {"error": "Unauthorized"})
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid agent data"})
        try:
            name = clean_text(data.get("displayName"), "displayName", 100)
            telegram_chat_id = data.get("telegramChatId")
            if telegram_chat_id is not None:
                telegram_chat_id = str(telegram_chat_id).strip()
                if telegram_chat_id and not telegram_chat_id.lstrip("-").isdigit():
                    raise ValueError("Telegram Chat ID must be numeric")
                if not telegram_chat_id:
                    telegram_chat_id = None

            raw_username = data.get("username")
            if raw_username and isinstance(raw_username, str) and raw_username.strip():
                username = clean_text(raw_username, "username", 50)
            elif telegram_chat_id:
                username = f"agent_{telegram_chat_id}"
            else:
                username = f"agent_{secrets.token_hex(4)}"

            raw_email = data.get("email")
            email = None
            if raw_email:
                cleaned_email = clean_text(raw_email, "email", 254).lower()
                if not valid_email_address(cleaned_email):
                    raise ValueError("Email address is invalid")
                email = cleaned_email
        except ValueError as error:
            return self.send_json(400, {"error": str(error)})

        agent_id = str(uuid.uuid4())
        temporary_password = secrets.token_urlsafe(16)
        password_hash = hash_agent_password(temporary_password)
        pairing_code = secrets.token_urlsafe(24)
        pairing_token_hash = hashlib.sha256(pairing_code.encode("utf-8")).hexdigest()
        bot_user = telegram_bot_username()
        pairing_url = f"https://t.me/{bot_user}?start=link_{pairing_code}"
        try:
            with connect_db() as db:
                db.execute(
                    """INSERT INTO agents (
                        id, display_name, access_token_hash, username, email, password_hash,
                        must_change_password, telegram_chat_id,
                        telegram_pair_token_hash, telegram_pair_expires_at
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
                    (
                        agent_id,
                        name,
                        hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
                        username,
                        email,
                        password_hash,
                        telegram_chat_id,
                        pairing_token_hash if not telegram_chat_id else None,
                        (time.time() + 15 * 60) if not telegram_chat_id else None,
                    ),
                )
        except sqlite3.IntegrityError as error:
            error_text = str(error).lower()
            if "username" in error_text:
                return self.send_json(400, {"error": "Username is already in use"})
            if "telegram_chat_id" in error_text:
                return self.send_json(400, {"error": "Telegram Chat ID is already registered to another agent"})
            return self.send_json(400, {"error": "Agent details conflict with an existing account"})
        except sqlite3.Error:
            return self.send_json(500, {"error": "Could not create agent"})

        token = create_referral_token(agent_id)
        host = self.headers.get("Host", f"{HOST}:{PORT}")
        referral_url = f"http://{host}/?ref={token}"

        if telegram_chat_id and telegram_bot_token():
            try:
                welcome_msg = (
                    f"👋 Olá, {name}!\n\n"
                    f"A sua conta de agente E-Mola foi criada com sucesso.\n\n"
                    f"🔗 O seu Link de Referência exclusivo:\n{referral_url}\n\n"
                    f"Partilhe este link para encaminhar clientes diretamente pelo seu perfil!"
                )
                send_telegram_message(telegram_chat_id, welcome_msg)
            except Exception:
                pass

        return self.send_json(
            201,
            {
                "agentId": agent_id,
                "displayName": name,
                "username": username,
                "email": email,
                "telegramChatId": telegram_chat_id,
                "temporaryPassword": temporary_password,
                "referralToken": token,
                "referralUrl": referral_url,
                "telegramPairingUrl": pairing_url,
            },
        )

    def message_agents(self, data):
        if not self.authorized(ADMIN_TOKEN):
            return self.send_json(401, {"error": "Unauthorized"})
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid request"})

        target = data.get("target")
        message_text = (data.get("message") or "").strip()
        custom_chat_id = (data.get("chatId") or "").strip()

        if not message_text:
            return self.send_json(400, {"error": "Message text is required"})

        if not telegram_bot_token():
            return self.send_json(400, {"error": "Telegram bot token is not configured"})

        recipients = []
        if target == "all":
            with connect_db() as db:
                rows = db.execute(
                    """SELECT display_name, telegram_chat_id FROM agents
                       WHERE telegram_chat_id IS NOT NULL AND trim(telegram_chat_id) != ''
                         AND status = 'active'"""
                ).fetchall()
                recipients = [(r["telegram_chat_id"], r["display_name"]) for r in rows]
        elif target == "custom" or (not target and custom_chat_id):
            if not custom_chat_id:
                return self.send_json(400, {"error": "Chat ID is required"})
            recipients = [(custom_chat_id, "Custom Chat")]
        elif target:
            with connect_db() as db:
                row = db.execute(
                    """SELECT display_name, telegram_chat_id FROM agents
                       WHERE id = ? OR username = ?""",
                    (target, target),
                ).fetchone()
                if not row or not row["telegram_chat_id"]:
                    return self.send_json(400, {"error": "Selected agent does not have a configured Telegram Chat ID"})
                recipients = [(row["telegram_chat_id"], row["display_name"])]
        else:
            return self.send_json(400, {"error": "Please select a recipient"})

        if not recipients:
            return self.send_json(400, {"error": "No agents found with a Telegram Chat ID"})

        sent_count = 0
        errors = []
        for chat_id, name in recipients:
            try:
                send_telegram_message(chat_id, message_text)
                sent_count += 1
            except Exception as e:
                errors.append(f"{name} ({chat_id}): {str(e)}")

        return self.send_json(200, {
            "ok": True,
            "sent": sent_count,
            "total": len(recipients),
            "errors": errors if errors else [],
        })

    def agent_login(self, data):
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid login data"})
        username = data.get("username")
        password = data.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            return self.send_json(400, {"error": "Username and password are required"})
        with connect_db() as db:
            agent = db.execute(
                """SELECT id, email, password_hash, must_change_password
                   FROM agents WHERE lower(username) = ? AND status = 'active'""",
                (username.strip().lower(),),
            ).fetchone()
        if not agent or not agent["password_hash"] or not verify_agent_password(
            password, agent["password_hash"]
        ):
            return self.send_json(401, {"error": "Invalid username or password"})
        if not agent["email"]:
            return self.send_json(400, {"error": "No email is configured for this account"})
        rate_limited = False
        with connect_db() as db:
            recent_challenge = db.execute(
                """SELECT strftime('%s', 'now') - strftime('%s', created_at) AS age
                   FROM agent_email_otps WHERE agent_id = ?""",
                (agent["id"],),
            ).fetchone()
            if recent_challenge and recent_challenge["age"] < 60:
                rate_limited = True
            else:
                db.execute("DELETE FROM agent_email_otps WHERE agent_id = ?", (agent["id"],))
        if rate_limited:
            return self.send_json(429, {"error": "Wait one minute before requesting another code"})
        challenge_token = secrets.token_urlsafe(32)
        otp_code = f"{secrets.randbelow(1_000_000):06d}"
        challenge_hash = hashlib.sha256(challenge_token.encode("utf-8")).hexdigest()
        code_hash = hashlib.sha256(
            f"{challenge_token}:{otp_code}".encode("utf-8")
        ).hexdigest()
        try:
            with connect_db() as db:
                db.execute(
                    """INSERT INTO agent_email_otps
                       (token_hash, agent_id, code_hash, expires_at)
                       VALUES (?, ?, ?, ?)""",
                    (challenge_hash, agent["id"], code_hash, time.time() + 300),
                )
            send_agent_otp(agent["email"], otp_code)
        except (OSError, RuntimeError, smtplib.SMTPException, ValueError) as error:
            with connect_db() as db:
                db.execute(
                    "DELETE FROM agent_email_otps WHERE token_hash = ?",
                    (challenge_hash,),
                )
            print(f"Agent OTP email delivery failed ({type(error).__name__}).")
            return self.send_json(503, {"error": "Could not send email code. Check SMTP configuration."})
        return self.send_json(
            200,
            {
                "otpRequired": True,
                "challengeToken": challenge_token,
                "maskedEmail": masked_email(agent["email"]),
            },
        )

    def verify_agent_otp(self, data):
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid verification data"})
        challenge_token = data.get("challengeToken")
        code = data.get("code")
        if (
            not isinstance(challenge_token, str)
            or not isinstance(code, str)
            or not re.fullmatch(r"\d{6}", code)
        ):
            return self.send_json(400, {"error": "Enter the six-digit email code"})
        challenge_hash = hashlib.sha256(challenge_token.encode("utf-8")).hexdigest()
        failure = None
        agent_id = None
        must_change_password = False
        with connect_db() as db:
            challenge = db.execute(
                """SELECT o.agent_id, o.code_hash, o.expires_at, o.attempts,
                          a.must_change_password
                   FROM agent_email_otps o JOIN agents a ON a.id = o.agent_id
                   WHERE o.token_hash = ? AND a.status = 'active'""",
                (challenge_hash,),
            ).fetchone()
            if not challenge or challenge["expires_at"] <= time.time():
                db.execute("DELETE FROM agent_email_otps WHERE token_hash = ?", (challenge_hash,))
                failure = (401, "Email code expired or invalid")
            elif challenge["attempts"] >= 5:
                db.execute("DELETE FROM agent_email_otps WHERE token_hash = ?", (challenge_hash,))
                failure = (429, "Too many incorrect codes. Log in again.")
            else:
                code_hash = hashlib.sha256(
                    f"{challenge_token}:{code}".encode("utf-8")
                ).hexdigest()
            if challenge and challenge["attempts"] < 5 and not failure and not hmac.compare_digest(
                code_hash, challenge["code_hash"]
            ):
                attempts = challenge["attempts"] + 1
                if attempts >= 5:
                    db.execute(
                        "DELETE FROM agent_email_otps WHERE token_hash = ?",
                        (challenge_hash,),
                    )
                else:
                    db.execute(
                        "UPDATE agent_email_otps SET attempts = ? WHERE token_hash = ?",
                        (attempts, challenge_hash),
                    )
                failure = (401, "Email code is incorrect")
            elif challenge and not failure:
                db.execute("DELETE FROM agent_email_otps WHERE token_hash = ?", (challenge_hash,))
                agent_id = challenge["agent_id"]
                must_change_password = bool(challenge["must_change_password"])
        if failure:
            return self.send_json(failure[0], {"error": failure[1]})
        session_token = secrets.token_urlsafe(32)
        expires_at = time.time() + 8 * 60 * 60
        with connect_db() as db:
            db.execute(
                "INSERT INTO agent_sessions (token_hash, agent_id, expires_at) VALUES (?, ?, ?)",
                (
                    hashlib.sha256(session_token.encode("utf-8")).hexdigest(),
                    agent_id,
                    expires_at,
                ),
            )

        return self.send_json(
            200,
            {"mustChangePassword": must_change_password},
            [("Set-Cookie", self.session_cookie(session_token, 8 * 60 * 60))],
        )

    def change_agent_password(self, data):
        session = self.agent_session()
        if not session:
            return self.send_json(401, {"error": "Please log in"})
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid password data"})
        current_password = data.get("currentPassword")
        new_password = data.get("newPassword")
        if not isinstance(current_password, str) or not isinstance(new_password, str):
            return self.send_json(400, {"error": "Current and new password are required"})
        if len(new_password) < 12 or len(new_password) > 128:
            return self.send_json(400, {"error": "New password must be 12 to 128 characters"})
        password_incorrect = False
        with connect_db() as db:
            agent = db.execute(
                "SELECT password_hash FROM agents WHERE id = ?", (session["id"],)
            ).fetchone()
            if not agent or not verify_agent_password(current_password, agent["password_hash"]):
                password_incorrect = True
            else:
                db.execute(
                    "UPDATE agents SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                    (hash_agent_password(new_password), session["id"]),
                )
        if password_incorrect:
            return self.send_json(401, {"error": "Current password is incorrect"})
        return self.send_json(200, {"ok": True})

    def agent_logout(self):
        session = self.agent_session()
        if session:
            with connect_db() as db:
                db.execute(
                    "DELETE FROM agent_sessions WHERE token_hash = ?",
                    (session["token_hash"],),
                )
        return self.send_json(
            200,
            {"ok": True},
            [("Set-Cookie", self.session_cookie("", 0))],
        )

    def create_application(self, data):
        if not isinstance(data, dict):
            return self.send_json(400, {"error": "Invalid application data"})
        try:
            application = validated_application(data)
            with connect_db() as db:
                existing = db.execute(
                    "SELECT id FROM applications WHERE submission_id = ?",
                    (application["submission_id"],),
                ).fetchone()
                if existing:
                    return self.send_json(200, {"applicationId": existing["id"]})
                db.execute(
                    """INSERT INTO applications (
                        id, submission_id, agent_id, first_name, last_name, phone,
                        loan_type, loan_amount, term_months, purpose, employment,
                        annual_income, agent_contact_consent
                    ) VALUES (
                        :id, :submission_id, :agent_id, :first_name, :last_name,
                        :phone, :loan_type, :loan_amount, :term_months, :purpose,
                        :employment, :annual_income, :agent_contact_consent
                    )""",
                    application,
                )
                if telegram_bot_token():
                    if application["agent_id"]:
                        db.execute(
                            "INSERT INTO telegram_agent_outbox (id, application_id) VALUES (?, ?)",
                            (str(uuid.uuid4()), application["id"]),
                        )
                    elif telegram_admin_chat_id():
                        db.execute(
                            "INSERT INTO telegram_outbox (id, application_id) VALUES (?, ?)",
                            (str(uuid.uuid4()), application["id"]),
                        )
        except ValueError as error:
            return self.send_json(400, {"error": str(error)})
        except sqlite3.IntegrityError:
            with connect_db() as db:
                existing = db.execute(
                    "SELECT id FROM applications WHERE submission_id = ?",
                    (application["submission_id"],),
                ).fetchone()
            return self.send_json(200, {"applicationId": existing["id"]})
        except sqlite3.Error:
            return self.send_json(500, {"error": "Could not submit application"})
        return self.send_json(201, {"applicationId": application["id"]})

    def agent_leads(self):
        session = self.agent_session()
        if not session:
            return self.send_json(401, {"error": "Please log in"})
        if session["must_change_password"]:
            return self.send_json(403, {"error": "Change your temporary password first"})
        with connect_db() as db:
            rows = db.execute(
                """SELECT id, first_name, last_name, phone, loan_type, loan_amount,
                          term_months, status, created_at
                   FROM applications
                   WHERE agent_id = ? AND agent_contact_consent = 1
                   ORDER BY created_at DESC LIMIT 200""",
                (session["id"],),
            ).fetchall()
        return self.send_json(200, {"leads": [dict(row) for row in rows]})

    def log_message(self, format, *args):
        message = format % args
        if "/api/" in message:
            super().log_message(format, *args)


if __name__ == "__main__":
    initialize_db()
    if not os.environ.get("EMOLA_ADMIN_TOKEN"):
        print(f"Local admin token: {ADMIN_TOKEN}")
    print(f"E-Mola referral prototype: http://{HOST}:{PORT}")
    running = ensure_telegram_threads_running()
    if running:
        print(f"Telegram bot listener enabled for @{telegram_bot_username()}.")
        if telegram_admin_chat_id():
            print("Telegram admin notifications enabled.")
    else:
        print("Telegram bot waiting for token: configure in /admin settings or with EMOLA_TELEGRAM_BOT_TOKEN.")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()