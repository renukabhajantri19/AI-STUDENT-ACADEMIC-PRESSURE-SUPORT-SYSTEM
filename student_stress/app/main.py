from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
import io
import secrets
import smtplib
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./academic_support.db")
DB_IS_MYSQL = DB_URL.startswith(("mysql://", "mysql+pymysql://"))
if DB_IS_MYSQL:
    parsed_db_url = urlsplit(DB_URL)
    MYSQL_DATABASE = parsed_db_url.path.lstrip("/")
    if not re.fullmatch(r"[A-Za-z0-9_]+", MYSQL_DATABASE):
        raise RuntimeError("DATABASE_URL must include a database name containing only letters, numbers, and underscores.")
    MYSQL_CONFIG = {
        "host": parsed_db_url.hostname or "localhost",
        "port": parsed_db_url.port or 3306,
        "user": unquote(parsed_db_url.username or ""),
        "password": unquote(parsed_db_url.password or ""),
        "charset": "utf8mb4",
        "autocommit": False,
    }
elif DB_URL.startswith("sqlite:///"):
    DB_PATH = (ROOT / DB_URL.removeprefix("sqlite:///./")).resolve()
else:
    raise RuntimeError("DATABASE_URL must use sqlite:/// or mysql+pymysql://.")
SECRET = os.getenv("APP_SECRET", "development-only-change-this-secret")
TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "720"))
fernet_key = os.getenv("MESSAGE_ENCRYPTION_KEY")
if not fernet_key:
    fernet_key = base64.urlsafe_b64encode(hashlib.sha256((SECRET + "message-key").encode()).digest()).decode()
cipher = Fernet(fernet_key.encode())
UPLOAD_DIR = ROOT / "private_uploads"
SUBJECTS = [
    ("TTLA", "Transform Techniques and Linear Algebra"),
    ("DDCO", "Digital Design and Computer Organization"),
    ("DS", "Data Structures"),
    ("OOPJ", "Object Oriented Programming with Java"),
    ("DMS", "Discrete Mathematical Structures"),
    ("UHV", "Universal Human Value Course"),
    ("AEC3", "Ability Enhancement Course-III"),
    ("DSL", "Data Structures Lab"),
    ("OOPJL", "Object-Oriented Programming with Java Lab"),
]

app = FastAPI(title="Academic Pressure Support API", version="1.0.0")
security = HTTPBearer(auto_error=False)


@contextmanager
def db():
    if DB_IS_MYSQL:
        import pymysql
        from pymysql.cursors import DictCursor

        connection = pymysql.connect(**MYSQL_CONFIG, database=MYSQL_DATABASE, cursorclass=DictCursor)
        connection = MySQLConnection(connection)
    else:
        connection = sqlite3.connect(DB_PATH)
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


class MySQLRow(dict):
    def __getitem__(self, key):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


class MySQLCursor:
    def __init__(self, cursor):
        self.cursor = cursor

    def __iter__(self):
        return iter(self.fetchall())

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    def fetchone(self):
        row = self.cursor.fetchone()
        return MySQLRow(row) if row is not None else None

    def fetchall(self):
        return [MySQLRow(row) for row in self.cursor.fetchall()]


class MySQLConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, parameters=()):
        cursor = self.connection.cursor()
        cursor.execute(query.replace("?", "%s"), parameters)
        return MySQLCursor(cursor)

    def executescript(self, script):
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return base64.b64encode(salt + digest).decode()


def password_ok(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), raw[:16], 240_000)
        return hmac.compare_digest(raw[16:], digest)
    except (ValueError, TypeError):
        return False


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_token(user: dict[str, Any]) -> str:
    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64(json.dumps({"sub": user["id"], "role": user["role"], "name": user["name"], "exp": int(time.time()) + TOKEN_MINUTES * 60}, separators=(",", ":")).encode())
    message = f"{header}.{payload}"
    signature = b64(hmac.new(SECRET.encode(), message.encode(), hashlib.sha256).digest())
    return f"{message}.{signature}"


def current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)) -> dict[str, Any]:
    if not credentials:
        raise HTTPException(status_code=401, detail="Sign in to continue")
    try:
        header, payload, signature = credentials.credentials.split(".")
        expected = b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            raise ValueError("signature")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        if claims["exp"] < time.time():
            raise ValueError("expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    with db() as con:
        row = con.execute("SELECT id, name, email, `role` FROM users WHERE id=?", (claims["sub"],)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    return dict(row)


def require_role(role: str):
    def check(user: dict[str, Any] = Depends(current_user)):
        if user["role"] != role:
            raise HTTPException(status_code=403, detail="This action is not available for your account")
        return user
    return check


class LoginBody(BaseModel):
    email: str
    password: str


class EmailBody(BaseModel):
    email: str


class ChallengeBody(BaseModel):
    challenge_id: str


class RegistrationBody(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role: str
    department: str = Field(min_length=2, max_length=255)
    identifier: str = Field(min_length=1, max_length=64)
    subject_id: int | None = None


class OtpBody(BaseModel):
    challenge_id: str
    code: str = Field(min_length=6, max_length=6)


class PasswordResetBody(OtpBody):
    new_password: str = Field(min_length=8, max_length=128)


class FeatureInput(BaseModel):
    assignments: int = Field(ge=0, le=3)
    notes: int = Field(ge=0, le=100)
    understanding: int = Field(ge=1, le=5)
    readiness: int = Field(ge=1, le=5)
    readiness_scale: int | None = Field(default=None, ge=3, le=3)


class AssessmentBody(BaseModel):
    subjects: list[int] = Field(min_length=1, max_length=9)
    responses: FeatureInput


class RequestBody(BaseModel):
    subject_id: int
    message: str = Field(min_length=1, max_length=2000)
    consent: bool


class ResponseBody(BaseModel):
    request_id: int
    message: str = Field(min_length=1, max_length=2000)


def risk_result(item: FeatureInput) -> dict[str, Any]:
    parts = {
        "Assignments completed": (3-item.assignments)/3*30,
        "Notes completion": (100-item.notes)/100*20,
        "Class concept understanding": (item.understanding-1)/4*25,
        "Exam readiness": (item.readiness-1)/(2 if item.readiness_scale == 3 else 4)*25,
    }
    score = round(sum(parts.values()))
    level = "Low" if score <= 40 else "Moderate" if score <= 70 else "High"
    return {"score": score, "level": level, "factors": sorted(parts.items(), key=lambda pair: pair[1], reverse=True)}


def migrate_legacy_support_messages(con) -> None:
    """Copy the original student note and any one-off lecturer replies into thread storage."""
    requests = con.execute("SELECT id,student_id,encrypted_message,image_path,attachment_name,created_at FROM support_requests").fetchall()
    for row in requests:
        if con.execute("SELECT 1 FROM support_messages WHERE legacy_source='support_request' AND legacy_source_id=?", (row["id"],)).fetchone():
            continue
        con.execute(
            "INSERT INTO support_messages(request_id,sender_id,sender_role,encrypted_message,image_path,attachment_name,created_at,read_at_student,legacy_source,legacy_source_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (row["id"], row["student_id"], "student", row["encrypted_message"], row["image_path"], row["attachment_name"], row["created_at"], row["created_at"], "support_request", row["id"]),
        )
    replies = con.execute("SELECT id,request_id,lecturer_id,encrypted_response,image_path,attachment_name,created_at FROM lecturer_responses").fetchall()
    for row in replies:
        if con.execute("SELECT 1 FROM support_messages WHERE legacy_source='lecturer_response' AND legacy_source_id=?", (row["id"],)).fetchone():
            continue
        con.execute(
            "INSERT INTO support_messages(request_id,sender_id,sender_role,encrypted_message,image_path,attachment_name,created_at,read_at_lecturer,legacy_source,legacy_source_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (row["request_id"], row["lecturer_id"], "lecturer", row["encrypted_response"], row["image_path"], row["attachment_name"], row["created_at"], row["created_at"], "lecturer_response", row["id"]),
        )


def thread_last_message(con, request_id: int, sender_role: str | None = None):
    if sender_role:
        return con.execute("SELECT * FROM support_messages WHERE request_id=? AND sender_role=? ORDER BY created_at DESC,id DESC LIMIT 1", (request_id, sender_role)).fetchone()
    return con.execute("SELECT * FROM support_messages WHERE request_id=? ORDER BY created_at DESC,id DESC LIMIT 1", (request_id,)).fetchone()


def thread_summary(con, request_id: int, viewer_role: str) -> dict[str, Any]:
    latest = thread_last_message(con, request_id)
    unread_column = "read_at_student" if viewer_role == "student" else "read_at_lecturer"
    incoming_role = "lecturer" if viewer_role == "student" else "student"
    unread = con.execute(f"SELECT COUNT(*) FROM support_messages WHERE request_id=? AND sender_role=? AND {unread_column} IS NULL", (request_id, incoming_role)).fetchone()[0]
    if not latest:
        return {"last_message": "", "last_message_role": None, "last_message_at": None, "unread_count": unread}
    return {
        "last_message": cipher.decrypt(latest["encrypted_message"].encode()).decode(),
        "last_message_role": latest["sender_role"],
        "last_message_at": latest["created_at"],
        "unread_count": unread,
    }


def init_db() -> None:
    if DB_IS_MYSQL:
        import pymysql

        connection = pymysql.connect(**MYSQL_CONFIG)
        try:
            with connection.cursor() as cursor:
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_DATABASE}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
        finally:
            connection.close()
    else:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as con:
        if DB_IS_MYSQL:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS users(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL UNIQUE, `role` VARCHAR(32) NOT NULL, password_hash TEXT NOT NULL, department VARCHAR(255) NOT NULL DEFAULT 'Computer Science', institutional_id VARCHAR(64) NULL, profile_image LONGBLOB NULL, CHECK (`role` IN ('student','lecturer'))) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS subjects(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, code VARCHAR(64) NOT NULL UNIQUE, name VARCHAR(255) NOT NULL, department VARCHAR(255) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS lecturer_subjects(lecturer_id INT NOT NULL REFERENCES users(id), subject_id INT NOT NULL REFERENCES subjects(id), PRIMARY KEY(lecturer_id, subject_id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS assessments(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, student_id INT NOT NULL REFERENCES users(id), created_at VARCHAR(40) NOT NULL, overall_score INT NOT NULL, risk_level VARCHAR(32) NOT NULL, responses TEXT NOT NULL, KEY idx_assessments_student(student_id, created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS subject_risks(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, assessment_id INT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, subject_id INT NOT NULL REFERENCES subjects(id), score INT NOT NULL, risk_level VARCHAR(32) NOT NULL, factors TEXT NOT NULL, inputs TEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS support_requests(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, student_id INT NOT NULL REFERENCES users(id), subject_id INT NOT NULL REFERENCES subjects(id), lecturer_id INT NOT NULL REFERENCES users(id), encrypted_message TEXT NOT NULL, image_path TEXT NULL, attachment_name VARCHAR(255) NULL, status VARCHAR(32) NOT NULL DEFAULT 'Open', created_at VARCHAR(40) NOT NULL, KEY idx_requests_lecturer(lecturer_id, status, created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS lecturer_responses(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, request_id INT NOT NULL REFERENCES support_requests(id) ON DELETE CASCADE, lecturer_id INT NOT NULL REFERENCES users(id), encrypted_response TEXT NOT NULL, image_path TEXT NULL, attachment_name VARCHAR(255) NULL, created_at VARCHAR(40) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS support_messages(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, request_id INT NOT NULL REFERENCES support_requests(id) ON DELETE CASCADE, sender_id INT NOT NULL REFERENCES users(id), sender_role VARCHAR(32) NOT NULL, encrypted_message TEXT NOT NULL, image_path TEXT NULL, attachment_name VARCHAR(255) NULL, created_at VARCHAR(40) NOT NULL, read_at_student VARCHAR(40) NULL, read_at_lecturer VARCHAR(40) NULL, legacy_source VARCHAR(32) NULL, legacy_source_id INT NULL, UNIQUE KEY idx_support_message_legacy(legacy_source,legacy_source_id), KEY idx_support_messages_thread(request_id,created_at,id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS audit_logs(id INT NOT NULL AUTO_INCREMENT PRIMARY KEY, actor_id INT NULL REFERENCES users(id), action VARCHAR(255) NOT NULL, detail TEXT, created_at VARCHAR(40) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            CREATE TABLE IF NOT EXISTS otp_challenges(challenge_id VARCHAR(64) PRIMARY KEY, email VARCHAR(255) NOT NULL, purpose VARCHAR(24) NOT NULL, code_hash VARCHAR(128) NOT NULL, expires_at BIGINT NOT NULL, resend_after BIGINT NOT NULL, attempts INT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, KEY idx_otp_email(email,purpose,created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
            """)
        else:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, `role` TEXT NOT NULL CHECK(`role` IN ('student','lecturer')), password_hash TEXT NOT NULL, department TEXT NOT NULL DEFAULT 'Computer Science', institutional_id TEXT, profile_image BLOB);
            CREATE TABLE IF NOT EXISTS subjects(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, department TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS lecturer_subjects(lecturer_id INTEGER NOT NULL REFERENCES users(id), subject_id INTEGER NOT NULL REFERENCES subjects(id), PRIMARY KEY(lecturer_id, subject_id));
            CREATE TABLE IF NOT EXISTS assessments(id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, overall_score INTEGER NOT NULL, risk_level TEXT NOT NULL, responses TEXT NOT NULL DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS subject_risks(id INTEGER PRIMARY KEY, assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, subject_id INTEGER NOT NULL REFERENCES subjects(id), score INTEGER NOT NULL, risk_level TEXT NOT NULL, factors TEXT NOT NULL, inputs TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS support_requests(id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL REFERENCES users(id), subject_id INTEGER NOT NULL REFERENCES subjects(id), lecturer_id INTEGER NOT NULL REFERENCES users(id), encrypted_message TEXT NOT NULL, image_path TEXT, attachment_name TEXT, status TEXT NOT NULL DEFAULT 'Open', created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS lecturer_responses(id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES support_requests(id) ON DELETE CASCADE, lecturer_id INTEGER NOT NULL REFERENCES users(id), encrypted_response TEXT NOT NULL, image_path TEXT, attachment_name TEXT, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS support_messages(id INTEGER PRIMARY KEY, request_id INTEGER NOT NULL REFERENCES support_requests(id) ON DELETE CASCADE, sender_id INTEGER NOT NULL REFERENCES users(id), sender_role TEXT NOT NULL CHECK(sender_role IN ('student','lecturer')), encrypted_message TEXT NOT NULL, image_path TEXT, attachment_name TEXT, created_at TEXT NOT NULL, read_at_student TEXT, read_at_lecturer TEXT, legacy_source TEXT, legacy_source_id INTEGER, UNIQUE(legacy_source,legacy_source_id));
            CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), action TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS otp_challenges(challenge_id TEXT PRIMARY KEY, email TEXT NOT NULL, purpose TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, resend_after INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_otp_email ON otp_challenges(email,purpose,created_at);
            CREATE INDEX IF NOT EXISTS idx_assessments_student ON assessments(student_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_requests_lecturer ON support_requests(lecturer_id, status, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_support_messages_thread ON support_messages(request_id, created_at, id);
            """)
        if DB_IS_MYSQL:
            if not con.execute("SHOW COLUMNS FROM users LIKE 'institutional_id'").fetchone():
                con.execute("ALTER TABLE users ADD COLUMN institutional_id VARCHAR(64) NULL")
            if not con.execute("SHOW COLUMNS FROM users LIKE 'profile_image'").fetchone():
                con.execute("ALTER TABLE users ADD COLUMN profile_image LONGBLOB NULL")
        else:
            user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)").fetchall()}
            if "institutional_id" not in user_columns:
                con.execute("ALTER TABLE users ADD COLUMN institutional_id TEXT")
            if "profile_image" not in user_columns:
                con.execute("ALTER TABLE users ADD COLUMN profile_image BLOB")
        # Migrate existing installations in place while retaining IDs and lecturer mappings.
        if DB_IS_MYSQL:
            for table, column, definition in [("assessments","responses","TEXT NOT NULL"),("support_requests","image_path","TEXT NULL"),("lecturer_responses","image_path","TEXT NULL"),("support_requests","attachment_name","VARCHAR(255) NULL"),("lecturer_responses","attachment_name","VARCHAR(255) NULL")]:
                if not con.execute(f"SHOW COLUMNS FROM {table} LIKE '{column}'").fetchone():
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        else:
            for table, column, definition in [("assessments","responses","TEXT NOT NULL DEFAULT '{}'"),("support_requests","image_path","TEXT"),("lecturer_responses","image_path","TEXT"),("support_requests","attachment_name","TEXT"),("lecturer_responses","attachment_name","TEXT")]:
                if not any(row[1] == column for row in con.execute(f"PRAGMA table_info({table})").fetchall()):
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        migrate_legacy_support_messages(con)
        old_subjects = con.execute("SELECT id,code,name FROM subjects").fetchall()
        old_mappings = [(r["lecturer_id"], r["code"], r["name"]) for r in con.execute("SELECT ls.lecturer_id,s.code,s.name FROM lecturer_subjects ls JOIN subjects s ON s.id=ls.subject_id ORDER BY ls.lecturer_id,s.id").fetchall()]
        for index, (code, name) in enumerate(SUBJECTS):
            existing = con.execute("SELECT id FROM subjects WHERE code=?", (code,)).fetchone()
            if existing:
                con.execute("UPDATE subjects SET name=? WHERE id=?", (name, existing[0]))
            elif index < len(old_subjects):
                old = old_subjects[index]
                con.execute("UPDATE subjects SET code=?,name=? WHERE id=?", (code, name, old[0]))
            else:
                con.execute("INSERT INTO subjects(code,name,department) VALUES(?,?,?)", (code, name, "Computer Science"))
        con.execute("DELETE FROM subjects WHERE code NOT IN (" + ",".join("?" for _ in SUBJECTS) + ")", tuple(code for code, _ in SUBJECTS))
        # Translate legacy course assignments to the closest canonical subject group.
        con.execute("DELETE FROM lecturer_subjects")
        canonical_codes={code for code,_ in SUBJECTS}
        for lecturer_id, legacy_code, legacy_name in old_mappings:
            name=legacy_name.lower()
            if legacy_code in canonical_codes: targets=[legacy_code]
            elif "java" in name or "object oriented" in name: targets=["OOPJ","OOPJL"]
            elif "math" in name: targets=["TTLA","DMS"]
            elif "digital" in name or "circuit" in name or "computer organization" in name: targets=["DDCO"]
            elif "data structure" in name or "database" in name: targets=["DS","DSL"]
            else: targets=[]
            # TTLA is intentionally left without an assigned lecturer.
            targets = [code for code in targets if code != "TTLA"]
            for code in targets:
                sid=con.execute("SELECT id FROM subjects WHERE code=?",(code,)).fetchone()[0]
                if not con.execute("SELECT 1 FROM lecturer_subjects WHERE lecturer_id=? AND subject_id=?",(lecturer_id,sid)).fetchone():
                    con.execute("INSERT INTO lecturer_subjects(lecturer_id,subject_id) VALUES(?,?)",(lecturer_id,sid))
        if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            lecturer = con.execute("INSERT INTO users(name,email,`role`,password_hash) VALUES(?,?,?,?)", ("Jordan Lee", "lecturer@demo.edu", "lecturer", password_hash("Faculty123!"))).lastrowid
            student = con.execute("INSERT INTO users(name,email,`role`,password_hash) VALUES(?,?,?,?)", ("Alex Morgan", "student@demo.edu", "student", password_hash("Student123!"))).lastrowid
            con.execute("INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)", (student, "demo_seeded", "Demo accounts and courses created", utcnow()))
        # Keep one canonical teaching assignment per lecturer and enforce it in the database.
        for row in con.execute("SELECT id FROM users WHERE `role`='lecturer'").fetchall():
            mapped = con.execute("SELECT subject_id FROM lecturer_subjects WHERE lecturer_id=? ORDER BY subject_id", (row[0],)).fetchall()
            if len(mapped) > 1:
                con.execute("DELETE FROM lecturer_subjects WHERE lecturer_id=? AND subject_id<>?", (row[0], mapped[0][0]))
        if DB_IS_MYSQL:
            if not con.execute("SHOW INDEX FROM lecturer_subjects WHERE Key_name='idx_lecturer_one_subject'").fetchone():
                con.execute("CREATE UNIQUE INDEX idx_lecturer_one_subject ON lecturer_subjects(lecturer_id)")
        else:
            con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_lecturer_one_subject ON lecturer_subjects(lecturer_id)")


@app.on_event("startup")
def startup():
    init_db()


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "Academic Pressure Support"}


def otp_digest(challenge_id: str, email: str, purpose: str, code: str) -> str:
    value = f"{challenge_id}:{email}:{purpose}:{code}".encode()
    return hmac.new(SECRET.encode(), value, hashlib.sha256).hexdigest()


def send_email_otp(email: str, code: str, purpose: str) -> None:
    host = os.getenv("SMTP_HOST", "").strip()
    sender = os.getenv("SMTP_FROM", "").strip()
    if not host or not sender:
        raise HTTPException(status_code=503, detail="Email verification is not configured. Set SMTP_HOST and SMTP_FROM in the server environment.")
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
        message = EmailMessage()
        message["Subject"] = "Your Clarity verification code" if purpose == "login" else "Reset your Clarity password"
        message["From"] = sender
        message["To"] = email
        action = "sign in" if purpose == "login" else "reset your password"
        message.set_content(f"Your Clarity code to {action} is {code}. It expires in 10 minutes. If you did not request this code, you can ignore this email.")
        username = os.getenv("SMTP_USER", os.getenv("SMTP_USERNAME", ""))
        password = os.getenv("SMTP_PASS", os.getenv("SMTP_PASSWORD", ""))
        if os.getenv("SMTP_USE_SSL", "false").lower() == "true":
            with smtplib.SMTP_SSL(host, port, timeout=15) as server:
                if username:
                    server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=15) as server:
                if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
                    server.starttls()
                if username:
                    server.login(username, password)
                server.send_message(message)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=503, detail="The verification email could not be sent. Check the SMTP server settings and try again.") from error


def smtp_is_configured() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip() and os.getenv("SMTP_FROM", "").strip())


def complete_login(email: str) -> dict[str, Any]:
    with db() as con:
        row = con.execute("SELECT id,name,email,`role` FROM users WHERE lower(email)=lower(?)", (email,)).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="The account could not be verified")
        user = {key: row[key] for key in ("id", "name", "email", "role")}
        con.execute("INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)", (user["id"], "login", "Sign in completed", utcnow()))
    return {"access_token": make_token(user), "token_type": "bearer", "user": user}


def masked_email(email: str) -> str:
    name, _, domain = email.partition("@")
    return f"{name[:1]}{'*' * max(2, len(name)-1)}@{domain}"


def create_otp_challenge(email: str, purpose: str, deliver: bool = True) -> dict[str, Any]:
    email = email.strip().lower()
    now = int(time.time())
    code = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = uuid.uuid4().hex
    with db() as con:
        recent = con.execute("SELECT COUNT(*) FROM otp_challenges WHERE email=? AND purpose=? AND created_at>?", (email, purpose, now-900)).fetchone()[0]
        if recent >= 5:
            raise HTTPException(status_code=429, detail="Too many code requests. Wait 15 minutes before trying again.")
        con.execute("DELETE FROM otp_challenges WHERE expires_at<?", (now,))
        con.execute("INSERT INTO otp_challenges(challenge_id,email,purpose,code_hash,expires_at,resend_after,attempts,created_at) VALUES(?,?,?,?,?,?,0,?)", (challenge_id, email, purpose, otp_digest(challenge_id,email,purpose,code), now+600, now+60, now))
    if deliver:
        try:
            send_email_otp(email, code, purpose)
        except Exception:
            with db() as con:
                con.execute("DELETE FROM otp_challenges WHERE challenge_id=?", (challenge_id,))
            raise
    return {"challenge_id": challenge_id, "masked_email": masked_email(email), "expires_in": 600, "resend_after": 60}


def resend_otp(challenge_id: str, purpose: str) -> dict[str, Any]:
    now = int(time.time())
    with db() as con:
        row = con.execute("SELECT email,resend_after,expires_at FROM otp_challenges WHERE challenge_id=? AND purpose=?", (challenge_id,purpose)).fetchone()
        if not row or row["expires_at"] < now:
            raise HTTPException(status_code=400, detail="This verification session expired. Start again.")
        if row["resend_after"] > now:
            raise HTTPException(status_code=429, detail=f"You can request another code in {row['resend_after']-now} seconds.")
        email = row["email"]
        if purpose == "password_reset" and not con.execute("SELECT 1 FROM users WHERE lower(email)=lower(?)", (email,)).fetchone():
            raise HTTPException(status_code=400, detail="This verification session expired. Start again.")
        code = f"{secrets.randbelow(1_000_000):06d}"
        digest = otp_digest(challenge_id,email,purpose,code)
    send_email_otp(email,code,purpose)
    with db() as con:
        con.execute("UPDATE otp_challenges SET code_hash=?,resend_after=?,attempts=0 WHERE challenge_id=?", (digest,now+60,challenge_id))
    return {"challenge_id":challenge_id,"masked_email":masked_email(email),"expires_in":600,"resend_after":60}


def consume_otp(challenge_id: str, code: str, purpose: str) -> str:
    now = int(time.time())
    error = None
    email = None
    with db() as con:
        row = con.execute("SELECT email,code_hash,expires_at,attempts FROM otp_challenges WHERE challenge_id=? AND purpose=?", (challenge_id,purpose)).fetchone()
        if not row or row["expires_at"] < now:
            error = "This verification code expired. Request a new one."
        elif row["attempts"] >= 5:
            error = "Too many incorrect codes. Request a new one."
        elif not hmac.compare_digest(row["code_hash"],otp_digest(challenge_id,row["email"],purpose,code)):
            con.execute("UPDATE otp_challenges SET attempts=attempts+1 WHERE challenge_id=?", (challenge_id,))
            error = "That verification code is incorrect."
        else:
            email = row["email"]
            con.execute("DELETE FROM otp_challenges WHERE challenge_id=?", (challenge_id,))
    if error:
        raise HTTPException(status_code=400, detail=error)
    return email


@app.post("/api/v1/auth/login")
def login(body: LoginBody):
    with db() as con:
        row = con.execute("SELECT id,name,email,`role`,password_hash FROM users WHERE lower(email)=lower(?)", (body.email.strip(),)).fetchone()
        if not row or not password_ok(body.password, row["password_hash"]):
            raise HTTPException(status_code=401, detail="Email or password is incorrect")
        email=row["email"]
    if not smtp_is_configured():
        return {"otp_required": False, **complete_login(email), "message": "Signed in. Email verification is unavailable until SMTP is configured."}
    challenge=create_otp_challenge(email,"login")
    return {"otp_required":True,**challenge}


@app.post("/api/v1/auth/login/verify")
def verify_login(body: OtpBody):
    email=consume_otp(body.challenge_id,body.code,"login")
    return complete_login(email)


@app.post("/api/v1/auth/login/resend")
def resend_login_code(body: ChallengeBody):
    return resend_otp(body.challenge_id,"login")


@app.post("/api/v1/auth/password-reset/request")
def password_reset_request(body: EmailBody):
    email=body.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email):
        raise HTTPException(status_code=422,detail="Enter a valid email address")
    with db() as con:
        exists=bool(con.execute("SELECT 1 FROM users WHERE lower(email)=lower(?)",(email,)).fetchone())
    challenge=create_otp_challenge(email,"password_reset",deliver=exists)
    return {**challenge,"message":"If an account uses this email, a reset code has been sent."}


@app.post("/api/v1/auth/password-reset/resend")
def resend_password_reset_code(body: ChallengeBody):
    return resend_otp(body.challenge_id,"password_reset")


@app.post("/api/v1/auth/password-reset/confirm")
def password_reset_confirm(body: PasswordResetBody):
    email=consume_otp(body.challenge_id,body.code,"password_reset")
    with db() as con:
        changed=con.execute("UPDATE users SET password_hash=? WHERE lower(email)=lower(?)",(password_hash(body.new_password),email)).rowcount
        if not changed:
            raise HTTPException(status_code=400,detail="Password reset could not be completed")
        user=con.execute("SELECT id FROM users WHERE lower(email)=lower(?)",(email,)).fetchone()
        con.execute("INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)",(user["id"],"password_reset","Password changed using email verification",utcnow()))
    return {"status":"updated","message":"Your password has been updated. Sign in with the new password."}


@app.post("/api/v1/auth/register")
def register(body: RegistrationBody):
    name = body.name.strip()
    email = body.email.strip().lower()
    department = body.department.strip()
    if body.role not in ("student", "lecturer"):
        raise HTTPException(status_code=422, detail="Choose student or lecturer registration")
    if body.role == "lecturer" and body.subject_id is None:
        raise HTTPException(status_code=422, detail="Select the subject you teach")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="Enter a valid email address")
    if not name or not department or not body.identifier.strip():
        raise HTTPException(status_code=422, detail="Complete all required fields")
    with db() as con:
        if con.execute("SELECT id FROM users WHERE lower(email)=lower(?)", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="An account with this email already exists")
        if body.role == "lecturer" and not con.execute("SELECT 1 FROM subjects WHERE id=? AND code<>'TTLA'", (body.subject_id,)).fetchone():
            raise HTTPException(status_code=422, detail="Select a subject with a lecturer assignment available")
        account_id = con.execute(
            "INSERT INTO users(name,email,`role`,password_hash,department,institutional_id) VALUES(?,?,?,?,?,?)",
            (name, email, body.role, password_hash(body.password), department, body.identifier.strip()),
        ).lastrowid
        if body.role == "lecturer":
            con.execute("INSERT INTO lecturer_subjects(lecturer_id,subject_id) VALUES(?,?)", (account_id, body.subject_id))
        user = {"id": account_id, "name": name, "email": email, "role": body.role}
        con.execute("INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)", (account_id, "registered", f"New {body.role} account", utcnow()))
    return {"status": "registered", "user": user, "message": "Sign in to verify your email and continue."}


@app.get("/api/v1/auth/me")
def me(user=Depends(current_user)):
    return user


@app.get("/api/v1/auth/profile")
def account_profile(user=Depends(current_user)):
    """Return profile fields for the authenticated account only."""
    with db() as con:
        row = con.execute("SELECT id,name,email,`role`,department,institutional_id FROM users WHERE id=?", (user["id"],)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Profile not found")
        profile = {
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
            "department": row["department"],
            "identifier_label": "Student ID" if row["role"] == "student" else "Employee ID",
            "identifier": row["institutional_id"],
        }
        if row["role"] == "lecturer":
            profile["subjects_handled"] = [
                subject["name"] for subject in con.execute(
                    "SELECT s.name FROM subjects s JOIN lecturer_subjects ls ON ls.subject_id=s.id WHERE ls.lecturer_id=? ORDER BY s.name",
                    (user["id"],),
                ).fetchall()
            ]
        return profile


@app.get("/api/v1/auth/registration-subjects")
def registration_subjects():
    with db() as con:
        return [dict(row) for row in con.execute("SELECT id,code,name FROM subjects WHERE code<>'TTLA' ORDER BY name").fetchall()]


@app.get("/api/v1/student/subjects")
def subjects(user=Depends(require_role("student"))):
    with db() as con:
        rows = con.execute("SELECT s.id,s.code,s.name,ls.lecturer_id,u.name AS lecturer_name,u.institutional_id AS lecturer_identifier FROM subjects s LEFT JOIN (SELECT subject_id,MIN(lecturer_id) AS lecturer_id FROM lecturer_subjects GROUP BY subject_id) ls ON ls.subject_id=s.id LEFT JOIN users u ON u.id=ls.lecturer_id ORDER BY CASE s.code WHEN 'TTLA' THEN 1 WHEN 'DDCO' THEN 2 WHEN 'DS' THEN 3 WHEN 'OOPJ' THEN 4 WHEN 'DMS' THEN 5 WHEN 'UHV' THEN 6 WHEN 'AEC3' THEN 7 WHEN 'DSL' THEN 8 WHEN 'OOPJL' THEN 9 END").fetchall()
    return [dict(row) for row in rows]


@app.post("/api/v1/assessment/submit")
def submit_assessment(body: AssessmentBody, user=Depends(require_role("student"))):
    with db() as con:
        valid = {row[0] for row in con.execute("SELECT id FROM subjects")}
        if any(subject_id not in valid for subject_id in body.subjects):
            raise HTTPException(status_code=422, detail="One or more subjects are not registered")
        if len(set(body.subjects)) != len(body.subjects):
            raise HTTPException(status_code=422, detail="Each subject can only be submitted once")
        results = [(subject_id, risk_result(body.responses)) for subject_id in body.subjects]
        overall = round(sum(result["score"] for _, result in results) / len(results))
        overall_level = "Low" if overall <= 40 else "Moderate" if overall <= 70 else "High"
        created_at = utcnow()
        aid = con.execute("INSERT INTO assessments(student_id,created_at,overall_score,risk_level,responses) VALUES(?,?,?,?,?)", (user["id"], created_at, overall, overall_level, body.responses.model_dump_json())).lastrowid
        response = []
        for subject_id, result in results:
            factors = [{"name": name, "contribution": round(value, 1)} for name, value in result["factors"] if value > 0]
            con.execute("INSERT INTO subject_risks(assessment_id,subject_id,score,risk_level,factors,inputs) VALUES(?,?,?,?,?,?)", (aid, subject_id, result["score"], result["level"], json.dumps(factors), body.responses.model_dump_json()))
            subject = con.execute("SELECT code,name FROM subjects WHERE id=?", (subject_id,)).fetchone()
            response.append({"subject_id": subject_id, "code": subject["code"], "name": subject["name"], "score": result["score"], "level": result["level"], "factors": factors, "plan": catch_up_plan(body.responses, factors)})
        con.execute("INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)", (user["id"], "assessment_submitted", f"Assessment {aid}", utcnow()))
    return {"assessment_id": aid, "student_name": user["name"], "student_email": user["email"], "created_at": created_at, "responses": body.responses.model_dump(), "overall_score": overall, "estimated_risk_percentage": overall, "risk_level": overall_level, "recommendations":["Focus first on the subject with the highest estimated risk.","Break study into short, scheduled sessions and ask the assigned lecturer for help with unclear topics."], "subjects": response}


def catch_up_plan(item: FeatureInput, factors: list[dict[str, Any]]) -> list[dict[str, str]]:
    focus = factors[0]["name"] if factors else "Maintain your current routine"
    tasks = [
        ("Day 1", f"List open work and choose one small task focused on {focus.lower()}"),
        ("Day 2", "Review key concepts for 30 minutes, then try two practice questions"),
        ("Day 3", "Complete one assignment section and check it against your notes"),
        ("Day 4", "Summarize this week’s topics and ask your lecturer about unclear points"),
        ("Day 5", "Take a short self-check quiz and plan the next study block around your closest deadline"),
    ]
    return [{"day": day, "task": task} for day, task in tasks]


@app.get("/api/v1/student/assessments")
def history(user=Depends(require_role("student"))):
    with db() as con:
        rows = con.execute("SELECT id,created_at,overall_score,risk_level FROM assessments WHERE student_id=? ORDER BY created_at DESC LIMIT 12", (user["id"],)).fetchall()
        result = []
        for row in rows:
            subjects = con.execute("SELECT s.code,s.name,r.score,r.risk_level FROM subject_risks r JOIN subjects s ON s.id=r.subject_id WHERE r.assessment_id=? ORDER BY r.score DESC", (row["id"],)).fetchall()
            result.append({**dict(row), "estimated_risk_percentage": row["overall_score"], "subjects": [dict(item) for item in subjects]})
    return result


def assessment_report(con, assessment_id, student_id=None, lecturer_id=None):
    query = "SELECT a.*,u.name AS student_name,u.email AS student_email FROM assessments a JOIN users u ON u.id=a.student_id WHERE a.id=?"
    row = con.execute(query, (assessment_id,)).fetchone()
    if not row or (student_id is not None and row["student_id"] != student_id):
        raise HTTPException(status_code=404, detail="Report not found")
    risks = con.execute("SELECT s.id,s.code,s.name,r.score,r.risk_level,r.factors,r.inputs FROM subject_risks r JOIN subjects s ON s.id=r.subject_id WHERE r.assessment_id=? ORDER BY r.score DESC", (assessment_id,)).fetchall()
    if lecturer_id is not None:
        allowed = {r[0] for r in con.execute("SELECT subject_id FROM lecturer_subjects WHERE lecturer_id=?", (lecturer_id,)).fetchall()}
        risks = [r for r in risks if r["id"] in allowed]
        if not risks:
            raise HTTPException(status_code=404, detail="Report not found for your assigned subjects")
    responses = json.loads(row["responses"] or "{}")
    if "assignments" not in responses and risks:
        old = json.loads(risks[0]["inputs"] or "{}")
        if "pending_assignments" in old:
            responses = {"assignments": max(0, 3-min(3, old.get("pending_assignments", 0))), "notes": old.get("notes_completion", 0), "understanding": old.get("topic_comprehension", 3), "readiness": min(5, old.get("cia_prep_status", 3)+1)}
    score = round(sum(r["score"] for r in risks)/len(risks)) if lecturer_id is not None else row["overall_score"]
    level = "Low" if score <= 40 else "Moderate" if score <= 70 else "High"
    def report_subject(r):
        saved=json.loads(r["inputs"] or "{}")
        if "assignments" not in saved:
            saved={"assignments":max(0,3-min(3,saved.get("pending_assignments",0))),"notes":saved.get("notes_completion",0),"understanding":saved.get("topic_comprehension",3),"readiness":min(5,saved.get("cia_prep_status",3)+1)}
        factors=json.loads(r["factors"])
        return {"code":r["code"],"name":r["name"],"score":r["score"],"level":r["risk_level"],"factors":factors,"plan":catch_up_plan(FeatureInput(**saved),factors)}
    report={"assessment_id": row["id"], "student_name": row["student_name"], "created_at": row["created_at"], "responses": responses, "overall_score": score, "estimated_risk_percentage": score, "risk_level": level, "recommendations":["Focus first on the subject with the highest estimated risk.","Break study into short, scheduled sessions and ask the assigned lecturer for help with unclear topics."], "subjects": [report_subject(r) for r in risks]}
    if student_id is not None: report["student_email"]=row["student_email"]
    return report


@app.get("/api/v1/student/assessments/{assessment_id}/report")
def student_report(assessment_id: int, user=Depends(require_role("student"))):
    with db() as con:
        return assessment_report(con, assessment_id, student_id=user["id"])


@app.get("/api/v1/student/assessments/{assessment_id}/report.pdf")
def student_report_pdf(assessment_id: int, user=Depends(require_role("student"))):
    with db() as con:
        report = assessment_report(con, assessment_id, student_id=user["id"])
    return make_pdf(report)


@app.get("/api/v1/lecturer/reports")
def lecturer_reports(user=Depends(require_role("lecturer"))):
    with db() as con:
        rows = con.execute("SELECT DISTINCT a.id,a.created_at,a.overall_score,a.risk_level,u.name AS student_name FROM assessments a JOIN users u ON u.id=a.student_id JOIN subject_risks r ON r.assessment_id=a.id JOIN lecturer_subjects ls ON ls.subject_id=r.subject_id WHERE ls.lecturer_id=? ORDER BY a.created_at DESC LIMIT 100", (user["id"],)).fetchall()
        results=[]
        for row in rows:
            report=assessment_report(con,row["id"],lecturer_id=user["id"])
            results.append({**dict(row),"subjects":report["subjects"]})
        return results


@app.get("/api/v1/lecturer/reports/{assessment_id}/pdf")
def lecturer_report_pdf(assessment_id: int, user=Depends(require_role("lecturer"))):
    with db() as con:
        report=assessment_report(con,assessment_id,lecturer_id=user["id"])
    # Only include responses and risk rows for subjects the lecturer is mapped to.
    return make_pdf(report)


def make_pdf(report):
    buffer=io.BytesIO(); pdf=canvas.Canvas(buffer,pagesize=letter); width,height=letter; y=height-48
    def line(value, size=10):
        nonlocal y
        if y<55: pdf.showPage(); y=height-48
        pdf.setFont("Helvetica",size); pdf.drawString(48,y,str(value)[:110]); y-=size+7
    line("Academic Pressure Assessment Report",16); line(f"Student: {report['student_name']}")
    if report.get("student_email"): line(f"Email ID: {report['student_email']}")
    line(f"Date: {report['created_at']}")
    line(f"Estimated Academic Pressure Risk: {report['estimated_risk_percentage']}% ({report['risk_level']})",12)
    answers=report.get("responses",{})
    readiness = {1:"Ready",2:"Average",3:"Not Ready"}.get(answers.get("readiness")) if answers.get("readiness_scale") == 3 else {1:"Very Ready",2:"Ready",3:"Average",4:"Not Ready",5:"Very Not Ready"}.get(answers.get("readiness"), answers.get("readiness","—"))
    for title,key in [("Assignments completed","assignments"),("Notes completion","notes"),("Class concept understanding","understanding")]: line(f"{title}: {answers.get(key,'—')}")
    line(f"Exam readiness: {readiness}")
    line("Subject-wise risk",12)
    line("Recommendations",12)
    for recommendation in report.get("recommendations",[]): line(recommendation)
    for subject in report["subjects"]:
        line(f"{subject['name']}: {subject['score']}% ({subject['level']})")
        for factor in subject["factors"]: line(f"  Factor: {factor['name']} ({factor['contribution']}%)")
        for step in subject["plan"]: line(f"  {step['day']}: {step['task']}")
    pdf.save(); buffer.seek(0)
    return Response(buffer.getvalue(),media_type="application/pdf",headers={"Content-Disposition":f"attachment; filename=assessment-{report['assessment_id']}-report.pdf"})


async def save_private_attachment(image: UploadFile | None) -> tuple[str | None, str | None]:
    if image is None or not image.filename:
        return None, None
    allowed_types={"image/jpeg":"jpg","image/png":"png","image/webp":"webp","image/gif":"gif","application/pdf":"pdf"}
    if image.content_type not in allowed_types:
        raise HTTPException(status_code=415, detail="Upload a JPG, JPEG, PNG, WebP, GIF, or PDF file")
    data = await image.read(5 * 1024 * 1024 + 1)
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Attachments must be 5 MB or smaller")
    ext = allowed_types[image.content_type]
    if image.content_type == "application/pdf":
        if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
            raise HTTPException(status_code=415, detail="The uploaded PDF file is invalid")
    else:
        # Validate that the uploaded bytes actually decode as an image.
        try:
            from PIL import Image
            decoded = Image.open(io.BytesIO(data)); decoded.verify()
        except Exception:
            raise HTTPException(status_code=415, detail="The uploaded file is not a valid image")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    path = UPLOAD_DIR / f"{uuid.uuid4().hex}.{ext}"
    path.write_bytes(cipher.encrypt(data))
    original_name=Path(image.filename.replace("\\", "/")).name[:255] or f"attachment.{ext}"
    return str(path), original_name


@app.post("/api/v1/support/request")
async def create_request(subject_id: int = Form(...), message: str = Form(...), consent: bool = Form(...), image: UploadFile | None = File(None), user=Depends(require_role("student"))):
    if not message.strip() or len(message) > 2000:
        raise HTTPException(status_code=422, detail="Enter a message up to 2,000 characters")
    if not consent:
        raise HTTPException(status_code=400, detail="Consent is required before sharing a request with the assigned lecturer")
    with db() as con:
        assignment = con.execute("SELECT lecturer_id FROM lecturer_subjects WHERE subject_id=? ORDER BY lecturer_id LIMIT 1", (subject_id,)).fetchone()
        if not assignment:
            raise HTTPException(status_code=404, detail="No lecturer is assigned to this subject yet")
        image_path, attachment_name = await save_private_attachment(image)
        request_id = con.execute("INSERT INTO support_requests(student_id,subject_id,lecturer_id,encrypted_message,image_path,attachment_name,created_at) VALUES(?,?,?,?,?,?,?)", (user["id"], subject_id, assignment["lecturer_id"], cipher.encrypt(message.encode()).decode(), image_path, attachment_name, utcnow())).lastrowid
        created_at = con.execute("SELECT created_at FROM support_requests WHERE id=?", (request_id,)).fetchone()[0]
        con.execute("INSERT INTO support_messages(request_id,sender_id,sender_role,encrypted_message,image_path,attachment_name,created_at,read_at_student,legacy_source,legacy_source_id) VALUES(?,?,?,?,?,?,?,?,?,?)", (request_id, user["id"], "student", cipher.encrypt(message.encode()).decode(), image_path, attachment_name, created_at, created_at, "support_request", request_id))
        con.execute("INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)", (user["id"], "support_request_created", f"Request {request_id}", utcnow()))
    return {"request_id": request_id, "status": "Open", "message": "Your private request was sent to the assigned lecturer."}


def authorized_support_request(con, request_id: int, user: dict[str, Any]):
    row = con.execute("SELECT id,student_id,lecturer_id,subject_id FROM support_requests WHERE id=?", (request_id,)).fetchone()
    allowed = row and (
        (user["role"] == "student" and user["id"] == row["student_id"])
        or (user["role"] == "lecturer" and user["id"] == row["lecturer_id"] and con.execute("SELECT 1 FROM lecturer_subjects WHERE lecturer_id=? AND subject_id=?", (user["id"], row["subject_id"])).fetchone())
    )
    if not allowed:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return row


def support_message_data(row):
    data = dict(row)
    data["message"] = cipher.decrypt(data.pop("encrypted_message").encode()).decode()
    data["image_url"] = f"/api/v1/support/{data['request_id']}/messages/{data['id']}/image" if data.get("image_path") else None
    data["attachment_type"] = Path(data["image_path"]).suffix.lower().lstrip(".") if data.get("image_path") else None
    data.pop("image_path", None)
    return data


async def add_support_message(request_id: int, message: str, image: UploadFile | None, user: dict[str, Any]):
    if not message.strip() or len(message) > 2000:
        raise HTTPException(status_code=422, detail="Enter a message up to 2,000 characters")
    created_at = utcnow()
    encrypted = cipher.encrypt(message.encode()).decode()
    with db() as con:
        request = authorized_support_request(con, request_id, user)
        image_path, attachment_name = await save_private_attachment(image)
        read_student = created_at if user["role"] == "student" else None
        read_lecturer = created_at if user["role"] == "lecturer" else None
        message_id = con.execute(
            "INSERT INTO support_messages(request_id,sender_id,sender_role,encrypted_message,image_path,attachment_name,created_at,read_at_student,read_at_lecturer) VALUES(?,?,?,?,?,?,?,?,?)",
            (request_id, user["id"], user["role"], encrypted, image_path, attachment_name, created_at, read_student, read_lecturer),
        ).lastrowid
        con.execute("UPDATE support_requests SET status=? WHERE id=?", ("Replied" if user["role"] == "lecturer" else "Open", request_id))
        if user["role"] == "lecturer":
            # Keep the original reply table populated for clients using the legacy API.
            legacy_id = con.execute("INSERT INTO lecturer_responses(request_id,lecturer_id,encrypted_response,image_path,attachment_name,created_at) VALUES(?,?,?,?,?,?)", (request_id, user["id"], encrypted, image_path, attachment_name, created_at)).lastrowid
            con.execute("UPDATE support_messages SET legacy_source='lecturer_response',legacy_source_id=? WHERE id=?", (legacy_id, message_id))
        action = "lecturer_replied" if user["role"] == "lecturer" else "student_message_sent"
        con.execute("INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)", (user["id"], action, f"Conversation {request_id}, message {message_id}", created_at))
        row = con.execute("SELECT m.*,u.name AS sender_name FROM support_messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?", (message_id,)).fetchone()
        return support_message_data(row)


@app.get("/api/v1/support/{request_id}/messages")
def support_messages(request_id: int, user=Depends(current_user)):
    with db() as con:
        authorized_support_request(con, request_id, user)
        rows = con.execute("SELECT m.*,u.name AS sender_name FROM support_messages m JOIN users u ON u.id=m.sender_id WHERE m.request_id=? ORDER BY m.created_at ASC,m.id ASC", (request_id,)).fetchall()
        return [support_message_data(row) for row in rows]


@app.post("/api/v1/support/{request_id}/messages")
async def send_support_message(request_id: int, message: str = Form(...), image: UploadFile | None = File(None), user=Depends(current_user)):
    return await add_support_message(request_id, message, image, user)


@app.post("/api/v1/support/{request_id}/read")
def mark_support_messages_read(request_id: int, user=Depends(current_user)):
    with db() as con:
        authorized_support_request(con, request_id, user)
        now = utcnow()
        if user["role"] == "student":
            con.execute("UPDATE support_messages SET read_at_student=? WHERE request_id=? AND sender_role='lecturer' AND read_at_student IS NULL", (now, request_id))
        else:
            con.execute("UPDATE support_messages SET read_at_lecturer=? WHERE request_id=? AND sender_role='student' AND read_at_lecturer IS NULL", (now, request_id))
    return {"status": "read"}


def remove_private_attachments(paths: list[str | None]):
    upload_root = UPLOAD_DIR.resolve()
    for stored_path in set(paths):
        if not stored_path:
            continue
        try:
            path = Path(stored_path).resolve()
            path.relative_to(upload_root)
            path.unlink(missing_ok=True)
        except (OSError, ValueError):
            continue


@app.delete("/api/v1/support/{request_id}")
def delete_support_conversation(request_id: int, user=Depends(current_user)):
    with db() as con:
        authorized_support_request(con, request_id, user)
        attachment_rows = con.execute(
            "SELECT image_path FROM support_requests WHERE id=? UNION SELECT image_path FROM lecturer_responses WHERE request_id=? UNION SELECT image_path FROM support_messages WHERE request_id=?",
            (request_id, request_id, request_id),
        ).fetchall()
        attachment_paths = [row["image_path"] for row in attachment_rows]
        con.execute("DELETE FROM support_messages WHERE request_id=?", (request_id,))
        con.execute("DELETE FROM lecturer_responses WHERE request_id=?", (request_id,))
        con.execute("DELETE FROM support_requests WHERE id=?", (request_id,))
        con.execute(
            "INSERT INTO audit_logs(actor_id,action,detail,created_at) VALUES(?,?,?,?)",
            (user["id"], "support_conversation_deleted", f"Conversation {request_id} deleted by {user['role']}", utcnow()),
        )
    remove_private_attachments(attachment_paths)
    return {"status": "deleted"}


@app.get("/api/v1/student/requests")
def student_requests(user=Depends(require_role("student"))):
    with db() as con:
        rows = con.execute("SELECT r.id,r.status,r.created_at,s.code,s.name,l.name AS lecturer_name,r.encrypted_message,r.image_path,r.attachment_name FROM support_requests r JOIN subjects s ON s.id=r.subject_id JOIN users l ON l.id=r.lecturer_id WHERE r.student_id=? ORDER BY r.created_at DESC", (user["id"],)).fetchall()
        results = []
        for row in rows:
            data = dict(row)
            data["message"] = cipher.decrypt(data.pop("encrypted_message").encode()).decode()
            reply = thread_last_message(con, row["id"], "lecturer")
            data["response"] = cipher.decrypt(reply["encrypted_message"].encode()).decode() if reply else None
            data["responded_at"] = reply["created_at"] if reply else None
            data.update(thread_summary(con, row["id"], "student"))
            data["image_url"] = f"/api/v1/support/{data['id']}/image" if data.get("image_path") else None
            data["attachment_type"] = Path(data["image_path"]).suffix.lower().lstrip(".") if data.get("image_path") else None
            data["attachment_name"] = data.get("attachment_name")
            data.pop("image_path",None)
            reply_data = dict(reply) if reply else {}
            data["response_image_url"] = f"/api/v1/support/{data['id']}/response-image" if reply_data.get("image_path") else None
            data["response_attachment_type"] = Path(reply_data["image_path"]).suffix.lower().lstrip(".") if reply_data.get("image_path") else None
            data["response_attachment_name"] = reply_data.get("attachment_name")
            results.append(data)
    return results


@app.get("/api/v1/lecturer/requests")
def lecturer_requests(user=Depends(require_role("lecturer"))):
    with db() as con:
        rows = con.execute("SELECT r.id,r.status,r.created_at,r.encrypted_message,r.image_path,r.attachment_name,u.name AS student_name,s.code,s.name AS subject_name,r.subject_id FROM support_requests r JOIN users u ON u.id=r.student_id JOIN subjects s ON s.id=r.subject_id JOIN lecturer_subjects ls ON ls.subject_id=r.subject_id AND ls.lecturer_id=r.lecturer_id WHERE r.lecturer_id=? ORDER BY r.created_at DESC", (user["id"],)).fetchall()
        results = []
        for row in rows:
            data = dict(row)
            data["message"] = cipher.decrypt(data.pop("encrypted_message").encode()).decode()
            reply = thread_last_message(con, row["id"], "lecturer")
            data["response"] = cipher.decrypt(reply["encrypted_message"].encode()).decode() if reply else None
            data["responded_at"] = reply["created_at"] if reply else None
            data.update(thread_summary(con, row["id"], "lecturer"))
            data["image_url"] = f"/api/v1/support/{data['id']}/image" if data.get("image_path") else None
            data["attachment_type"] = Path(data["image_path"]).suffix.lower().lstrip(".") if data.get("image_path") else None
            data["attachment_name"] = data.get("attachment_name")
            data.pop("image_path",None)
            reply_data = dict(reply) if reply else {}
            data["response_image_url"] = f"/api/v1/support/{data['id']}/response-image" if reply_data.get("image_path") else None
            data["response_attachment_type"] = Path(reply_data["image_path"]).suffix.lower().lstrip(".") if reply_data.get("image_path") else None
            data["response_attachment_name"] = reply_data.get("attachment_name")
            results.append(data)
    return results


@app.post("/api/v1/lecturer/respond")
async def lecturer_respond(request_id: int = Form(...), message: str = Form(...), image: UploadFile | None = File(None), user=Depends(require_role("lecturer"))):
    await add_support_message(request_id, message, image, user)
    return {"status": "Replied", "message": "Your reply was delivered privately to the student."}


def private_image(path, media_type, original_name=None):
    if not path or not Path(path).is_file(): raise HTTPException(status_code=404,detail="Image not found")
    try: data=cipher.decrypt(Path(path).read_bytes())
    except Exception: raise HTTPException(status_code=404,detail="Image not found")
    filename=re.sub(r"[^A-Za-z0-9._ -]", "_", original_name or Path(path).name)[:180] or "attachment"
    return Response(data,media_type=media_type,headers={"Cache-Control":"private, no-store","Content-Disposition":f'inline; filename="{filename}"'})


def attachment_media_type(path):
    if not path: raise HTTPException(status_code=404,detail="Attachment not found")
    ext=Path(path).suffix.lower()
    return {".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp",".gif":"image/gif",".pdf":"application/pdf"}.get(ext,"application/octet-stream")


@app.get("/api/v1/support/{request_id}/image")
def support_image(request_id: int,user=Depends(current_user)):
    with db() as con:
        row=con.execute("SELECT r.image_path,r.attachment_name,r.student_id,r.lecturer_id,r.subject_id FROM support_requests r WHERE r.id=?",(request_id,)).fetchone()
        allowed= row and (user["id"]==row["student_id"] or (user["role"]=="lecturer" and user["id"]==row["lecturer_id"] and con.execute("SELECT 1 FROM lecturer_subjects WHERE lecturer_id=? AND subject_id=?",(user["id"],row["subject_id"])).fetchone()))
        if not allowed: raise HTTPException(status_code=404,detail="Image not found")
        path=row["image_path"]; filename=row["attachment_name"]
    return private_image(path,attachment_media_type(path),filename)


@app.get("/api/v1/support/{request_id}/response-image")
def response_image(request_id: int,user=Depends(current_user)):
    with db() as con:
        row=con.execute("SELECT r.student_id,r.lecturer_id,r.subject_id,lr.image_path,lr.attachment_name FROM support_requests r JOIN lecturer_responses lr ON lr.request_id=r.id WHERE r.id=? ORDER BY lr.created_at DESC LIMIT 1",(request_id,)).fetchone()
        allowed=row and (user["id"]==row["student_id"] or (user["role"]=="lecturer" and user["id"]==row["lecturer_id"] and con.execute("SELECT 1 FROM lecturer_subjects WHERE lecturer_id=? AND subject_id=?",(user["id"],row["subject_id"])).fetchone()))
        if not allowed: raise HTTPException(status_code=404,detail="Image not found")
        path=row["image_path"]; filename=row["attachment_name"]
    return private_image(path,attachment_media_type(path),filename)


@app.get("/api/v1/support/{request_id}/messages/{message_id}/image")
def support_message_image(request_id: int, message_id: int, user=Depends(current_user)):
    with db() as con:
        authorized_support_request(con, request_id, user)
        row = con.execute("SELECT image_path,attachment_name FROM support_messages WHERE id=? AND request_id=?", (message_id, request_id)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")
        path=row["image_path"]; filename=row["attachment_name"]
    return private_image(path, attachment_media_type(path), filename)


@app.get("/api/v1/subjects")
def public_subjects(user=Depends(current_user)):
    with db() as con:
        if user["role"] == "lecturer":
            rows = con.execute("SELECT s.id,s.code,s.name FROM subjects s JOIN lecturer_subjects ls ON ls.subject_id=s.id WHERE ls.lecturer_id=? ORDER BY CASE s.code WHEN 'TTLA' THEN 1 WHEN 'DDCO' THEN 2 WHEN 'DS' THEN 3 WHEN 'OOPJ' THEN 4 WHEN 'DMS' THEN 5 WHEN 'UHV' THEN 6 WHEN 'AEC3' THEN 7 WHEN 'DSL' THEN 8 WHEN 'OOPJL' THEN 9 END", (user["id"],)).fetchall()
        else:
            rows = con.execute("SELECT id,code,name FROM subjects ORDER BY CASE code WHEN 'TTLA' THEN 1 WHEN 'DDCO' THEN 2 WHEN 'DS' THEN 3 WHEN 'OOPJ' THEN 4 WHEN 'DMS' THEN 5 WHEN 'UHV' THEN 6 WHEN 'AEC3' THEN 7 WHEN 'DSL' THEN 8 WHEN 'OOPJL' THEN 9 END").fetchall()
    return [dict(row) for row in rows]


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


@app.get("/logo.png", include_in_schema=False)
def institution_logo():
    return FileResponse(ROOT / "public" / "logo.png", media_type="image/png")


app.mount("/static", StaticFiles(directory=ROOT / "web"), name="static")
