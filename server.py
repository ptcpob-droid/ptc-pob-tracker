import csv
import os
import io
import json
import base64
import hashlib
import secrets
import functools
import re
import tempfile
from datetime import datetime, date, timedelta, timezone

from flask import Flask, request, jsonify, send_from_directory, send_file
import qrcode
import pyotp
from io import BytesIO

# ============================================================
# CONFIG
# ============================================================

app = Flask(__name__, static_folder='public', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

DATABASE_URL = os.environ.get('DATABASE_URL', '')
USE_POSTGRES = DATABASE_URL.startswith('postgres')
ADMIN_DEFAULT_PIN = os.environ.get('ADMIN_PIN', '1234')
IS_PRODUCTION = os.environ.get('RENDER', '') or os.environ.get('PRODUCTION', '')
# No account lockout or disabling: login always allowed on correct credentials

ROSTER_CSV = os.path.join(os.path.dirname(__file__), 'adnoc_workforce_roste.csv')

ROLE_HIERARCHY = {
    'executive': 50,
    'admin': 40,
    'manager': 35,
    'project_manager': 30,
    'focal_point': 25,
    'supervisor': 20,
    'scanner': 18,
    'viewer': 10
}

# Hierarchy: Division -> Area -> Project -> Personnel
# 4 divisions; each has areas; each area has projects; headcount per project
DIVISIONS = [
    ('P&C BAB/NEB', ['BAB', 'NEB', 'BAB MP']),
    ('P&C GTG', ['GAS', 'TPO', 'GAS/TPO', 'WEP', 'FUJ', 'GAS (ASAB)', 'GAS (BAB)', 'IPS', 'JD', 'MPS']),
    ('P&C SE', ['Asab/Sahil', 'SQM', 'SHAH', 'QW', 'MN']),
    ('P&C BUHASA', ['Buhasa', 'BUIFDP (Buhasa)', 'BUHASA MP']),
]

AREA_ALIASES = {
    'P&C SHAH': 'SHAH', 'P&C (SHAH)': 'SHAH', 'Shah': 'SHAH', 'shah': 'SHAH',
    'P&C Qusahwira': 'QW', 'P&C (Qusahwira/Mender QW/MN)': 'QW', 'Qusahwira': 'QW',
    'P&C Mender': 'MN', 'Mender': 'MN',
    'P&C (FUJ)': 'FUJ', 'P&C FUJ': 'FUJ', 'fuj': 'FUJ', 'Fuj': 'FUJ',
    'P&C (IPS)': 'IPS', '(IPS)': 'IPS',
    'P&C (JD)': 'JD', '(JD)': 'JD',
    'P&C (MPS)': 'MPS', '(MPS)': 'MPS',
    'P&C GAS(BAB)': 'GAS (BAB)', 'GAS(BAB)': 'GAS (BAB)',
    'P&C GAS(ASAB)': 'GAS (ASAB)', 'GAS(ASAB)': 'GAS (ASAB)',
    'P&C Asab': 'GAS (ASAB)',
    'P&C Sahil': 'SHAH',
    'P&C Buhasa': 'BUHASA', 'Buhasa': 'BUHASA', 'buhasa': 'BUHASA',
    'Buhasa MP': 'BUHASA MP', 'P&C Buhasa MP': 'BUHASA MP',
    'BAB MP': 'BAB MP',
}

COMMON_PINS = {'0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
               '1234', '4321', '1122', '1212', '0123', '9876', '5678', '8765'}

LOGIN_ATTEMPTS = {}
LOGIN_WINDOW = 60
LOGIN_MAX_PER_IP = 20

# ============================================================
# HTTPS REDIRECT (when behind proxy e.g. Render)
# ============================================================

@app.before_request
def redirect_http_to_https():
    """Redirect HTTP to HTTPS when the app is behind a proxy that sets X-Forwarded-Proto."""
    if not request.is_secure and request.headers.get('X-Forwarded-Proto') == 'http':
        from flask import redirect
        return redirect(request.url.replace('http://', 'https://', 1), code=301)


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://unpkg.com; "
        "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response

# ============================================================
# DATABASE ABSTRACTION (SQLite local / PostgreSQL cloud)
# ============================================================

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras

    def get_db():
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn

    def _translate_sql(sql):
        sql = sql.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')
        sql = sql.replace('TIMESTAMP DEFAULT CURRENT_TIMESTAMP', "TIMESTAMP DEFAULT NOW()")
        # Order matters: replace longer patterns first
        sql = sql.replace("datetime('now', '+24 hours')", "NOW() + INTERVAL '24 hours'")
        sql = sql.replace("datetime('now', '+5 minutes')", "NOW() + INTERVAL '5 minutes'")
        sql = sql.replace(
            "datetime('now', '+' || ? || ' minutes')",
            "(NOW() + (%s || ' minutes')::interval)"
        )
        sql = sql.replace("datetime('now')", "NOW()")
        sql = sql.replace('?', '%s')
        sql = re.sub(r'INSERT OR (?:REPLACE|IGNORE) INTO', 'INSERT INTO', sql)
        return sql

    def db_execute(conn, sql, params=None):
        sql = _translate_sql(sql)
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, params or [])
        return cur

    def db_fetchone(conn, sql, params=None):
        cur = db_execute(conn, sql, params)
        return cur.fetchone()

    def db_fetchall(conn, sql, params=None):
        cur = db_execute(conn, sql, params)
        return cur.fetchall()

else:
    import sqlite3

    def get_db():
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'pob.db'))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def db_execute(conn, sql, params=None):
        return conn.execute(sql, params or [])

    def db_fetchone(conn, sql, params=None):
        row = conn.execute(sql, params or []).fetchone()
        return dict(row) if row else None

    def db_fetchall(conn, sql, params=None):
        return [dict(r) for r in conn.execute(sql, params or []).fetchall()]


def hash_pin(pin):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"


def verify_pin(pin, stored):
    if ':' not in stored:
        return hashlib.sha256(pin.encode()).hexdigest() == stored
    salt, h = stored.split(':', 1)
    return hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 100000).hex() == h


def is_weak_pin(pin):
    if pin in COMMON_PINS:
        return True
    if len(set(pin)) == 1:
        return True
    digits = [int(d) for d in pin]
    if all(digits[i+1] - digits[i] == 1 for i in range(len(digits)-1)):
        return True
    if all(digits[i] - digits[i+1] == 1 for i in range(len(digits)-1)):
        return True
    return False


# ============================================================
# DATABASE INIT
# ============================================================

def init_db():
    conn = get_db()
    try:
        tables = [
            '''CREATE TABLE IF NOT EXISTS divisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''',
            '''CREATE TABLE IF NOT EXISTS areas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                division_id INTEGER NOT NULL REFERENCES divisions(id),
                name TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(division_id, name)
            )''',
            '''CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                area_id INTEGER REFERENCES areas(id),
                name TEXT NOT NULL,
                description TEXT,
                agreement_no TEXT,
                contract_number TEXT,
                contractor_company TEXT,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(area_id, name)
            )''',
            '''CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                project_id INTEGER NOT NULL REFERENCES projects(id),
                description TEXT,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(name, project_id)
            )''',
            '''CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                srl TEXT, agreement_no TEXT, name TEXT NOT NULL, nationality TEXT,
                dob TEXT, designation TEXT, work_location TEXT, camp_name TEXT,
                employee_no TEXT NOT NULL, qualification TEXT, date_joining TEXT,
                date_deployment TEXT, medical_date TEXT, discipline TEXT,
                subcontractor TEXT, remarks TEXT,
                project_id INTEGER NOT NULL REFERENCES projects(id),
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(employee_no, project_id)
            )''',
            '''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                pin_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'supervisor',
                active INTEGER DEFAULT 1,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                must_change_pin INTEGER DEFAULT 0,
                totp_secret TEXT,
                totp_enabled INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )''',
            '''CREATE TABLE IF NOT EXISTS user_project_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                project_id INTEGER NOT NULL REFERENCES projects(id),
                UNIQUE(user_id, project_id)
            )''',
            '''CREATE TABLE IF NOT EXISTS user_division_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                division_id INTEGER NOT NULL REFERENCES divisions(id),
                UNIQUE(user_id, division_id)
            )''',
            '''CREATE TABLE IF NOT EXISTS auth_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                token TEXT UNIQUE NOT NULL,
                device_info TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )''',
            '''CREATE TABLE IF NOT EXISTS pending_2fa (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                pending_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )''',
            '''CREATE TABLE IF NOT EXISTS download_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL
            )''',
            '''CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                detail TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''',
            '''CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL REFERENCES employees(id),
                employee_no TEXT NOT NULL,
                project_id INTEGER NOT NULL REFERENCES projects(id),
                site_id INTEGER NOT NULL REFERENCES sites(id),
                scan_date TEXT NOT NULL,
                session TEXT NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                supervisor_id INTEGER REFERENCES users(id),
                supervisor_name TEXT,
                latitude REAL, longitude REAL,
                UNIQUE(employee_no, project_id, scan_date, session)
            )'''
        ]

        for sql in tables:
            try:
                db_execute(conn, sql)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"  Table warning: {e}")

        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_att_date ON attendance(scan_date)',
            'CREATE INDEX IF NOT EXISTS idx_att_project ON attendance(project_id)',
            'CREATE INDEX IF NOT EXISTS idx_att_site ON attendance(site_id)',
            'CREATE INDEX IF NOT EXISTS idx_emp_no ON employees(employee_no)',
            'CREATE INDEX IF NOT EXISTS idx_emp_project ON employees(project_id)',
            'CREATE INDEX IF NOT EXISTS idx_projects_area ON projects(area_id)',
            'CREATE INDEX IF NOT EXISTS idx_areas_division ON areas(division_id)',
            'CREATE INDEX IF NOT EXISTS idx_token ON auth_tokens(token)',
            'CREATE INDEX IF NOT EXISTS idx_upa_user ON user_project_access(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_uda_user ON user_division_access(user_id)',
        ]
        for sql in indexes:
            try:
                db_execute(conn, sql)
                conn.commit()
            except Exception:
                conn.rollback()

        # Add new columns if missing (migrations)
        for alter in [
            'ALTER TABLE projects ADD COLUMN region TEXT',
            'ALTER TABLE projects ADD COLUMN area_id INTEGER REFERENCES areas(id)',
            'ALTER TABLE projects ADD COLUMN contract_number TEXT',
            'ALTER TABLE projects ADD COLUMN contractor_company TEXT',
            'ALTER TABLE users ADD COLUMN email TEXT',
            'ALTER TABLE users ADD COLUMN designation TEXT',
            'ALTER TABLE attendance ADD COLUMN scanner_email TEXT',
            'ALTER TABLE attendance ADD COLUMN scanner_designation TEXT',
        ]:
            try:
                db_execute(conn, alter)
                conn.commit()
            except Exception:
                conn.rollback()

        # Seed divisions and areas (Division -> Area -> Project)
        for div_name, area_names in DIVISIONS:
            row = db_fetchone(conn, 'SELECT id FROM divisions WHERE name = ?', (div_name,))
            if not row:
                db_execute(conn, 'INSERT INTO divisions (name, active) VALUES (?, 1)', (div_name,))
                conn.commit()
                row = db_fetchone(conn, 'SELECT id FROM divisions WHERE name = ?', (div_name,))
            div_id = row['id'] if isinstance(row, dict) else row[0]
            for area_name in area_names:
                ar = db_fetchone(conn, 'SELECT id FROM areas WHERE division_id = ? AND name = ?', (div_id, area_name))
                if not ar:
                    db_execute(conn, 'INSERT INTO areas (division_id, name, active) VALUES (?, ?, 1)', (div_id, area_name))
                    conn.commit()
                    ar = db_fetchone(conn, 'SELECT id FROM areas WHERE division_id = ? AND name = ?', (div_id, area_name))
                area_id = ar['id'] if isinstance(ar, dict) else ar[0]
        # Normalize old area names to canonical names
        for old_name, canonical in AREA_ALIASES.items():
            try:
                existing = db_fetchone(conn, 'SELECT id FROM areas WHERE name = ?', (old_name,))
                if existing:
                    canon_exists = db_fetchone(conn, 'SELECT id FROM areas WHERE name = ? AND id != ?',
                                               (canonical, existing['id'] if isinstance(existing, dict) else existing[0]))
                    if canon_exists:
                        old_id = existing['id'] if isinstance(existing, dict) else existing[0]
                        canon_id = canon_exists['id'] if isinstance(canon_exists, dict) else canon_exists[0]
                        db_execute(conn, 'UPDATE projects SET area_id = ? WHERE area_id = ?', (canon_id, old_id))
                        db_execute(conn, 'UPDATE user_division_access SET division_id = division_id WHERE 1=0')
                        db_execute(conn, 'DELETE FROM areas WHERE id = ?', (old_id,))
                    else:
                        db_execute(conn, 'UPDATE areas SET name = ? WHERE id = ?',
                                   (canonical, existing['id'] if isinstance(existing, dict) else existing[0]))
                    conn.commit()
            except Exception:
                conn.rollback()

        # Backfill area_id for existing projects that have region set (legacy)
        try:
            for div_name, area_names in DIVISIONS:
                div_row = db_fetchone(conn, 'SELECT id FROM divisions WHERE name = ?', (div_name,))
                if not div_row:
                    continue
                div_id = div_row['id'] if isinstance(div_row, dict) else div_row[0]
                for area_name in area_names:
                    ar = db_fetchone(conn, 'SELECT id FROM areas WHERE division_id = ? AND name = ?', (div_id, area_name))
                    if not ar:
                        continue
                    area_id = ar['id'] if isinstance(ar, dict) else ar[0]
                    db_execute(conn, 'UPDATE projects SET area_id = ? WHERE (area_id IS NULL OR area_id = 0) AND (name = ? OR region = ?)', (area_id, area_name, div_name))
                    conn.commit()
        except Exception:
            conn.rollback()

        # Seed projects from contractors CSV (if available)
        csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'contractors.csv')
        if os.path.exists(csv_path):
            import csv
            try:
                with open(csv_path, 'r', encoding='utf-8-sig') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        proj_name = (row.get('Project Name') or '').strip()
                        contract_no = (row.get('Contract Number') or '').strip()
                        div_name = (row.get('Division') or '').strip()
                        area_name = (row.get('Area') or '').strip()
                        contractor = (row.get('Name of Contractors') or '').strip()
                        if not proj_name or not div_name or not area_name:
                            continue
                        div_row = db_fetchone(conn, 'SELECT id FROM divisions WHERE name = ?', (div_name,))
                        if not div_row:
                            continue
                        div_id = div_row['id'] if isinstance(div_row, dict) else div_row[0]
                        ar = db_fetchone(conn, 'SELECT id FROM areas WHERE division_id = ? AND name = ?', (div_id, area_name))
                        if not ar:
                            continue
                        area_id = ar['id'] if isinstance(ar, dict) else ar[0]
                        existing = db_fetchone(conn, 'SELECT id FROM projects WHERE area_id = ? AND name = ?', (area_id, proj_name))
                        if existing:
                            pid = existing['id'] if isinstance(existing, dict) else existing[0]
                            db_execute(conn, 'UPDATE projects SET contract_number = ?, contractor_company = ? WHERE id = ?',
                                       (contract_no, contractor, pid))
                        else:
                            try:
                                db_execute(conn, '''INSERT INTO projects (area_id, name, contract_number, contractor_company, active)
                                    VALUES (?, ?, ?, ?, 1)''', (area_id, proj_name, contract_no, contractor))
                            except Exception:
                                conn.rollback()
                                continue
                        conn.commit()
                print(f'  Seeded projects from contractors CSV')
            except Exception as e:
                print(f'  CSV seed warning: {e}')
                conn.rollback()

        user = db_fetchone(conn, 'SELECT COUNT(*) as c FROM users')
        count = user['c'] if isinstance(user, dict) else user[0]
        if count == 0:
            totp_secret = pyotp.random_base32()
            db_execute(conn, '''
                INSERT INTO users (username, display_name, pin_hash, role, must_change_pin, totp_secret, totp_enabled)
                VALUES (?, ?, ?, 'executive', 0, ?, 1)
            ''', ('admin', 'Administrator', hash_pin('0000'), totp_secret))
            conn.commit()
            uri = pyotp.TOTP(totp_secret).provisioning_uri(name='admin', issuer_name='PTC POB Tracker')
            print('  Default admin (2FA only): username=admin')
            print(f'  Add this secret to your authenticator app: {totp_secret}')
            print(f'  Or scan QR for: {uri[:60]}...')
        else:
            # Non-scanner users without 2FA get a secret so admin login works
            rows = db_fetchall(conn, "SELECT id, username, role FROM users WHERE (totp_secret IS NULL OR totp_enabled = 0) AND role != 'scanner'")
            for row in rows:
                uid = row['id'] if isinstance(row, dict) else row[0]
                uname = (row.get('username') or row[1]) if isinstance(row, dict) else row[1]
                new_secret = pyotp.random_base32()
                db_execute(conn, 'UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?', (new_secret, uid))
                conn.commit()
                print(f'  2FA set for user {uname}. Add to authenticator: {new_secret}')
    finally:
        conn.close()


# Run init_db at import time so gunicorn/production picks it up
# If it fails (e.g. Postgres transaction state), app still starts so / and /reset-admin work
print("Initializing database...")
try:
    init_db()
except Exception as e:
    print(f"  init_db warning: {e}")
    import traceback
    traceback.print_exc()


# ============================================================
# AUTH
# ============================================================

def now_utc():
    return datetime.now(timezone.utc)


def cleanup_expired(conn):
    """Purge expired tokens and 2FA sessions."""
    try:
        db_execute(conn, "DELETE FROM auth_tokens WHERE expires_at < datetime('now')")
        db_execute(conn, "DELETE FROM pending_2fa WHERE expires_at < datetime('now')")
        db_execute(conn, "DELETE FROM download_tokens WHERE expires_at < datetime('now')")
    except Exception:
        pass


def get_current_user():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return None

    conn = get_db()
    try:
        if USE_POSTGRES:
            row = db_fetchone(conn, '''
                SELECT u.* FROM users u
                JOIN auth_tokens t ON t.user_id = u.id
                WHERE t.token = ? AND t.expires_at > NOW()
            ''', (token,))
        else:
            row = db_fetchone(conn, '''
                SELECT u.* FROM users u
                JOIN auth_tokens t ON t.user_id = u.id
                WHERE t.token = ? AND t.expires_at > datetime('now')
            ''', (token,))
        return row
    finally:
        conn.close()


def get_user_projects(conn, user_id, role):
    """Site isolation: each area’s data is separate. Executive and Manager see all; Scanner/Focal Point see only their assigned areas."""
    if role in ('executive', 'admin', 'manager'):
        return None  # see all
    if role == 'focal_point':
        rows = db_fetchall(conn, 'SELECT division_id FROM user_division_access WHERE user_id = ?', (user_id,))
        if not rows:
            return []
        div_ids = [r['division_id'] for r in rows]
        placeholders = ','.join(['?' for _ in div_ids])
        proj_rows = db_fetchall(conn, f'''SELECT p.id FROM projects p
            JOIN areas a ON a.id = p.area_id
            WHERE a.division_id IN ({placeholders}) AND (p.active = 1 OR p.active IS NULL)''', div_ids)
        return [r['id'] for r in proj_rows]
    rows = db_fetchall(conn, 'SELECT project_id FROM user_project_access WHERE user_id = ?', (user_id,))
    return [r['project_id'] for r in rows]


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required', 'auth_required': True}), 401
        request.user = user
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required', 'auth_required': True}), 401
            if user['role'] not in roles:
                return jsonify({'error': f'Requires role: {", ".join(roles)}'}), 403
            request.user = user
            return f(*args, **kwargs)
        return decorated
    return decorator


def audit(user_id, action, detail=''):
    try:
        conn = get_db()
        try:
            db_execute(conn, 'INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)',
                       (user_id, action, detail, request.remote_addr))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass


def check_ip_rate_limit(ip):
    now = datetime.now().timestamp()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < LOGIN_WINDOW]
    if len(LOGIN_ATTEMPTS[ip]) >= LOGIN_MAX_PER_IP:
        return False
    LOGIN_ATTEMPTS[ip].append(now)
    return True


def apply_project_filter(conn, query, params, user, table_alias='a'):
    allowed = get_user_projects(conn, user['id'], user['role'])
    if allowed is not None:
        if not allowed:
            query += f' AND {table_alias}.project_id = -1'
        elif len(allowed) == 1:
            query += f' AND {table_alias}.project_id = ?'
            params.append(allowed[0])
        else:
            placeholders = ','.join(['?' for _ in allowed])
            query += f' AND {table_alias}.project_id IN ({placeholders})'
            params.extend(allowed)
    return query, params


def check_project_access(conn, user, project_id):
    allowed = get_user_projects(conn, user['id'], user['role'])
    if allowed is None:
        return True
    return int(project_id) in allowed


def get_user_divisions(conn, user_id, role):
    """Division IDs the user can access. Focal point: from user_division_access; others: all (None)."""
    if role != 'focal_point':
        return None
    rows = db_fetchall(conn, 'SELECT division_id FROM user_division_access WHERE user_id = ?', (user_id,))
    return [r['division_id'] for r in rows]


# ============================================================
# AUTH ROUTES
# ============================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Two login paths: scanner (username+PIN) and admin (username+2FA)."""
    try:
        return _do_login()
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

def _do_login():
    if not check_ip_rate_limit(request.remote_addr):
        return jsonify({'success': False, 'message': 'Too many attempts. Wait 1 minute.'}), 429

    data = request.json or {}
    login_mode = (data.get('login_mode') or 'admin').strip()
    username = (data.get('username') or '').strip().lower()

    if not username:
        return jsonify({'success': False, 'message': 'Username required'}), 400

    conn = get_db()
    try:
        cleanup_expired(conn)
        user = db_fetchone(conn, 'SELECT * FROM users WHERE username = ?', (username,))
        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        if login_mode == 'scanner':
            pin = (data.get('pin') or '').strip()
            if not pin:
                return jsonify({'success': False, 'message': 'PIN required'}), 400
            if user['role'] not in ('scanner',):
                return jsonify({'success': False, 'message': 'Use Admin sign-in for this account'}), 403
            if not verify_pin(pin, user['pin_hash']):
                audit(user['id'], 'login_failed', 'bad PIN')
                return jsonify({'success': False, 'message': 'Invalid PIN'}), 401
        else:
            totp_code = (data.get('totp_code') or '').strip()
            if not totp_code:
                return jsonify({'success': False, 'message': '2FA code required'}), 400
            if len(totp_code) != 6 or not totp_code.isdigit():
                return jsonify({'success': False, 'message': 'Enter the 6-digit code from your authenticator app'}), 400
            if user['role'] == 'scanner':
                return jsonify({'success': False, 'message': 'Use Scanner sign-in for this account'}), 403
            secret = (user.get('totp_secret') or '').strip()
            enabled = user.get('totp_enabled')
            if not secret or enabled in (None, 0, False, '0'):
                return jsonify({'success': False, 'message': '2FA not set up. Contact your administrator.'}), 403
            try:
                totp = pyotp.TOTP(secret)
                if not totp.verify(totp_code, valid_window=2):
                    audit(user['id'], '2fa_failed', request.remote_addr)
                    return jsonify({'success': False, 'message': 'Invalid 2FA code. Try the newest code from your app.'}), 401
            except Exception:
                return jsonify({'success': False, 'message': '2FA verification error. Contact support.'}), 500

        token = secrets.token_urlsafe(48)
        device = request.headers.get('User-Agent', '')[:200]
        db_execute(conn, "INSERT INTO auth_tokens (user_id, token, device_info, expires_at) VALUES (?, ?, ?, datetime('now', '+24 hours'))",
                   (user['id'], token, device))
        db_execute(conn, "UPDATE users SET last_login = datetime('now') WHERE id = ?", (user['id'],))
        conn.commit()

        allowed = get_user_projects(conn, user['id'], user['role'])
        allowed_divs = get_user_divisions(conn, user['id'], user['role'])
        audit(user['id'], 'login', f'{login_mode} | {device[:60]}')

        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user['id'], 'username': user['username'],
                'display_name': user['display_name'], 'role': user['role'],
                'email': user.get('email') or '', 'designation': user.get('designation') or '',
                'must_change_pin': False,
                'totp_enabled': bool(user.get('totp_enabled')),
                'allowed_projects': allowed,
                'allowed_divisions': allowed_divs
            }
        })
    finally:
        conn.close()


@app.route('/api/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    pending_token = data.get('pending_token', '').strip()
    totp_code = data.get('totp_code', '').strip()

    if not pending_token or not totp_code:
        return jsonify({'success': False, 'message': '2FA code required'}), 400

    conn = get_db()
    try:
        if USE_POSTGRES:
            pending = db_fetchone(conn, '''
                SELECT p.user_id, p.pending_token, u.* FROM pending_2fa p
                JOIN users u ON u.id = p.user_id WHERE p.pending_token = ? AND p.expires_at > NOW()
            ''', (pending_token,))
        else:
            pending = db_fetchone(conn, '''
                SELECT p.user_id, p.pending_token, u.* FROM pending_2fa p
                JOIN users u ON u.id = p.user_id WHERE p.pending_token = ? AND p.expires_at > datetime('now')
            ''', (pending_token,))

        if not pending:
            return jsonify({'success': False, 'message': 'Session expired, login again'}), 401

        totp = pyotp.TOTP(pending['totp_secret'])
        if not totp.verify(totp_code, valid_window=1):
            db_execute(conn, 'DELETE FROM pending_2fa WHERE pending_token = ?', (pending_token,))
            conn.commit()
            audit(pending['user_id'], '2fa_failed')
            return jsonify({'success': False, 'message': 'Invalid code. Login again.'}), 401

        db_execute(conn, 'DELETE FROM pending_2fa WHERE user_id = ?', (pending['user_id'],))
        token = secrets.token_urlsafe(48)
        device = request.headers.get('User-Agent', '')[:200]
        db_execute(conn, "INSERT INTO auth_tokens (user_id, token, device_info, expires_at) VALUES (?, ?, ?, datetime('now', '+24 hours'))",
                   (pending['user_id'], token, device))
        db_execute(conn, "UPDATE users SET last_login = datetime('now') WHERE id = ?", (pending['user_id'],))
        conn.commit()

        allowed = get_user_projects(conn, pending['user_id'], pending['role'])
        allowed_divs = get_user_divisions(conn, pending['user_id'], pending['role'])
        audit(pending['user_id'], 'login_2fa')

        return jsonify({
            'success': True, 'token': token,
            'user': {
                'id': pending['user_id'], 'username': pending['username'],
                'display_name': pending['display_name'], 'role': pending['role'],
                'email': pending.get('email') or '', 'designation': pending.get('designation') or '',
                'must_change_pin': bool(pending.get('must_change_pin')),
                'totp_enabled': True,
                'allowed_projects': allowed,
                'allowed_divisions': allowed_divs
            }
        })
    finally:
        conn.close()


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    conn = get_db()
    try:
        db_execute(conn, 'DELETE FROM auth_tokens WHERE token = ?', (token,))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'logout')
    return jsonify({'success': True})


@app.route('/api/auth/change-pin', methods=['POST'])
@require_auth
def change_pin():
    data = request.json
    new_pin = data.get('new_pin', '').strip()
    current_pin = data.get('current_pin', '').strip()

    if not new_pin or len(new_pin) < 4 or len(new_pin) > 8 or not new_pin.isdigit():
        return jsonify({'success': False, 'message': 'PIN must be 4-8 digits'}), 400
    if is_weak_pin(new_pin):
        return jsonify({'success': False, 'message': 'PIN too simple. Avoid sequences and repeated digits.'}), 400

    conn = get_db()
    try:
        user = db_fetchone(conn, 'SELECT * FROM users WHERE id = ?', (request.user['id'],))
        if not user.get('must_change_pin') and not verify_pin(current_pin, user['pin_hash']):
            return jsonify({'success': False, 'message': 'Current PIN incorrect'}), 401

        db_execute(conn, 'UPDATE users SET pin_hash = ?, must_change_pin = 0 WHERE id = ?',
                   (hash_pin(new_pin), request.user['id']))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'pin_changed')
    return jsonify({'success': True, 'message': 'PIN updated'})


@app.route('/api/auth/me')
@require_auth
def auth_me():
    conn = get_db()
    try:
        allowed = get_user_projects(conn, request.user['id'], request.user['role'])
        allowed_divs = get_user_divisions(conn, request.user['id'], request.user['role'])
    finally:
        conn.close()
    return jsonify({
        'id': request.user['id'], 'username': request.user['username'],
        'display_name': request.user['display_name'], 'role': request.user['role'],
        'email': request.user.get('email') or '', 'designation': request.user.get('designation') or '',
        'must_change_pin': bool(request.user.get('must_change_pin')),
        'totp_enabled': bool(request.user.get('totp_enabled')),
        'allowed_projects': allowed,
        'allowed_divisions': allowed_divs
    })


# --- 2FA Setup ---

@app.route('/api/auth/2fa/setup', methods=['POST'])
@require_auth
def setup_2fa():
    conn = get_db()
    try:
        user = db_fetchone(conn, 'SELECT * FROM users WHERE id = ?', (request.user['id'],))
        if user.get('totp_enabled'):
            return jsonify({'success': False, 'message': '2FA already enabled'}), 400

        secret = pyotp.random_base32()
        db_execute(conn, 'UPDATE users SET totp_secret = ? WHERE id = ?', (secret, request.user['id']))
        conn.commit()
    finally:
        conn.close()

    uri = pyotp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name='PTC POB Tracker')
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=3)
    qr.add_data(uri)
    qr.make(fit=True)
    buf = BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buf, format='PNG')
    return jsonify({'success': True, 'secret': secret, 'qr_code': base64.b64encode(buf.getvalue()).decode(), 'uri': uri})


@app.route('/api/auth/2fa/confirm', methods=['POST'])
@require_auth
def confirm_2fa():
    totp_code = request.json.get('totp_code', '').strip()
    conn = get_db()
    try:
        user = db_fetchone(conn, 'SELECT * FROM users WHERE id = ?', (request.user['id'],))
        if not user.get('totp_secret'):
            return jsonify({'success': False, 'message': 'Run setup first'}), 400
        if not pyotp.TOTP(user['totp_secret']).verify(totp_code, valid_window=1):
            return jsonify({'success': False, 'message': 'Invalid code'}), 400
        db_execute(conn, 'UPDATE users SET totp_enabled = 1 WHERE id = ?', (request.user['id'],))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], '2fa_enabled')
    return jsonify({'success': True, 'message': '2FA enabled'})


@app.route('/api/auth/2fa/disable', methods=['POST'])
@require_auth
def disable_2fa():
    """Disable 2FA; requires current 2FA code (sign-in is 2FA only)."""
    data = request.json or {}
    totp_code = (data.get('totp_code') or data.get('pin') or '').strip()
    conn = get_db()
    try:
        user = db_fetchone(conn, 'SELECT * FROM users WHERE id = ?', (request.user['id'],))
        if not user.get('totp_secret'):
            return jsonify({'success': False, 'message': '2FA is not enabled'}), 400
        if not totp_code or len(totp_code) != 6:
            return jsonify({'success': False, 'message': 'Enter your current 6-digit 2FA code to disable'}), 400
        if not pyotp.TOTP(user['totp_secret']).verify(totp_code, valid_window=1):
            return jsonify({'success': False, 'message': 'Incorrect 2FA code'}), 401
        db_execute(conn, 'UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', (request.user['id'],))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], '2fa_disabled')
    return jsonify({'success': True, 'message': '2FA disabled'})


# ============================================================
# USER MANAGEMENT
# ============================================================

@app.route('/api/users')
@require_role('executive', 'admin')
def api_users():
    conn = get_db()
    try:
        rows = db_fetchall(conn, '''
            SELECT id, username, display_name, email, designation, role, active, must_change_pin,
                   failed_attempts, locked_until, totp_enabled, created_at, last_login
            FROM users ORDER BY role, display_name
        ''')
        for row in rows:
            access = db_fetchall(conn, '''
                SELECT p.id, p.name FROM user_project_access upa
                JOIN projects p ON p.id = upa.project_id WHERE upa.user_id = ?
            ''', (row['id'],))
            row['projects'] = access
            divs = db_fetchall(conn, '''
                SELECT d.id, d.name FROM user_division_access uda
                JOIN divisions d ON d.id = uda.division_id WHERE uda.user_id = ?
            ''', (row['id'],))
            row['divisions'] = divs
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/users', methods=['POST'])
@require_role('executive', 'admin')
def api_add_user():
    data = request.json
    username = data.get('username', '').strip().lower()
    display_name = data.get('display_name', '').strip()
    role = data.get('role', 'supervisor')
    pin = data.get('pin', '1234').strip() or '1234'
    project_ids = data.get('project_ids', [])
    division_ids = data.get('division_ids', [])

    if not username or not display_name:
        return jsonify({'success': False, 'message': 'Username and name required'}), 400
    if role not in ROLE_HIERARCHY:
        return jsonify({'success': False, 'message': f'Invalid role. Use: {", ".join(ROLE_HIERARCHY.keys())}'}), 400
    if request.user['role'] != 'executive' and role in ('executive', 'admin'):
        return jsonify({'success': False, 'message': 'Only executives can create admin/executive users'}), 403

    email = data.get('email', '').strip()
    designation = data.get('designation', '').strip()
    if role in ('scanner', 'focal_point'):
        if not email:
            return jsonify({'success': False, 'message': 'Email required for scanner/focal point'}), 400
        if not designation:
            return jsonify({'success': False, 'message': 'Designation required for scanner/focal point'}), 400
    if role == 'scanner' and not project_ids:
        return jsonify({'success': False, 'message': 'Assign at least one project for scanner'}), 400
    if role == 'focal_point' and not division_ids:
        return jsonify({'success': False, 'message': 'Assign at least one division for divisional focal point'}), 400

    needs_2fa = role != 'scanner'
    totp_secret = pyotp.random_base32() if needs_2fa else None
    conn = get_db()
    try:
        db_execute(conn, '''
            INSERT INTO users (username, display_name, email, designation, pin_hash, role, must_change_pin, totp_secret, totp_enabled)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
        ''', (username, display_name, email or None, designation or None, hash_pin(pin), role,
              totp_secret, 1 if needs_2fa else 0))
        conn.commit()

        user = db_fetchone(conn, 'SELECT id FROM users WHERE username = ?', (username,))
        if project_ids and role == 'scanner':
            for pid in project_ids:
                try:
                    db_execute(conn, 'INSERT INTO user_project_access (user_id, project_id) VALUES (?, ?)',
                               (user['id'], pid))
                except Exception:
                    pass
            conn.commit()
        if division_ids and role == 'focal_point':
            for did in division_ids:
                try:
                    db_execute(conn, 'INSERT INTO user_division_access (user_id, division_id) VALUES (?, ?)',
                               (user['id'], did))
                except Exception:
                    pass
            conn.commit()

        audit(request.user['id'], 'user_created', f'{username} ({role})')
        result = {'success': True}
        if needs_2fa:
            uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name='PTC POB Tracker')
            result['message'] = f'User {username} created. Give them the 2FA setup below to sign in.'
            result['totp_setup'] = {'secret': totp_secret, 'uri': uri}
        else:
            result['message'] = f'Scanner {username} created with PIN {pin}. Share the username and PIN with them.'
        return jsonify(result)
    except Exception as e:
        if 'UNIQUE' in str(e).upper() or 'unique' in str(e).lower():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        return jsonify({'success': False, 'message': str(e)}), 400
    finally:
        conn.close()


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@require_role('executive', 'admin')
def api_update_user(user_id):
    data = request.json
    conn = get_db()
    try:
        if 'role' in data and data['role'] in ROLE_HIERARCHY:
            db_execute(conn, 'UPDATE users SET role = ? WHERE id = ?', (data['role'], user_id))
        if 'display_name' in data:
            db_execute(conn, 'UPDATE users SET display_name = ? WHERE id = ?', (data['display_name'], user_id))
        if 'email' in data:
            db_execute(conn, 'UPDATE users SET email = ? WHERE id = ?', (data['email'], user_id))
        if 'designation' in data:
            db_execute(conn, 'UPDATE users SET designation = ? WHERE id = ?', (data['designation'], user_id))
        if 'project_ids' in data:
            db_execute(conn, 'DELETE FROM user_project_access WHERE user_id = ?', (user_id,))
            for pid in data['project_ids']:
                try:
                    db_execute(conn, 'INSERT INTO user_project_access (user_id, project_id) VALUES (?, ?)', (user_id, pid))
                except Exception:
                    pass
        if 'division_ids' in data:
            db_execute(conn, 'DELETE FROM user_division_access WHERE user_id = ?', (user_id,))
            for did in data['division_ids']:
                try:
                    db_execute(conn, 'INSERT INTO user_division_access (user_id, division_id) VALUES (?, ?)', (user_id, did))
                except Exception:
                    pass
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'user_updated', f'#{user_id}')
    return jsonify({'success': True})


@app.route('/api/users/<int:user_id>/reset-pin', methods=['POST'])
@require_role('executive', 'admin')
def api_reset_pin(user_id):
    new_pin = request.json.get('pin', '1234')
    conn = get_db()
    try:
        db_execute(conn, 'UPDATE users SET pin_hash = ?, must_change_pin = 1, failed_attempts = 0, locked_until = NULL WHERE id = ?',
                   (hash_pin(new_pin), user_id))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'pin_reset', f'#{user_id}')
    return jsonify({'success': True, 'message': f'PIN reset to {new_pin}'})


@app.route('/api/users/<int:user_id>/reset-2fa', methods=['POST'])
@require_role('executive', 'admin')
def admin_reset_2fa(user_id):
    """Generate new 2FA secret for user; return secret/uri so admin can give it to the user (sign-in is 2FA only)."""
    conn = get_db()
    try:
        row = db_fetchone(conn, 'SELECT username FROM users WHERE id = ?', (user_id,))
        if not row:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        new_secret = pyotp.random_base32()
        db_execute(conn, 'UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?', (new_secret, user_id))
        conn.commit()
        uri = pyotp.TOTP(new_secret).provisioning_uri(name=row['username'], issuer_name='PTC POB Tracker')
        audit(request.user['id'], '2fa_reset', f'#{user_id}')
        return jsonify({
            'success': True,
            'message': 'New 2FA secret generated. Give the user this setup to sign in.',
            'totp_setup': {'secret': new_secret, 'uri': uri}
        })
    finally:
        conn.close()


# ============================================================
# DIVISIONS / AREAS / PROJECTS (filtered by user access)
# ============================================================

@app.route('/api/health')
def health():
    """Diagnostic endpoint."""
    conn = get_db()
    try:
        row = db_fetchone(conn, 'SELECT COUNT(*) as c FROM users')
        users = row['c'] if isinstance(row, dict) else row[0]
        prow = db_fetchone(conn, 'SELECT COUNT(*) as c FROM projects')
        projects = prow['c'] if isinstance(prow, dict) else prow[0]
        return jsonify({'status': 'ok', 'users': users, 'projects': projects, 'db': 'PostgreSQL' if DATABASE_URL else 'SQLite'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/')
def index():
    return send_from_directory('public', 'index.html')


@app.route('/api/divisions')
@require_auth
def api_divisions():
    """List divisions. Focal point sees only their assigned divisions; admin/manager sees all."""
    conn = get_db()
    try:
        if request.user['role'] == 'focal_point':
            rows = db_fetchall(conn, '''SELECT d.id, d.name, d.active
                FROM divisions d
                JOIN user_division_access uda ON uda.division_id = d.id
                WHERE uda.user_id = ? AND (d.active = 1 OR d.active IS NULL)
                ORDER BY d.name''', (request.user['id'],))
        else:
            rows = db_fetchall(conn, 'SELECT id, name, active FROM divisions WHERE active = 1 OR active IS NULL ORDER BY name')
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/areas')
@require_auth
def api_areas():
    """List areas. Optional division_id= to filter. Respects user access."""
    division_id = request.args.get('division_id', type=int)
    conn = get_db()
    try:
        query = '''SELECT a.id, a.division_id, a.name, a.active, d.name as division_name
            FROM areas a
            JOIN divisions d ON d.id = a.division_id
            WHERE (a.active = 1 OR a.active IS NULL)'''
        params = []
        if division_id:
            query += ' AND a.division_id = ?'
            params.append(division_id)
        if request.user['role'] == 'focal_point':
            query += ' AND EXISTS (SELECT 1 FROM user_division_access uda WHERE uda.user_id = ? AND uda.division_id = a.division_id)'
            params.append(request.user['id'])
        query += ' ORDER BY a.name'
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/divisions', methods=['POST'])
@require_role('executive', 'admin')
def api_add_division():
    name = (request.json or {}).get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name required'}), 400
    conn = get_db()
    try:
        existing = db_fetchone(conn, 'SELECT id FROM divisions WHERE name = ?', (name,))
        if existing:
            return jsonify({'success': False, 'message': 'Division already exists'}), 409
        db_execute(conn, 'INSERT INTO divisions (name, active) VALUES (?, 1)', (name,))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'division_added', name)
    return jsonify({'success': True})


@app.route('/api/divisions/<int:div_id>', methods=['PUT'])
@require_role('executive', 'admin')
def api_update_division(div_id):
    name = (request.json or {}).get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name required'}), 400
    conn = get_db()
    try:
        db_execute(conn, 'UPDATE divisions SET name = ? WHERE id = ?', (name, div_id))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'division_renamed', f'#{div_id} -> {name}')
    return jsonify({'success': True})


@app.route('/api/divisions/<int:div_id>', methods=['DELETE'])
@require_role('executive', 'admin')
def api_delete_division(div_id):
    conn = get_db()
    try:
        db_execute(conn, 'UPDATE divisions SET active = 0 WHERE id = ?', (div_id,))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'division_deleted', f'#{div_id}')
    return jsonify({'success': True})


@app.route('/api/areas', methods=['POST'])
@require_role('executive', 'admin')
def api_add_area():
    data = request.json or {}
    name = data.get('name', '').strip()
    division_id = data.get('division_id')
    if not name or not division_id:
        return jsonify({'success': False, 'message': 'Name and division_id required'}), 400
    conn = get_db()
    try:
        existing = db_fetchone(conn, 'SELECT id FROM areas WHERE division_id = ? AND name = ?', (division_id, name))
        if existing:
            return jsonify({'success': False, 'message': 'Area already exists in this division'}), 409
        db_execute(conn, 'INSERT INTO areas (division_id, name, active) VALUES (?, ?, 1)', (division_id, name))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'area_added', name)
    return jsonify({'success': True})


@app.route('/api/areas/<int:area_id>', methods=['PUT'])
@require_role('executive', 'admin')
def api_update_area(area_id):
    name = (request.json or {}).get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Name required'}), 400
    conn = get_db()
    try:
        db_execute(conn, 'UPDATE areas SET name = ? WHERE id = ?', (name, area_id))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'area_renamed', f'#{area_id} -> {name}')
    return jsonify({'success': True})


@app.route('/api/areas/<int:area_id>', methods=['DELETE'])
@require_role('executive', 'admin')
def api_delete_area(area_id):
    conn = get_db()
    try:
        db_execute(conn, 'UPDATE areas SET active = 0 WHERE id = ?', (area_id,))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'area_deleted', f'#{area_id}')
    return jsonify({'success': True})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@require_role('executive', 'admin')
def api_delete_user(user_id):
    if user_id == request.user['id']:
        return jsonify({'success': False, 'message': 'Cannot delete yourself'}), 400
    conn = get_db()
    try:
        db_execute(conn, 'DELETE FROM user_project_access WHERE user_id = ?', (user_id,))
        db_execute(conn, 'DELETE FROM user_division_access WHERE user_id = ?', (user_id,))
        db_execute(conn, 'DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    finally:
        conn.close()
    audit(request.user['id'], 'user_deleted', f'#{user_id}')
    return jsonify({'success': True})


@app.route('/api/projects')
@require_auth
def api_projects():
    """List projects with division/area info. Optional area_id= or division_id=. Filtered by role."""
    area_id = request.args.get('area_id', type=int)
    division_id = request.args.get('division_id', type=int)
    conn = get_db()
    try:
        query = '''SELECT p.id, p.area_id, p.name, p.description, p.agreement_no,
            p.contract_number, p.contractor_company, p.active,
            a.name as area_name, a.division_id, d.name as division_name,
            COUNT(DISTINCT e.id) as employee_count, COUNT(DISTINCT s.id) as site_count
            FROM projects p
            LEFT JOIN areas a ON a.id = p.area_id
            LEFT JOIN divisions d ON d.id = a.division_id
            LEFT JOIN employees e ON e.project_id = p.id AND e.active = 1
            LEFT JOIN sites s ON s.project_id = p.id AND s.active = 1
            WHERE (p.active = 1 OR p.active IS NULL)'''
        params = []
        if area_id:
            query += ' AND p.area_id = ?'
            params.append(area_id)
        if division_id:
            query += ' AND a.division_id = ?'
            params.append(division_id)
        allowed = get_user_projects(conn, request.user['id'], request.user['role'])
        if allowed is not None:
            if not allowed:
                query += ' AND p.id = -1'
            else:
                placeholders = ','.join(['?' for _ in allowed])
                query += f' AND p.id IN ({placeholders})'
                params.extend(allowed)
        query += " GROUP BY p.id, p.area_id, p.name, p.contract_number, p.contractor_company, a.id, a.name, a.division_id, d.id, d.name ORDER BY COALESCE(d.name, ''), COALESCE(a.name, ''), p.name"
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/projects', methods=['POST'])
@require_role('executive', 'admin', 'focal_point')
def api_add_project():
    data = request.json or {}
    area_id = data.get('area_id')
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'message': 'Project name required'}), 400
    if not area_id and request.user['role'] != 'executive' and request.user['role'] != 'admin':
        return jsonify({'success': False, 'message': 'Area required'}), 400
    conn = get_db()
    try:
        db_execute(conn, 'INSERT INTO projects (area_id, name, description, agreement_no, active) VALUES (?, ?, ?, ?, 1)',
                   (area_id, name, data.get('description', ''), data.get('agreement_no', '')))
        conn.commit()
        proj = db_fetchone(conn, 'SELECT * FROM projects WHERE area_id = ? AND name = ?', (area_id, name))
        if proj:
            db_execute(conn, 'INSERT INTO sites (name, project_id, active) VALUES (?, ?, 1)', (name, proj['id']))
            conn.commit()
        audit(request.user['id'], 'project_created', name)
        return jsonify({'success': True, 'project': proj})
    except Exception as e:
        if 'UNIQUE' in str(e).upper():
            return jsonify({'success': False, 'message': 'Project already exists in this area'}), 400
        return jsonify({'success': False, 'message': str(e)}), 400
    finally:
        conn.close()


@app.route('/api/sites')
@require_auth
def api_sites():
    project_id = request.args.get('project_id')
    conn = get_db()
    try:
        query = 'SELECT s.* FROM sites s WHERE s.active = 1'
        params = []
        if project_id:
            query += ' AND s.project_id = ?'
            params.append(project_id)
        query, params = apply_project_filter(conn, query, params, request.user, 's')
        query += ' ORDER BY s.name'
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/sites', methods=['POST'])
@require_role('executive', 'admin')
def api_add_site():
    data = request.json
    conn = get_db()
    try:
        db_execute(conn, 'INSERT INTO sites (name, project_id, description) VALUES (?, ?, ?)',
                   (data['name'], data['project_id'], data.get('description', '')))
        conn.commit()
        return jsonify({'success': True})
    except Exception:
        return jsonify({'success': False, 'message': 'Site already exists'}), 400
    finally:
        conn.close()


# ============================================================
# IMPORT
# ============================================================

@app.route('/api/import-roster', methods=['POST'])
@require_role('executive', 'admin')
def api_import_roster():
    project_name = request.json.get('project_name') if request.is_json else None
    count, msg = import_roster(project_name=project_name)
    audit(request.user['id'], 'roster_imported', msg)
    return jsonify({'success': True, 'count': count, 'message': msg})


@app.route('/api/import-csv', methods=['POST'])
@require_role('executive', 'admin')
def api_import_csv():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file'}), 400
    f = request.files['file']
    project_name = request.form.get('project_name', '').strip()
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv', delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name
    try:
        count, msg = import_roster(tmp_path, project_name=project_name or None)
    finally:
        os.unlink(tmp_path)
    audit(request.user['id'], 'csv_imported', msg)
    return jsonify({'success': True, 'count': count, 'message': msg})


@app.route('/api/import-excel', methods=['POST'])
@require_role('executive', 'admin')
def api_import_excel():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith(('.xlsx', '.xls')):
        return jsonify({'success': False, 'message': 'Upload an .xlsx file'}), 400
    area_id = request.form.get('area_id', type=int)
    if not area_id:
        return jsonify({'success': False, 'message': 'Select an area for the import'}), 400
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.xlsx', delete=False) as tmp:
        f.save(tmp.name)
        tmp_path = tmp.name
    try:
        count, msg = import_excel(tmp_path, area_id=area_id)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    audit(request.user['id'], 'excel_imported', msg)
    return jsonify({'success': True, 'count': count, 'message': msg})


# ============================================================
# EMPLOYEES / SCAN / HEADCOUNT (project-scoped)
# ============================================================

@app.route('/api/contractors')
@require_auth
def api_contractors():
    """Return distinct contractor company names (from projects + employee subcontractor)."""
    project_id = request.args.get('project_id', '')
    area_id = request.args.get('area_id', type=int)
    division_id = request.args.get('division_id', type=int)
    conn = get_db()
    try:
        names = set()
        # From projects table
        pq = '''SELECT DISTINCT p.contractor_company FROM projects p
            LEFT JOIN areas a ON a.id = p.area_id
            WHERE p.active = 1 AND p.contractor_company IS NOT NULL AND p.contractor_company != '' '''
        pp = []
        if project_id:
            pq += ' AND p.id = ?'
            pp.append(project_id)
        if area_id:
            pq += ' AND p.area_id = ?'
            pp.append(area_id)
        if division_id:
            pq += ' AND a.division_id = ?'
            pp.append(division_id)
        for r in db_fetchall(conn, pq, pp):
            names.add(r['contractor_company'])
        # From employees subcontractor field
        eq = '''SELECT DISTINCT e.subcontractor FROM employees e
            LEFT JOIN projects p ON p.id = e.project_id
            LEFT JOIN areas a ON a.id = p.area_id
            WHERE e.active = 1 AND e.subcontractor IS NOT NULL AND e.subcontractor != '' '''
        ep = []
        if project_id:
            eq += ' AND e.project_id = ?'
            ep.append(project_id)
        if area_id:
            eq += ' AND p.area_id = ?'
            ep.append(area_id)
        if division_id:
            eq += ' AND a.division_id = ?'
            ep.append(division_id)
        eq, ep = apply_project_filter(conn, eq, ep, request.user, 'e')
        for r in db_fetchall(conn, eq, ep):
            names.add(r['subcontractor'])
    finally:
        conn.close()
    return jsonify(sorted(names))


@app.route('/api/employees')
@require_auth
def api_employees():
    conn = get_db()
    try:
        search = request.args.get('search', '')
        project_id = request.args.get('project_id', '')
        area_id = request.args.get('area_id', type=int)
        division_id = request.args.get('division_id', type=int)
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 500))
        offset = (page - 1) * per_page

        query = '''SELECT e.*, p.name as project_name, a.name as area_name, d.name as division_name
            FROM employees e
            LEFT JOIN projects p ON p.id = e.project_id
            LEFT JOIN areas a ON a.id = p.area_id
            LEFT JOIN divisions d ON d.id = a.division_id
            WHERE e.active = 1'''
        params = []
        if project_id:
            query += ' AND e.project_id = ?'
            params.append(project_id)
        if area_id:
            query += ' AND p.area_id = ?'
            params.append(area_id)
        if division_id:
            query += ' AND a.division_id = ?'
            params.append(division_id)
        subcontractor = request.args.get('subcontractor', '').strip()
        if subcontractor:
            query += ' AND e.subcontractor = ?'
            params.append(subcontractor)
        query, params = apply_project_filter(conn, query, params, request.user, 'e')
        if search:
            escaped = search.replace('%', r'\%').replace('_', r'\_')
            query += " AND (e.name LIKE ? ESCAPE '\\' OR e.employee_no LIKE ? ESCAPE '\\')"
            params.extend([f'%{escaped}%', f'%{escaped}%'])

        count_query = query.replace('SELECT e.*, p.name as project_name, a.name as area_name, d.name as division_name', 'SELECT COUNT(*) as total_count', 1)
        total_row = db_fetchone(conn, count_query, params)
        total = total_row.get('total_count', 0) if total_row else 0

        query += ' ORDER BY e.name LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/scan', methods=['POST'])
@require_auth
def api_scan():
    data = request.json
    employee_no = data.get('employee_no', '').strip()
    project_id = data.get('project_id')
    site_id = data.get('site_id')
    session = data.get('session', '').upper()
    qr_data = (data.get('qr_data') or '').strip()
    user = request.user

    # Accept unique QR payload: "project_id|employee_no"
    if qr_data and '|' in qr_data:
        parts = qr_data.split('|', 1)
        try:
            project_id = int(parts[0])
            employee_no = parts[1].strip()
        except (ValueError, IndexError):
            pass

    VALID_SESSIONS = ('AM', 'PM', 'EV')  # 9 AM, 2 PM, 6 PM
    if not employee_no or not project_id or not site_id or session not in VALID_SESSIONS:
        return jsonify({'success': False, 'message': 'Missing fields'}), 400

    # Focal points (ADNOC Onshore): view-only, cannot scan
    if user.get('role') == 'focal_point':
        return jsonify({'success': False, 'message': 'View-only access. You cannot scan.'}), 403

    conn = get_db()
    try:
        if not check_project_access(conn, user, project_id):
            return jsonify({'success': False, 'message': 'No access to this area'}), 403

        site = db_fetchone(conn, 'SELECT id FROM sites WHERE id = ? AND project_id = ?', (site_id, project_id))
        if not site:
            return jsonify({'success': False, 'message': 'Invalid site for this project'}), 400

        emp = db_fetchone(conn, 'SELECT * FROM employees WHERE employee_no = ? AND project_id = ?', (employee_no, project_id))
        if not emp:
            return jsonify({'success': False, 'message': f'Not found: {employee_no}'}), 404

        today = date.today().isoformat()
        existing = db_fetchone(conn, 'SELECT id FROM attendance WHERE employee_no = ? AND project_id = ? AND scan_date = ? AND session = ?',
                               (employee_no, project_id, today, session))
        if existing:
            return jsonify({'success': False, 'duplicate': True, 'message': f'{emp["name"]} already scanned for {session}', 'employee': emp})

        # Record scanner identity (name, email, designation) on every scan
        scanner_email = user.get('email') or ''
        scanner_designation = user.get('designation') or ''
        db_execute(conn, '''INSERT INTO attendance (employee_id, employee_no, project_id, site_id, scan_date, session, supervisor_id, supervisor_name, scanner_email, scanner_designation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (emp['id'], employee_no, project_id, site_id, today, session, user['id'], user['display_name'], scanner_email, scanner_designation))
        conn.commit()

        count = db_fetchone(conn, 'SELECT COUNT(*) as c FROM attendance WHERE project_id = ? AND site_id = ? AND scan_date = ? AND session = ?',
                            (project_id, site_id, today, session))['c']
        total = db_fetchone(conn, 'SELECT COUNT(*) as c FROM employees WHERE project_id = ? AND active = 1', (project_id,))['c']
    finally:
        conn.close()
    return jsonify({'success': True, 'message': f'Checked in: {emp["name"]}', 'employee': emp, 'site_count': count, 'site_total': total})


@app.route('/api/headcount')
@require_auth
def api_headcount():
    scan_date = request.args.get('date', date.today().isoformat())
    project_id = request.args.get('project_id')
    site_id = request.args.get('site_id')

    conn = get_db()
    try:
        query = '''SELECT p.name as project_name, s.name as site_name, a.session, COUNT(DISTINCT a.employee_no) as count
            FROM attendance a JOIN sites s ON s.id = a.site_id JOIN projects p ON p.id = a.project_id
            WHERE a.scan_date = ?'''
        params = [scan_date]
        if project_id:
            query += ' AND a.project_id = ?'
            params.append(project_id)
        if site_id:
            query += ' AND a.site_id = ?'
            params.append(site_id)
        query, params = apply_project_filter(conn, query, params, request.user)
        query += ' GROUP BY p.name, s.name, a.session ORDER BY p.name, s.name'
        rows = db_fetchall(conn, query, params)

        results = {}
        for row in rows:
            key = f"{row['project_name']}|{row['site_name']}"
            if key not in results:
                ec = db_fetchone(conn, '''SELECT COUNT(*) as c FROM employees e JOIN projects p ON p.id = e.project_id
                    WHERE e.active = 1 AND p.name = ? AND e.work_location = ?''', (row['project_name'], row['site_name']))
                results[key] = {'project': row['project_name'], 'site': row['site_name'], 'total_employees': ec['c'], 'AM': 0, 'PM': 0, 'EV': 0}
            results[key][row['session']] = row['count']

        tq = 'SELECT COUNT(*) as c FROM employees e WHERE e.active = 1'
        tp = []
        if project_id:
            tq += ' AND e.project_id = ?'
            tp.append(project_id)
        tq, tp = apply_project_filter(conn, tq, tp, request.user, 'e')
        total = db_fetchone(conn, tq, tp)['c']
    finally:
        conn.close()
    return jsonify({'date': scan_date, 'total_employees': total, 'sites': list(results.values())})


@app.route('/api/headcount/detail')
@require_auth
def api_headcount_detail():
    scan_date = request.args.get('date', date.today().isoformat())
    project_id = request.args.get('project_id')
    session = request.args.get('session', '')

    conn = get_db()
    try:
        query = '''SELECT e.name, e.employee_no, e.designation, e.discipline, a.session, a.scanned_at, a.supervisor_name, a.scanner_email, a.scanner_designation
            FROM attendance a JOIN employees e ON e.id = a.employee_id WHERE a.scan_date = ?'''
        params = [scan_date]
        if project_id:
            query += ' AND a.project_id = ?'
            params.append(project_id)
        if session:
            query += ' AND a.session = ?'
            params.append(session.upper())
        query, params = apply_project_filter(conn, query, params, request.user)
        query += ' ORDER BY a.scanned_at DESC'
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/headcount/missing')
@require_auth
def api_missing():
    scan_date = request.args.get('date', date.today().isoformat())
    project_id = request.args.get('project_id')
    session = request.args.get('session', 'AM')

    conn = get_db()
    try:
        query = 'SELECT e.* FROM employees e WHERE e.active = 1'
        params = []
        if project_id:
            query += ' AND e.project_id = ?'
            params.append(project_id)
        query, params = apply_project_filter(conn, query, params, request.user, 'e')
        query += ' AND e.employee_no NOT IN (SELECT a.employee_no FROM attendance a WHERE a.scan_date = ? AND a.session = ?'
        params.extend([scan_date, session.upper()])
        if project_id:
            query += ' AND a.project_id = ?'
            params.append(project_id)
        query += ') ORDER BY e.name'
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()
    return jsonify(rows)


@app.route('/api/stats')
@require_auth
def api_stats():
    project_id = request.args.get('project_id')
    area_id = request.args.get('area_id', type=int)
    division_id = request.args.get('division_id', type=int)
    conn = get_db()
    try:
        today = date.today().isoformat()

        eq = '''SELECT COUNT(*) as c FROM employees e
            LEFT JOIN projects p ON p.id = e.project_id
            LEFT JOIN areas ar ON ar.id = p.area_id
            WHERE e.active = 1'''
        ep = []
        if project_id:
            eq += ' AND e.project_id = ?'
            ep.append(project_id)
        if area_id:
            eq += ' AND p.area_id = ?'
            ep.append(area_id)
        if division_id:
            eq += ' AND ar.division_id = ?'
            ep.append(division_id)
        eq, ep = apply_project_filter(conn, eq, ep, request.user, 'e')

        def count_session(session_name):
            q = '''SELECT COUNT(DISTINCT a.employee_no) as c FROM attendance a
                LEFT JOIN projects p ON p.id = a.project_id
                LEFT JOIN areas ar ON ar.id = p.area_id
                WHERE a.scan_date = ? AND a.session = ?'''
            params = [today, session_name]
            if project_id:
                q += ' AND a.project_id = ?'
                params.append(project_id)
            if area_id:
                q += ' AND p.area_id = ?'
                params.append(area_id)
            if division_id:
                q += ' AND ar.division_id = ?'
                params.append(division_id)
            q, params = apply_project_filter(conn, q, params, request.user)
            return db_fetchone(conn, q, params)['c']

        total_emp = db_fetchone(conn, eq, ep)['c']
        today_am = count_session('AM')
        today_ev = count_session('EV')
        total_projects = db_fetchone(conn, 'SELECT COUNT(*) as c FROM projects WHERE active = 1')['c']
    finally:
        conn.close()
    return jsonify({'total_employees': total_emp, 'today_am': today_am, 'today_ev': today_ev, 'total_projects': total_projects, 'date': today})


@app.route('/api/trends')
@require_auth
def api_trends():
    """Attendance trend over N days, optionally filtered by session, designation, nationality, subcontractor."""
    days = int(request.args.get('days', 30))
    session = request.args.get('session', '').upper()
    designation = request.args.get('designation', '').strip()
    nationality = request.args.get('nationality', '').strip()
    subcontractor = request.args.get('subcontractor', '').strip()
    project_id = request.args.get('project_id', '')
    area_id = request.args.get('area_id', type=int)
    division_id = request.args.get('division_id', type=int)

    end = date.today()
    start = end - timedelta(days=days - 1)
    conn = get_db()
    try:
        query = '''SELECT att.scan_date, COUNT(DISTINCT att.employee_no) as count
            FROM attendance att
            JOIN employees e ON e.employee_no = att.employee_no AND e.project_id = att.project_id
            LEFT JOIN projects p ON p.id = att.project_id
            LEFT JOIN areas ar ON ar.id = p.area_id
            WHERE att.scan_date >= ? AND att.scan_date <= ? AND e.active = 1'''
        params = [start.isoformat(), end.isoformat()]
        if session:
            query += ' AND att.session = ?'
            params.append(session)
        if designation:
            query += ' AND e.designation = ?'
            params.append(designation)
        if nationality:
            query += ' AND e.nationality = ?'
            params.append(nationality)
        if subcontractor:
            query += ' AND e.subcontractor = ?'
            params.append(subcontractor)
        if project_id:
            query += ' AND att.project_id = ?'
            params.append(project_id)
        if area_id:
            query += ' AND p.area_id = ?'
            params.append(area_id)
        if division_id:
            query += ' AND ar.division_id = ?'
            params.append(division_id)
        query, params = apply_project_filter(conn, query, params, request.user, 'att')
        query += ' GROUP BY att.scan_date ORDER BY att.scan_date'
        rows = db_fetchall(conn, query, params)

        # Total workforce (filtered same way)
        tq = '''SELECT COUNT(DISTINCT e.id) as c FROM employees e
            LEFT JOIN projects p ON p.id = e.project_id
            LEFT JOIN areas ar ON ar.id = p.area_id WHERE e.active = 1'''
        tp = []
        if designation:
            tq += ' AND e.designation = ?'
            tp.append(designation)
        if nationality:
            tq += ' AND e.nationality = ?'
            tp.append(nationality)
        if subcontractor:
            tq += ' AND e.subcontractor = ?'
            tp.append(subcontractor)
        if project_id:
            tq += ' AND e.project_id = ?'
            tp.append(project_id)
        if area_id:
            tq += ' AND p.area_id = ?'
            tp.append(area_id)
        if division_id:
            tq += ' AND ar.division_id = ?'
            tp.append(division_id)
        tq, tp = apply_project_filter(conn, tq, tp, request.user, 'e')
        total = db_fetchone(conn, tq, tp)['c']

        # Distinct values for filter dropdowns
        desig_rows = db_fetchall(conn, "SELECT DISTINCT designation FROM employees WHERE active = 1 AND designation IS NOT NULL AND designation != '' ORDER BY designation")
        nat_rows = db_fetchall(conn, "SELECT DISTINCT nationality FROM employees WHERE active = 1 AND nationality IS NOT NULL AND nationality != '' ORDER BY nationality")
    finally:
        conn.close()

    dates_map = {r['scan_date']: r['count'] for r in rows}
    labels = []
    values = []
    d = start
    while d <= end:
        iso = d.isoformat()
        labels.append(iso)
        values.append(dates_map.get(iso, 0))
        d += timedelta(days=1)

    return jsonify({
        'labels': labels, 'values': values, 'total': total,
        'designations': [r['designation'] for r in desig_rows],
        'nationalities': [r['nationality'] for r in nat_rows]
    })


# ============================================================
# QR / Export / Audit
# ============================================================

@app.route('/api/qrcodes/batch')
@require_auth
def api_qrcodes_batch():
    conn = get_db()
    try:
        project_id = request.args.get('project_id', '')
        area_id = request.args.get('area_id', type=int)
        division_id = request.args.get('division_id', type=int)
        query = '''SELECT e.project_id, e.employee_no, e.name, e.designation, e.discipline, e.work_location, p.name as project_name
            FROM employees e
            JOIN projects p ON p.id = e.project_id
            LEFT JOIN areas a ON a.id = p.area_id
            WHERE e.active = 1'''
        params = []
        if project_id:
            query += ' AND e.project_id = ?'
            params.append(project_id)
        if area_id:
            query += ' AND p.area_id = ?'
            params.append(area_id)
        if division_id:
            query += ' AND a.division_id = ?'
            params.append(division_id)
        query, params = apply_project_filter(conn, query, params, request.user, 'e')
        query += ' ORDER BY e.name'
        employees = db_fetchall(conn, query, params)
    finally:
        conn.close()

    # Unique QR per person: encode project_id|employee_no so each code is globally unique
    results = []
    for emp in employees:
        qr_payload = f"{emp['project_id']}|{emp['employee_no']}"
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=3)
        qr.add_data(qr_payload)
        qr.make(fit=True)
        buf = BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(buf, format='PNG')
        results.append({**emp, 'qr_base64': base64.b64encode(buf.getvalue()).decode()})
    return jsonify(results)


@app.route('/api/qrcodes/single')
@require_auth
def api_qrcode_single():
    """Download a single QR code PNG for one employee."""
    employee_no = request.args.get('employee_no', '').strip()
    project_id = request.args.get('project_id', '').strip()
    if not employee_no or not project_id:
        return jsonify({'error': 'employee_no and project_id required'}), 400
    qr_payload = f"{project_id}|{employee_no}"
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=4)
    qr.add_data(qr_payload)
    qr.make(fit=True)
    buf = BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png', as_attachment=True, download_name=f'QR_{employee_no}.png')


@app.route('/api/export/download-token', methods=['POST'])
@require_auth
def api_download_token():
    conn = get_db()
    try:
        tok = secrets.token_urlsafe(32)
        db_execute(conn, "INSERT INTO download_tokens (user_id, token, expires_at) VALUES (?, ?, datetime('now', '+5 minutes'))",
                   (request.user['id'], tok))
        conn.commit()
    finally:
        conn.close()
    return jsonify({'token': tok})


@app.route('/api/export/attendance')
def api_export():
    dl_token = request.args.get('dl_token', '')
    if not dl_token:
        return jsonify({'error': 'Missing download token'}), 401

    conn = get_db()
    try:
        if USE_POSTGRES:
            tok_row = db_fetchone(conn, '''
                SELECT d.user_id, u.* FROM download_tokens d JOIN users u ON u.id = d.user_id
                WHERE d.token = ? AND d.expires_at > NOW()
            ''', (dl_token,))
        else:
            tok_row = db_fetchone(conn, '''
                SELECT d.user_id, u.* FROM download_tokens d JOIN users u ON u.id = d.user_id
                WHERE d.token = ? AND d.expires_at > datetime('now')
            ''', (dl_token,))

        if not tok_row:
            return jsonify({'error': 'Invalid or expired token'}), 401

        db_execute(conn, 'DELETE FROM download_tokens WHERE token = ?', (dl_token,))
        conn.commit()

        scan_date = request.args.get('date', date.today().isoformat())
        project_id = request.args.get('project_id')

        query = '''SELECT e.employee_no, e.name, e.designation, e.discipline, e.nationality, e.work_location,
            e.subcontractor, p.name as project_name, a.session, a.scan_date, a.scanned_at, a.supervisor_name, a.scanner_email, a.scanner_designation
            FROM attendance a JOIN employees e ON e.id = a.employee_id JOIN projects p ON p.id = a.project_id WHERE a.scan_date = ?'''
        params = [scan_date]
        if project_id:
            query += ' AND a.project_id = ?'
            params.append(project_id)
        query, params = apply_project_filter(conn, query, params, tok_row)
        query += ' ORDER BY p.name, e.name'
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Project', 'Employee No', 'Name', 'Designation', 'Discipline', 'Nationality',
                     'Work Location', 'Sub-contractor', 'Session', 'Date', 'Scanned At', 'Supervisor', 'Scanner Email', 'Scanner Designation'])
    for r in rows:
        writer.writerow([r['project_name'], r['employee_no'], r['name'], r['designation'], r['discipline'],
                        r['nationality'], r['work_location'], r['subcontractor'], r['session'], r['scan_date'],
                        r['scanned_at'], r['supervisor_name'], r.get('scanner_email') or '', r.get('scanner_designation') or ''])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv',
                     as_attachment=True, download_name=f'attendance_{scan_date}.csv')


# Full roster export: all required columns (Agreement No., Name, Nationality, DOB, Designation, Physical Work Location, Residing Camp, Employee No., Qualification, Date of Joining, Date of Deployment, Latest Periodic Medical, Discipline, Sub-contractor, Remarks)
@app.route('/api/export/roster')
def api_export_roster():
    dl_token = request.args.get('dl_token', '')
    if not dl_token:
        return jsonify({'error': 'Missing download token'}), 401
    conn = get_db()
    try:
        if USE_POSTGRES:
            tok_row = db_fetchone(conn, '''
                SELECT d.user_id, u.* FROM download_tokens d JOIN users u ON u.id = d.user_id
                WHERE d.token = ? AND d.expires_at > NOW()
            ''', (dl_token,))
        else:
            tok_row = db_fetchone(conn, '''
                SELECT d.user_id, u.* FROM download_tokens d JOIN users u ON u.id = d.user_id
                WHERE d.token = ? AND d.expires_at > datetime('now')
            ''', (dl_token,))
        if not tok_row:
            return jsonify({'error': 'Invalid or expired token'}), 401
        db_execute(conn, 'DELETE FROM download_tokens WHERE token = ?', (dl_token,))
        conn.commit()
        project_id = request.args.get('project_id', '')
        query = '''SELECT e.srl, e.agreement_no, e.name, e.nationality, e.dob, e.designation,
            e.work_location, e.camp_name, e.employee_no, e.qualification, e.date_joining,
            e.date_deployment, e.medical_date, e.discipline, e.subcontractor, e.remarks,
            p.name as project_name
            FROM employees e JOIN projects p ON p.id = e.project_id WHERE e.active = 1'''
        params = []
        if project_id:
            query += ' AND e.project_id = ?'
            params.append(project_id)
        query, params = apply_project_filter(conn, query, params, tok_row)
        query += ' ORDER BY p.name, e.name'
        rows = db_fetchall(conn, query, params)
    finally:
        conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Srl', 'Agreement No.', 'Name', 'Nationality', 'DOB', 'Designation',
        'Physical Work Location (Site / City Name)', 'Residing Camp Name & Location',
        'Employee No. / Contractor Ref.', 'Qualification', 'Date of Joining',
        'Date of Deployment with NQC Projects', 'Latest Periodic Medical conducted (Date)',
        'Discipline (Civil/Electrical/Mechanical/Others)', 'Sub-contractor/Manpower Supplier', 'Remarks', 'Project'
    ])
    for r in rows:
        writer.writerow([
            r.get('srl') or '', r.get('agreement_no') or '', r.get('name') or '', r.get('nationality') or '',
            r.get('dob') or '', r.get('designation') or '', r.get('work_location') or '', r.get('camp_name') or '',
            r.get('employee_no') or '', r.get('qualification') or '', r.get('date_joining') or '',
            r.get('date_deployment') or '', r.get('medical_date') or '', r.get('discipline') or '',
            r.get('subcontractor') or '', r.get('remarks') or '', r.get('project_name') or ''
        ])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv',
                     as_attachment=True, download_name='roster_full.csv')


@app.route('/api/audit')
@require_role('executive', 'admin')
def api_audit():
    conn = get_db()
    try:
        rows = db_fetchall(conn, '''SELECT a.*, u.display_name as user_name FROM audit_log a
            LEFT JOIN users u ON u.id = a.user_id ORDER BY a.created_at DESC LIMIT 200''')
    finally:
        conn.close()
    return jsonify(rows)


# ============================================================
# ROSTER IMPORT
# ============================================================

def import_roster(csv_path=None, project_name=None):
    if csv_path is None:
        csv_path = ROSTER_CSV
    if not os.path.exists(csv_path):
        return 0, "CSV file not found"

    if not project_name:
        project_name = os.path.splitext(os.path.basename(csv_path))[0].replace('_', ' ').title()

    conn = get_db()
    try:
        existing = db_fetchone(conn, 'SELECT id FROM projects WHERE name = ?', (project_name,))
        if not existing:
            db_execute(conn, 'INSERT INTO projects (name) VALUES (?)', (project_name,))
            conn.commit()
        project = db_fetchone(conn, 'SELECT id FROM projects WHERE name = ?', (project_name,))
        project_id = project['id']

        count = 0
        sites_found = set()

        with open(csv_path, 'r', encoding='utf-8-sig') as f:
            content = f.read()
        content = content.replace('\n(Site / City Name) ', '').replace('\nLocation\n', ' Location,').replace('\nContractor Ref.', ' Contractor Ref.')

        lines = content.strip().split('\n')
        fixed = [lines[0]] + [l for l in lines[1:] if l.strip()]
        reader = csv.reader(io.StringIO('\n'.join(fixed)))
        next(reader)

        agr = None
        for row in reader:
            if len(row) < 15 or not row[0].strip():
                continue
            try:
                vals = [c.strip() for c in row[:16]] + ([''] if len(row) <= 15 else [row[15].strip()])
                srl, agreement_no, name, nationality, dob, designation = vals[0], vals[1], vals[2], vals[3], vals[4], vals[5]
                work_location, camp_name, employee_no = vals[6], vals[7], vals[8]
                qualification, date_joining, date_deployment = vals[9], vals[10], vals[11]
                medical_date, discipline, subcontractor = vals[12], vals[13], vals[14]
                remarks = vals[15] if len(vals) > 15 else ''

                if not employee_no or not name:
                    continue
                if not agr and agreement_no:
                    agr = agreement_no
                    db_execute(conn, 'UPDATE projects SET agreement_no = ? WHERE id = ?', (agreement_no, project_id))

                sites_found.add(work_location)

                existing_emp = db_fetchone(conn, 'SELECT id FROM employees WHERE employee_no = ? AND project_id = ?', (employee_no, project_id))
                if existing_emp:
                    db_execute(conn, '''UPDATE employees SET srl=?, agreement_no=?, name=?, nationality=?, dob=?,
                        designation=?, work_location=?, camp_name=?, qualification=?, date_joining=?,
                        date_deployment=?, medical_date=?, discipline=?, subcontractor=?, remarks=?
                        WHERE employee_no = ? AND project_id = ?''',
                        (srl, agreement_no, name, nationality, dob, designation, work_location, camp_name,
                         qualification, date_joining, date_deployment, medical_date, discipline, subcontractor,
                         remarks, employee_no, project_id))
                else:
                    db_execute(conn, '''INSERT INTO employees (srl, agreement_no, name, nationality, dob, designation,
                        work_location, camp_name, employee_no, qualification, date_joining, date_deployment,
                        medical_date, discipline, subcontractor, remarks, project_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (srl, agreement_no, name, nationality, dob, designation, work_location, camp_name,
                         employee_no, qualification, date_joining, date_deployment, medical_date, discipline,
                         subcontractor, remarks, project_id))
                count += 1
            except Exception as e:
                print(f"Import error: {e}")

        for sn in sites_found:
            if sn:
                existing_site = db_fetchone(conn, 'SELECT id FROM sites WHERE name = ? AND project_id = ?', (sn, project_id))
                if not existing_site:
                    db_execute(conn, 'INSERT INTO sites (name, project_id) VALUES (?, ?)', (sn, project_id))

        conn.commit()
    finally:
        conn.close()
    return count, f"Imported {count} employees into '{project_name}'"


def _col_index(header_row, *names):
    """Find column index by header name (case-insensitive, partial match)."""
    for i, cell in enumerate(header_row):
        raw = getattr(cell, 'value', cell) or ''
        val = str(raw).strip().lower().replace('\n', ' ')
        for n in names:
            if n.lower() in val or val in n.lower():
                return i
    return -1


SHEET_TO_PROJECT = {}

def _cell_str(row, idx):
    if idx < 0 or idx >= len(row) or row[idx] is None:
        return ''
    v = row[idx]
    if hasattr(v, 'strftime'):
        return v.strftime('%Y-%m-%d')
    return str(v).strip()


def import_excel(xlsx_path, area_id=None):
    """Import sheets from the standard 16-column Excel template. Projects are created under the given area_id."""
    try:
        import openpyxl
    except ImportError:
        return 0, "Install openpyxl: pip install openpyxl"

    if not os.path.exists(xlsx_path):
        return 0, "Excel file not found"
    if not area_id:
        return 0, "Area is required for import"

    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    conn = get_db()
    total = 0
    messages = []
    # Resolve area name for project naming
    area_row = db_fetchone(conn, 'SELECT name FROM areas WHERE id = ?', (area_id,))
    area_label = (area_row['name'] if isinstance(area_row, dict) else area_row[0]) if area_row else ''
    try:
        for sheet_name in wb.sheetnames:
            ws = wb[sheet_name]
            # Read project name from cell C3; fall back to sheet name
            c3_val = None
            try:
                c3_val = ws['C3'].value
            except Exception:
                pass
            raw = str(c3_val).strip() if c3_val else sheet_name.strip()
            project_name = raw

            # Use provided area_id for new projects
            existing = db_fetchone(conn, 'SELECT id FROM projects WHERE area_id = ? AND name = ?', (area_id, project_name))
            if not existing:
                db_execute(conn, 'INSERT INTO projects (area_id, name, active) VALUES (?, ?, 1)', (area_id, project_name))
                conn.commit()
            proj = db_fetchone(conn, 'SELECT id FROM projects WHERE area_id = ? AND name = ?', (area_id, project_name))
            project_id = proj['id']
            site_name = project_name
            existing_site = db_fetchone(conn, 'SELECT id FROM sites WHERE name = ? AND project_id = ?', (site_name, project_id))
            if not existing_site:
                db_execute(conn, 'INSERT INTO sites (name, project_id, active) VALUES (?, ?, 1)', (site_name, project_id))
                conn.commit()

            # Fixed 16-column template:
            # 0:Srl, 1:Agreement No., 2:Name, 3:Nationality, 4:DOB, 5:Designation,
            # 6:Physical Work Location, 7:Residing Camp Name, 8:Employee No./Contractor Ref.,
            # 9:Qualification, 10:Date of Joining, 11:Date of Deployment,
            # 12:Medical Date, 13:Discipline, 14:Sub-contractor, 15:Remarks
            count = 0
            sites_found = set()
            for row in ws.iter_rows(min_row=2, values_only=True):
                if not row or len(row) < 9:
                    continue
                try:
                    name = _cell_str(row, 2)
                    employee_no = _cell_str(row, 8)
                    if not name or not employee_no:
                        continue
                    skip = employee_no.lower()
                    if skip in ('employee no.', 'contractor ref.', 'employee no', 'none', ''):
                        continue

                    srl = _cell_str(row, 0)
                    agreement_no = _cell_str(row, 1)
                    nationality = _cell_str(row, 3)
                    dob = _cell_str(row, 4)
                    designation = _cell_str(row, 5)
                    work_location = _cell_str(row, 6) or site_name
                    camp_name = _cell_str(row, 7)
                    qualification = _cell_str(row, 9)
                    date_joining = _cell_str(row, 10)
                    date_deployment = _cell_str(row, 11)
                    medical_date = _cell_str(row, 12)
                    discipline = _cell_str(row, 13)
                    subcontractor = _cell_str(row, 14)
                    remarks = _cell_str(row, 15)

                    existing_emp = db_fetchone(conn, 'SELECT id FROM employees WHERE employee_no = ? AND project_id = ?', (employee_no, project_id))
                    if existing_emp:
                        db_execute(conn, '''UPDATE employees SET srl=?, agreement_no=?, name=?, nationality=?, dob=?,
                            designation=?, work_location=?, camp_name=?, qualification=?, date_joining=?,
                            date_deployment=?, medical_date=?, discipline=?, subcontractor=?, remarks=?
                            WHERE employee_no = ? AND project_id = ?''',
                            (srl, agreement_no, name, nationality, dob, designation, work_location, camp_name,
                             qualification, date_joining, date_deployment, medical_date, discipline, subcontractor,
                             remarks, employee_no, project_id))
                    else:
                        db_execute(conn, '''INSERT INTO employees (srl, agreement_no, name, nationality, dob, designation,
                            work_location, camp_name, employee_no, qualification, date_joining, date_deployment,
                            medical_date, discipline, subcontractor, remarks, project_id)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                            (srl, agreement_no, name, nationality, dob, designation, work_location, camp_name,
                             employee_no, qualification, date_joining, date_deployment, medical_date, discipline,
                             subcontractor, remarks, project_id))
                    count += 1
                    if work_location and work_location != site_name:
                        sites_found.add(work_location)
                except Exception as e:
                    print(f"Excel row error ({sheet_name}): {e}")

            for sn in sites_found:
                if sn:
                    ex = db_fetchone(conn, 'SELECT id FROM sites WHERE name = ? AND project_id = ?', (sn, project_id))
                    if not ex:
                        db_execute(conn, 'INSERT INTO sites (name, project_id, active) VALUES (?, ?, 1)', (sn, project_id))
            conn.commit()
            total += count
            messages.append(f"{project_name}: {count} people")
        wb.close()
    finally:
        conn.close()
    return total, ("Excel import: " + "; ".join(messages)) if messages else "No data imported"


# ============================================================
# STARTUP (local dev only)
# ============================================================

if __name__ == '__main__':
    import socket
    import ssl as _ssl

    if os.path.exists(ROSTER_CSV):
        conn = get_db()
        try:
            ec = db_fetchone(conn, 'SELECT COUNT(*) as c FROM employees')['c']
        finally:
            conn.close()
        if ec == 0:
            print("Importing roster...")
            cnt, msg = import_roster()
            print(f"  {msg}")
        else:
            print(f"  {ec} employees in database")

    local_ip = socket.gethostbyname(socket.gethostname())
    cert_dir = os.path.join(os.path.dirname(__file__), 'certs')
    cert_file = os.path.join(cert_dir, 'cert.pem')
    key_file = os.path.join(cert_dir, 'key.pem')
    use_ssl = os.path.exists(cert_file) and os.path.exists(key_file)

    if not use_ssl:
        try:
            os.makedirs(cert_dir, exist_ok=True)
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
            cert = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.DNSName('127.0.0.1')]), critical=False)
                .sign(key, hashes.SHA256(), default_backend())
            )
            with open(key_file, 'wb') as f:
                f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            use_ssl = True
            print("  Generated self-signed HTTPS cert in ./certs/")
        except Exception as e:
            print(f"  HTTPS cert generation skipped: {e}")
            print("  Run with http:// (or add cert.pem + key.pem to ./certs/ for HTTPS)")

    proto = 'https' if use_ssl else 'http'
    print(f"\n{'='*44}")
    print(f"  PTC POB Tracker - Cloud Ready")
    print(f"{'='*44}")
    print(f"  {proto}://localhost:5000")
    print(f"  {proto}://{local_ip}:5000")
    print(f"  DB: {'PostgreSQL' if USE_POSTGRES else 'SQLite (local)'}")
    print(f"{'='*44}\n")

    ssl_ctx = None
    if use_ssl:
        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert_file, key_file)

    app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=ssl_ctx)
