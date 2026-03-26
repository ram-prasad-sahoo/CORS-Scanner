"""
CORS Vulnerability Checker — Admin Dashboard Backend
Flask server with SQLite database, CAPTCHA login, and scan history API.
"""

import os
import json
import time
import random
import hashlib
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session, redirect

app = Flask(__name__)
# In production, use a fixed secret key via environment variables
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

@app.after_request
def add_security_headers(response):
    # Mask Server header to prevent Werkzeug info disclosure
    response.headers['Server'] = 'CORS-Checker Server'
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME-sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# ── Database Setup ───────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cors_scans.db')

# ── Admin Credentials (SHA-256 hashed) ──────────────────────────────────────────
ADMIN_USER = 'admin'
ADMIN_PASS_HASH = hashlib.sha256('admin'.encode()).hexdigest()

# ── Brute-force protection state ────────────────────────────────────────────────
login_attempts = {}  # ip -> { count, lockout_until }
MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 30

# ── CAPTCHA state ───────────────────────────────────────────────────────────────
captcha_store = {}  # session_id -> { answer, created_at }


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            method TEXT DEFAULT 'GET',
            mode TEXT DEFAULT 'single',
            timestamp TEXT NOT NULL,
            verdict TEXT DEFAULT '',
            risk_level TEXT DEFAULT '',
            findings_json TEXT DEFAULT '[]',
            headers_json TEXT DEFAULT '{}',
            response_preview TEXT DEFAULT '',
            with_credentials INTEGER DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


init_db()


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Admin-Token') or request.args.get('token') or request.cookies.get('admin_token')
        if not token:
            return jsonify({'error': 'Unauthorized'}), 401
        conn = get_db()
        row = conn.execute('SELECT * FROM admin_sessions WHERE token = ?', (token,)).fetchone()
        conn.close()
        if not row:
            return jsonify({'error': 'Invalid session'}), 401
        return f(*args, **kwargs)
    return decorated


def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr)


def is_locked_out(ip):
    if ip in login_attempts:
        info = login_attempts[ip]
        if info.get('lockout_until') and time.time() < info['lockout_until']:
            remaining = int(info['lockout_until'] - time.time())
            return True, remaining
    return False, 0


# ═══════════════════════════════════════════════════════════════════════════════
# CAPTCHA
# ═══════════════════════════════════════════════════════════════════════════════
def generate_captcha():
    """Generate a random math CAPTCHA."""
    ops = [
        ('+', lambda a, b: a + b),
        ('-', lambda a, b: a - b),
        ('×', lambda a, b: a * b),
    ]
    op_symbol, op_fn = random.choice(ops)
    if op_symbol == '×':
        a, b = random.randint(2, 9), random.randint(2, 9)
    elif op_symbol == '-':
        a = random.randint(10, 50)
        b = random.randint(1, a)
    else:
        a, b = random.randint(5, 45), random.randint(5, 45)
    answer = op_fn(a, b)
    question = f"{a} {op_symbol} {b}"
    captcha_id = secrets.token_hex(16)
    captcha_store[captcha_id] = {
        'answer': str(answer),
        'created_at': time.time()
    }
    # Clean old captchas (older than 5 minutes)
    now = time.time()
    expired = [k for k, v in captcha_store.items() if now - v['created_at'] > 300]
    for k in expired:
        del captcha_store[k]

    return captcha_id, question, answer


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES — HTML Pages
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/')
def index():
    return send_from_directory('.', 'cors-checker.html')

@app.route('/docs')
def docs_page():
    return send_from_directory('.', 'how-to-use.html')


@app.route('/admin')
def admin_page():
    return send_from_directory('.', 'admin.html')


@app.route('/dashboard')
def dashboard_page():
    token = request.cookies.get('admin_token')
    if not token:
        return redirect('/admin')
    conn = get_db()
    row = conn.execute('SELECT * FROM admin_sessions WHERE token = ?', (token,)).fetchone()
    conn.close()
    if not row:
        return redirect('/admin')
    return send_from_directory('.', 'admin-dashboard.html')


# ═══════════════════════════════════════════════════════════════════════════════
# API — CAPTCHA
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/api/captcha', methods=['GET'])
def api_captcha():
    captcha_id, question, _ = generate_captcha()
    ip = get_client_ip()
    locked, remaining = is_locked_out(ip)
    return jsonify({
        'captcha_id': captcha_id,
        'question': question,
        'locked': locked,
        'lockout_remaining': remaining
    })


# ═══════════════════════════════════════════════════════════════════════════════
# API — LOGIN
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/api/login', methods=['POST'])
def api_login():
    ip = get_client_ip()
    locked, remaining = is_locked_out(ip)
    if locked:
        return jsonify({
            'success': False,
            'error': f'Too many failed attempts. Try again in {remaining}s.',
            'locked': True,
            'lockout_remaining': remaining
        }), 429

    data = request.get_json() or {}
    client_uname_hash = data.get('client_uname_hash', '')  # SHA256(username + challenge)
    client_hash = data.get('client_hash', '')  # SHA256(password_hash + challenge)
    captcha_id = data.get('captcha_id', '')
    captcha_answer = str(data.get('captcha_answer', '')).strip()

    # Verify CAPTCHA first
    captcha_entry = captcha_store.pop(captcha_id, None)
    if not captcha_entry:
        return jsonify({'success': False, 'error': 'CAPTCHA/Challenge expired. Please refresh.'}), 400
    if captcha_answer != captcha_entry['answer']:
        # Count as failed attempt
        if ip not in login_attempts:
            login_attempts[ip] = {'count': 0}
        login_attempts[ip]['count'] += 1
        if login_attempts[ip]['count'] >= MAX_ATTEMPTS:
            login_attempts[ip]['lockout_until'] = time.time() + LOCKOUT_SECONDS
        return jsonify({
            'success': False,
            'error': 'Wrong CAPTCHA answer.',
            'attempts_left': max(0, MAX_ATTEMPTS - login_attempts.get(ip, {}).get('count', 0))
        }), 400

    # Verify credentials via challenge-response
    # Expected User: SHA256(ADMIN_USER + captcha_id)
    # Expected Pass: SHA256(ADMIN_PASS_HASH + captcha_id)
    expected_uname_hash = hashlib.sha256((ADMIN_USER + captcha_id).encode()).hexdigest()
    expected_pass_hash = hashlib.sha256((ADMIN_PASS_HASH + captcha_id).encode()).hexdigest()

    if client_uname_hash != expected_uname_hash or client_hash != expected_pass_hash:
        if ip not in login_attempts:
            login_attempts[ip] = {'count': 0}
        login_attempts[ip]['count'] += 1
        if login_attempts[ip]['count'] >= MAX_ATTEMPTS:
            login_attempts[ip]['lockout_until'] = time.time() + LOCKOUT_SECONDS
        attempts_left = max(0, MAX_ATTEMPTS - login_attempts[ip]['count'])
        return jsonify({
            'success': False,
            'error': f'Invalid credentials. {attempts_left} attempt(s) left.',
            'attempts_left': attempts_left
        }), 401

    # Success — reset attempts and create session
    login_attempts.pop(ip, None)
    token = secrets.token_hex(32)
    conn = get_db()
    conn.execute('INSERT INTO admin_sessions (token, created_at) VALUES (?, ?)',
                 (token, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    # Create response signature using token, expected_pass_hash (which equals clientHash), and captcha_id
    # Signature = SHA256(token + expected_pass_hash + captcha_id)
    signature = hashlib.sha256((token + expected_pass_hash + captcha_id).encode()).hexdigest()

    response = jsonify({'success': True, 'token': token, 'signature': signature})
    response.set_cookie('admin_token', token, httponly=True, samesite='Strict')
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# API — LOGOUT
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/api/logout', methods=['POST'])
def api_logout():
    token = request.headers.get('X-Admin-Token') or request.cookies.get('admin_token')
    if token:
        conn = get_db()
        conn.execute('DELETE FROM admin_sessions WHERE token = ?', (token,))
        conn.commit()
        conn.close()
    
    response = jsonify({'success': True})
    response.delete_cookie('admin_token')
    return response


# ═══════════════════════════════════════════════════════════════════════════════
# API — SAVE SCAN
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/api/scan', methods=['POST'])
def api_save_scan():
    data = request.get_json() or {}
    required = ['url', 'verdict']
    if not all(data.get(k) for k in required):
        return jsonify({'error': 'Missing required fields'}), 400

    conn = get_db()
    conn.execute('''
        INSERT INTO scans (url, method, mode, timestamp, verdict, risk_level,
                           findings_json, headers_json, response_preview, with_credentials)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('url', ''),
        data.get('method', 'GET'),
        data.get('mode', 'single'),
        datetime.now().isoformat(),
        data.get('verdict', ''),
        data.get('risk_level', 'info'),
        json.dumps(data.get('findings', [])),
        json.dumps(data.get('headers', {})),
        data.get('response_preview', '')[:2000],
        1 if data.get('with_credentials') else 0
    ))
    conn.commit()
    scan_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.close()

    return jsonify({'success': True, 'id': scan_id})


# ═══════════════════════════════════════════════════════════════════════════════
# API — GET SCANS (Admin Only)
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/api/scans', methods=['GET'])
@require_admin
def api_get_scans():
    conn = get_db()
    rows = conn.execute('SELECT * FROM scans ORDER BY id DESC').fetchall()
    conn.close()
    scans = []
    for row in rows:
        scans.append({
            'id': row['id'],
            'url': row['url'],
            'method': row['method'],
            'mode': row['mode'],
            'timestamp': row['timestamp'],
            'verdict': row['verdict'],
            'risk_level': row['risk_level'],
            'findings': json.loads(row['findings_json'] or '[]'),
            'headers': json.loads(row['headers_json'] or '{}'),
            'response_preview': row['response_preview'],
            'with_credentials': bool(row['with_credentials'])
        })
    return jsonify({'scans': scans, 'total': len(scans)})


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
@require_admin
def api_get_scan(scan_id):
    conn = get_db()
    row = conn.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify({
        'id': row['id'],
        'url': row['url'],
        'method': row['method'],
        'mode': row['mode'],
        'timestamp': row['timestamp'],
        'verdict': row['verdict'],
        'risk_level': row['risk_level'],
        'findings': json.loads(row['findings_json'] or '[]'),
        'headers': json.loads(row['headers_json'] or '{}'),
        'response_preview': row['response_preview'],
        'with_credentials': bool(row['with_credentials'])
    })


@app.route('/api/scans/export', methods=['GET'])
@require_admin
def api_export_scans():
    conn = get_db()
    rows = conn.execute('SELECT * FROM scans ORDER BY id DESC').fetchall()
    conn.close()
    scans = []
    for row in rows:
        scans.append({
            'id': row['id'],
            'url': row['url'],
            'method': row['method'],
            'mode': row['mode'],
            'timestamp': row['timestamp'],
            'verdict': row['verdict'],
            'risk_level': row['risk_level'],
            'findings': json.loads(row['findings_json'] or '[]'),
            'headers': json.loads(row['headers_json'] or '{}'),
            'response_preview': row['response_preview'],
            'with_credentials': bool(row['with_credentials'])
        })
    from flask import Response
    return Response(
        json.dumps({'exported_at': datetime.now().isoformat(), 'scans': scans}, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=cors_scan_export.json'}
    )


@app.route('/api/scans', methods=['DELETE'])
@require_admin
def api_clear_scans():
    conn = get_db()
    conn.execute('DELETE FROM scans')
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'All scan history cleared.'})


@app.route('/api/scans/batch_delete', methods=['POST'])
@require_admin
def api_batch_delete():
    data = request.get_json() or {}
    ids = data.get('ids', [])
    if not ids or not isinstance(ids, list):
        return jsonify({'error': 'No IDs provided'}), 400
    
    conn = get_db()
    placeholders = ','.join('?' for _ in ids)
    conn.execute(f'DELETE FROM scans WHERE id IN ({placeholders})', ids)
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ═══════════════════════════════════════════════════════════════════════════════
# API — STATS
# ═══════════════════════════════════════════════════════════════════════════════
@app.route('/api/stats', methods=['GET'])
@require_admin
def api_stats():
    conn = get_db()
    total = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    vuln = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level IN ('high', 'critical')").fetchone()[0]
    safe = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'safe'").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'critical'").fetchone()[0]
    last_scan = conn.execute('SELECT timestamp FROM scans ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    return jsonify({
        'total': total,
        'vulnerable': vuln,
        'safe': safe,
        'critical': critical,
        'last_scan': last_scan[0] if last_scan else None
    })


if __name__ == '__main__':
    print("\n" + "═" * 60)
    print("  CORS Vulnerability Checker — Admin Server")
    print("═" * 60)
    print(f"  🌐 Scanner:    http://localhost:5000")
    print(f"  🔐 Admin:      http://localhost:5000/admin")
    print(f"  📊 Dashboard:  http://localhost:5000/dashboard")
    print(f"  💾 Database:   {DB_PATH}")
    print("═" * 60 + "\n")
    # For production deployment, default to debug=False and rely on environment variables or WSGI
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
