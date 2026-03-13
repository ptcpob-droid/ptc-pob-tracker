#!/usr/bin/env python3
"""
One-time script to unlock admin and set a new PIN.
Run on Render: Shell tab, then: python reset_admin.py 1234
(Use whatever PIN you want instead of 1234.)
"""
import os
import sys
import hashlib
import secrets

DATABASE_URL = os.environ.get('DATABASE_URL', '')
if not DATABASE_URL.startswith('postgres'):
    print('DATABASE_URL not set or not PostgreSQL. Run this on Render.')
    sys.exit(1)

def hash_pin(pin):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt.encode(), 100000)
    return f"{salt}:{h.hex()}"

def main():
    new_pin = sys.argv[1] if len(sys.argv) > 1 else '1234'
    if len(new_pin) < 4 or not new_pin.isdigit():
        print('PIN must be 4+ digits. Usage: python reset_admin.py 1234')
        sys.exit(1)

    import psycopg2
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET pin_hash = %s, locked_until = NULL, failed_attempts = 0, active = 1 WHERE LOWER(username) = 'admin'",
        (hash_pin(new_pin),)
    )
    conn.commit()
    n = cur.rowcount
    row = None
    if n == 0:
        cur.execute("SELECT id, username FROM users ORDER BY id LIMIT 1")
        row = cur.fetchone()
        if row:
            cur.execute(
                "UPDATE users SET pin_hash = %s, locked_until = NULL, failed_attempts = 0, active = 1 WHERE id = %s",
                (hash_pin(new_pin), row[0])
            )
            conn.commit()
            n = cur.rowcount
    conn.close()
    if n:
        if row:
            print(f'User "{row[1]}" (id={row[0]}) unlocked. Log in with username **{row[1]}** and PIN **{new_pin}**.')
        else:
            print(f'Admin unlocked. Log in with username **admin** and PIN **{new_pin}**.')
    else:
        print('No user found in database.')
    sys.exit(0 if n else 1)

if __name__ == '__main__':
    main()
