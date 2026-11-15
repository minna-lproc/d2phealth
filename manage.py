"""Run: python manage.py init-admin (or reset-admin). Passwords are prompted securely."""
import argparse, getpass, sqlite3, uuid
from app import app, password_hash, stamp
parser=argparse.ArgumentParser();parser.add_argument('command',choices=['init-admin','reset-admin']);args=parser.parse_args()
username=input('Administrator username [admin]: ').strip().lower() or 'admin'
import re
if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,49}',username): raise SystemExit('Username must be 3–50 valid characters.')
password=getpass.getpass('Password (12–128 characters): ')
if not 12<=len(password)<=128: raise SystemExit('Password must be 12–128 characters.')
if password!=getpass.getpass('Repeat password: '): raise SystemExit('Passwords do not match.')
with sqlite3.connect(app.config['DATABASE']) as db:
    if args.command=='init-admin':
        if db.execute("SELECT 1 FROM members WHERE role='admin'").fetchone(): raise SystemExit('An administrator already exists. Use reset-admin to reset its password.')
        name=input('Administrator display name: ').strip() or 'Project administrator'
        db.execute("INSERT INTO members(id,username,email,name,role,password_hash,must_change_password,created_at) VALUES(?,?,'',?,'admin',?,0,?)",(str(uuid.uuid4()),username,name,password_hash(password),stamp()))
    else:
        result=db.execute("UPDATE members SET password_hash=?,must_change_password=0,enabled=1,auth_version=auth_version+1 WHERE username=? AND role='admin'",(password_hash(password),username))
        if result.rowcount!=1: raise SystemExit('Administrator username not found.')
print('Administrator account is ready. No password was written to a log or configuration file.')
