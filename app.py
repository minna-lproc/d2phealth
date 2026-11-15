"""D2P Community Health: Flask, SQLite, account roles and offline sync."""
from __future__ import annotations
import hashlib, json, os, re, secrets, sqlite3, time, uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, request, session, jsonify, g, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

ROOT = Path(__file__).resolve().parent
QUESTIONNAIRE = json.loads((ROOT / 'static/data.js').read_text(encoding='utf-8')[len('const SECTIONS='):-1])
QUESTIONS = {q['id']: q['en'] for section in QUESTIONNAIRE for q in section['questions']}
SCHEMA = '''
CREATE TABLE members (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, email TEXT NOT NULL DEFAULT '', name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','enumerator')), enabled INTEGER NOT NULL DEFAULT 1, password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1, auth_version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE interviews (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES members(id), payload TEXT NOT NULL, content_hash TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, server_updated TEXT NOT NULL);
CREATE INDEX interviews_owner_id ON interviews(owner_id,id);
CREATE TABLE audit_events (id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE login_attempts (attempt_key TEXT PRIMARY KEY, failures INTEGER NOT NULL, window_start INTEGER NOT NULL);
PRAGMA user_version=1;
'''
def stamp(): return datetime.now(timezone.utc).isoformat()
def password_hash(password): return generate_password_hash(password, method='pbkdf2:sha256:600000')
class Problem(Exception):
    def __init__(self, status, message): self.status, self.message = status, message

def create_app(test_config=None):
    app = Flask(__name__, static_folder=None, instance_relative_config=True)
    # PythonAnywhere terminates HTTPS at its front proxy. Only trust the scheme header.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=0, x_for=0)
    instance = Path(os.environ.get('D2P_INSTANCE_PATH', str(ROOT / 'instance')))
    if test_config and test_config.get('INSTANCE_PATH'): instance = Path(test_config['INSTANCE_PATH'])
    instance.mkdir(parents=True, exist_ok=True)
    secret_path = instance / 'secret_key'
    secret = os.environ.get('D2P_SECRET_KEY')
    if not secret:
        try:
            fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError: pass
        else:
            with os.fdopen(fd, 'w') as file: file.write(secrets.token_hex(32))
        secret = secret_path.read_text().strip()
    app.config.update(SECRET_KEY=secret, DATABASE=str(instance / 'survey.sqlite3'), MAX_CONTENT_LENGTH=1024*1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('D2P_DEV_HTTP') != '1',
                      PERMANENT_SESSION_LIFETIME=timedelta(days=14))
    if test_config: app.config.update(test_config)
    with sqlite3.connect(app.config['DATABASE']) as db:
        db.execute('PRAGMA journal_mode=WAL')
        version=db.execute('PRAGMA user_version').fetchone()[0]
        if version == 0: db.executescript(SCHEMA)
        elif version != 1: raise RuntimeError('Unsupported database schema version. Back up the database before upgrading.')
    dummy_hash=password_hash(secrets.token_urlsafe(24))
    def db():
        if 'db' not in g:
            g.db=sqlite3.connect(app.config['DATABASE'], timeout=20)
            g.db.row_factory=sqlite3.Row
            g.db.execute('PRAGMA foreign_keys=ON')
        return g.db
    @app.teardown_appcontext
    def close_db(error):
        connection=g.pop('db', None)
        if connection is not None: connection.close()
    def csrf():
        if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
        return session['csrf']
    def profile(row):
        return {'id':row['id'], 'memberId':row['id'], 'username':row['username'], 'email':row['email'], 'name':row['name'], 'role':row['role'], 'mustChangePassword':bool(row['must_change_password'])}
    def current():
        if 'user_id' not in session: return None
        row=db().execute('SELECT * FROM members WHERE id=?',(session['user_id'],)).fetchone()
        if not row or not row['enabled'] or row['auth_version']!=session.get('auth_version'):
            session.clear()
            raise Problem(401,'Your session expired or account access changed. Sign in again. Local interviews are kept on this device.')
        return row
    def authorized(admin=False, allow_password=False):
        def decorate(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                row=current()
                if not row: raise Problem(401,'Sign in to continue.')
                if row['must_change_password'] and not allow_password: raise Problem(428,'Change your temporary password before continuing.')
                if admin and row['role']!='admin': raise Problem(403,'Administrator access required.')
                g.member=row
                return fn(*args, **kwargs)
            return wrapped
        return decorate
    def data():
        value=request.get_json(silent=True)
        if not isinstance(value,dict): raise Problem(400,'Expected a JSON object.')
        return value
    def audit(action,target):
        db().execute('INSERT INTO audit_events VALUES (?,?,?,?,?)',(str(uuid.uuid4()),g.member['id'],action,target,stamp()))
    @app.before_request
    def protect_mutations():
        if request.path.startswith('/api/') and request.method not in ('GET','HEAD','OPTIONS'):
            if request.headers.get('Origin') != request.host_url.rstrip('/'):
                raise Problem(403,'Request origin not allowed.')
            if not request.is_json: raise Problem(415,'Use application/json.')
            token=request.headers.get('X-CSRF-Token','')
            if not token or not secrets.compare_digest(token,session.get('csrf','')):
                raise Problem(403,'Security check expired. Refresh the page and try again.')
    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='same-origin'
        response.headers['Cache-Control']='no-store' if request.path.startswith('/api/') else 'no-cache'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        if request.path=='/sw.js': response.headers['Service-Worker-Allowed']='/'
        return response
    @app.errorhandler(Problem)
    def problem(error): return jsonify(error=error.message),error.status
    @app.errorhandler(413)
    def too_large(error): return jsonify(error='This request is too large. Sync fewer interviews at a time.'),413
    @app.errorhandler(sqlite3.OperationalError)
    def db_error(error):
        app.logger.exception('Database request failed')
        return jsonify(error='Database temporarily unavailable. Your interviews remain saved on this device. Try syncing again.'),503
    @app.get('/api/session')
    def get_session():
        row=current()
        return jsonify(user=profile(row) if row else None,csrfToken=csrf())
    @app.post('/api/login')
    def login():
        b=data(); username=str(b.get('username','')).strip().lower(); password=b.get('password','')
        if not isinstance(password,str) or len(password)>1024: raise Problem(400,'Invalid login.')
        # Per-account and per-client limits are checked in a write transaction.
        keys=['account:'+username[:100], 'ip:'+str(request.remote_addr)]
        now=int(time.time());connection=db();connection.execute('BEGIN IMMEDIATE')
        for key in keys:
            attempt=connection.execute('SELECT * FROM login_attempts WHERE attempt_key=?',(key,)).fetchone()
            limit=8 if key.startswith('account:') else 40
            if attempt and now-attempt['window_start']<900 and attempt['failures']>=limit:
                connection.rollback();raise Problem(429,'Too many login attempts. Wait 15 minutes before trying again.')
        row=connection.execute('SELECT * FROM members WHERE username=?',(username,)).fetchone()
        valid=check_password_hash(row['password_hash'] if row else dummy_hash,password)
        if not row or not row['enabled'] or not valid:
            for key in keys:
                connection.execute('INSERT INTO login_attempts VALUES (?,?,?) ON CONFLICT(attempt_key) DO UPDATE SET failures=CASE WHEN ?-window_start>=900 THEN 1 ELSE failures+1 END,window_start=CASE WHEN ?-window_start>=900 THEN ? ELSE window_start END',(key,1,now,now,now,now))
            connection.commit();raise Problem(401,'Incorrect username or password, or this account is disabled.')
        connection.execute('DELETE FROM login_attempts WHERE attempt_key=?',(keys[0],));connection.commit()
        session.clear();session.permanent=True;session['user_id']=row['id'];session['auth_version']=row['auth_version']
        return jsonify(user=profile(row),csrfToken=csrf())
    @app.post('/api/logout')
    def logout(): session.clear();return jsonify(ok=True)
    @app.get('/api/me')
    @authorized(allow_password=True)
    def me(): return jsonify(user=profile(g.member),csrfToken=csrf())
    @app.post('/api/password')
    @authorized(allow_password=True)
    def change_password():
        b=data();old=b.get('currentPassword','');new=b.get('newPassword','')
        if not isinstance(old,str) or not isinstance(new,str) or not 12<=len(new)<=128: raise Problem(400,'Use a new password of 12–128 characters.')
        if not check_password_hash(g.member['password_hash'],old): raise Problem(400,'The current password is incorrect.')
        if old==new: raise Problem(400,'Choose a different password.')
        db().execute('UPDATE members SET password_hash=?,must_change_password=0,auth_version=auth_version+1 WHERE id=?',(password_hash(new),g.member['id']));db().commit()
        row=db().execute('SELECT * FROM members WHERE id=?',(g.member['id'],)).fetchone();session['auth_version']=row['auth_version'];session['csrf']=secrets.token_urlsafe(32)
        return jsonify(user=profile(row),csrfToken=csrf())
    @app.get('/api/members')
    @authorized(admin=True)
    def members():
        rows=db().execute('SELECT id,username,email,name,role,enabled,id AS user_id,must_change_password,created_at FROM members ORDER BY created_at DESC LIMIT 1000').fetchall()
        return jsonify(members=[dict(r) for r in rows])
    @app.post('/api/members')
    @authorized(admin=True)
    def add_member():
        b=data();username=str(b.get('username','')).strip().lower();name=str(b.get('name','')).strip();email=str(b.get('email','')).strip();password=b.get('temporaryPassword','')
        if not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{2,49}',username): raise Problem(400,'Username must be 3–50 letters, numbers, dots, dashes or underscores.')
        if not name or len(name)>150 or len(email)>254: raise Problem(400,'Enter a name of up to 150 characters and a valid email if used.')
        if not isinstance(password,str) or not 12<=len(password)<=128: raise Problem(400,'Temporary password must be 12–128 characters.')
        identifier=str(uuid.uuid4())
        try: db().execute("INSERT INTO members(id,username,email,name,role,password_hash,created_at) VALUES(?,?,?,?,'enumerator',?,?)",(identifier,username,email,name,password_hash(password),stamp()))
        except sqlite3.IntegrityError: raise Problem(409,'That username already exists.')
        audit('add_enumerator',identifier);db().commit();return jsonify(ok=True),201
    @app.patch('/api/members/<identifier>')
    @authorized(admin=True)
    def update_member(identifier):
        b=data();row=db().execute('SELECT * FROM members WHERE id=?',(identifier,)).fetchone()
        if not row: raise Problem(404,'Enumerator not found.')
        if row['role']=='admin': raise Problem(400,'Use the administrator password command to manage the administrator account.')
        if 'temporaryPassword' in b:
            pw=b['temporaryPassword']
            if not isinstance(pw,str) or not 12<=len(pw)<=128: raise Problem(400,'Temporary password must be 12–128 characters.')
            db().execute('UPDATE members SET password_hash=?,must_change_password=1,auth_version=auth_version+1 WHERE id=?',(password_hash(pw),identifier));audit('reset_password',identifier)
        elif type(b.get('enabled')) is bool:
            db().execute('UPDATE members SET enabled=?,auth_version=auth_version+1 WHERE id=?',(int(b['enabled']),identifier));audit('enable_enumerator' if b['enabled'] else 'disable_enumerator',identifier)
        else: raise Problem(400,'Choose an access or password change.')
        db().commit();return jsonify(ok=True)
    @app.get('/api/records')
    @authorized()
    def get_records():
        team=request.args.get('team')=='1';cursor=request.args.get('cursor','')[:100]
        if team and g.member['role']!='admin': raise Problem(403,'Administrator access required.')
        rows=(db().execute('SELECT id,payload,version,server_updated FROM interviews WHERE id>? ORDER BY id LIMIT 101',(cursor,)) if team else db().execute('SELECT id,payload,version,server_updated FROM interviews WHERE owner_id=? AND id>? ORDER BY id LIMIT 101',(g.member['id'],cursor))).fetchall()
        return jsonify(records=[{'record':json.loads(r['payload']),'version':r['version'],'serverUpdated':r['server_updated']} for r in rows[:100]],nextCursor=rows[99]['id'] if len(rows)>100 else None)
    def validate_record(r):
        if not isinstance(r,dict): raise Problem(400,'Invalid interview.')
        if not isinstance(r.get('id'),str) or not re.fullmatch(r'[a-zA-Z0-9-]{1,100}',r['id']): raise Problem(400,'Invalid interview ID.')
        if r.get('ownerId') and r['ownerId']!=g.member['id']: raise Problem(403,'You can only sync your own interviews.')
        for key in ['code','date','created','updated','consentAt']:
            if not isinstance(r.get(key),str) or len(r[key])>150: raise Problem(400,'Invalid '+key)
        if not r['code'].strip() or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',r['date']): raise Problem(400,'Enter a code and interview date.')
        try: datetime.strptime(r['date'],'%Y-%m-%d')
        except ValueError: raise Problem(400,'Invalid interview date.')
        if r.get('status') not in ['draft','complete'] or r.get('language') not in ['en','bis']: raise Problem(400,'Invalid interview status or language.')
        modules=r.get('modules')
        if not isinstance(modules,list) or len(modules)>8 or any(type(i) is not int or i<11 or i>18 for i in modules) or len(set(modules))!=len(modules): raise Problem(400,'Invalid modules.')
        answers=r.get('answers')
        if not isinstance(answers,dict) or len(answers)>1000: raise Problem(400,'Invalid answers.')
        for key,value in answers.items():
            match=re.fullmatch(r'(s\d+_q\d+)(?:_(other|detail|amount|lat|lng|start|end|duration))?',key)
            if not match or match[1] not in QUESTIONS: raise Problem(400,'Unknown question.')
            q=QUESTIONS[match[1]]
            if match[2]:
                if not isinstance(value,str) or len(value)>10000: raise Problem(400,'Invalid supplemental answer.')
            elif q['options']:
                vals=value if q['type']=='multi' else [value]
                if not isinstance(vals,list) or any(type(v) is not int or not 0<=v<len(q['options']) for v in vals) or len(set(vals))!=len(vals): raise Problem(400,'Invalid response option.')
            else:
                if type(value) not in (str,int,float) or len(str(value))>10000: raise Problem(400,'Invalid response.')
                if q['type']=='number' and value!='':
                    try: number=float(value)
                    except (ValueError,TypeError): raise Problem(400,'Invalid number.')
                    if not number.is_integer() or number<0: raise Problem(400,'Invalid number.')
                    if match[1]=='s9_q4' and not 1<=number<=10: raise Problem(400,'Health rating must be 1–10.')
        if not isinstance(r.get('notes',''),str) or len(r.get('notes',''))>10000: raise Problem(400,'Notes are too long.')
        clean={k:r[k] for k in ['id','code','date','language','modules','consentAt','created','updated','status','answers']};clean.update(ownerId=g.member['id'],enumerator=g.member['name'],notes=r.get('notes',''))
        if r.get('completed'): clean['completed']=str(r['completed'])[:150]
        encoded=json.dumps(clean,separators=(',',':'),sort_keys=True,ensure_ascii=False)
        if len(encoded.encode())>250000: raise Problem(413,'Interview too large.')
        return clean,encoded,hashlib.sha256(encoded.encode()).hexdigest()
    @app.post('/api/sync')
    @authorized()
    def sync():
        items=data().get('records')
        if not isinstance(items,list) or not 1<=len(items)<=3: raise Problem(400,'Sync 1–3 interviews at a time.')
        validated=[]
        for item in items:
            if not isinstance(item,dict) or type(item.get('expectedVersion')) is not int or item['expectedVersion']<0: raise Problem(400,'Invalid sync version.')
            clean,encoded,digest=validate_record(item.get('record'));validated.append((item,clean,encoded,digest))
        results=[];connection=db();connection.execute('BEGIN IMMEDIATE')
        try:
            for item,r,encoded,digest in validated:
                row=connection.execute('SELECT * FROM interviews WHERE id=?',(r['id'],)).fetchone()
                if row and row['owner_id']!=g.member['id']:
                    results.append({'id':r['id'],'status':'blocked','error':'This interview ID belongs to another account.'});continue
                if row and row['content_hash']==digest:
                    results.append({'id':r['id'],'status':'synced','version':row['version']});continue
                if (row['version'] if row else 0)!=item['expectedVersion']:
                    results.append({'id':r['id'],'status':'conflict','version':row['version'] if row else 0,'record':json.loads(row['payload']) if row else None});continue
                version=item['expectedVersion']+1;updated=stamp()
                if row: connection.execute('UPDATE interviews SET payload=?,content_hash=?,version=?,server_updated=? WHERE id=?',(encoded,digest,version,updated,r['id']))
                else: connection.execute('INSERT INTO interviews VALUES(?,?,?,?,?,?)',(r['id'],g.member['id'],encoded,digest,version,updated))
                results.append({'id':r['id'],'status':'synced','version':version,'serverUpdated':updated})
            connection.commit()
        except Exception: connection.rollback();raise
        return jsonify(results=results)
    @app.get('/')
    def index(): return send_from_directory(ROOT/'static','index.html')
    @app.get('/<path:filename>')
    def assets(filename):
        if '/' in filename or filename not in {p.name for p in (ROOT/'static').iterdir() if p.is_file()}: return 'Not found',404
        return send_from_directory(ROOT/'static',filename)
    return app

app=create_app()
