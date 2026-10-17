from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timezone
import sqlite3, os, json, re, secrets

BASE = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE') == '1', MAX_CONTENT_LENGTH=256 * 1024)
DB = os.environ.get('DATABASE_PATH', os.path.join(BASE, 'centralsoc.db'))

def db():
    con = sqlite3.connect(DB); con.row_factory = sqlite3.Row; return con

def init_db():
    con = db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst');
    CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, title TEXT NOT NULL, source TEXT, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'new', score INTEGER NOT NULL, details TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', owner TEXT, description TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS memories(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, evidence TEXT, author TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT, action TEXT NOT NULL, target TEXT, created_at TEXT NOT NULL);
    ''')
    if not con.execute('SELECT 1 FROM users').fetchone():
        admin_password = os.environ.get('ADMIN_PASSWORD')
        if not admin_password:
            raise RuntimeError('Set ADMIN_PASSWORD before initializing a new database.')
        con.execute('INSERT INTO users(username,password,role) VALUES(?,?,?)', ('admin', generate_password_hash(admin_password), 'admin'))
        now=datetime.now(timezone.utc).isoformat()
        alerts=[('Échecs SSH répétés','185.220.101.14','critical','investigating',96,'47 échecs de connexion en 5 minutes sur srv-prod-01'),('Connexion impossible depuis un pays inhabituel','10.20.4.18','high','new',82,'Connexion au compte admin depuis une zone inhabituelle'),('Balayage de ports détecté','172.16.10.8','medium','new',61,'32 ports sondés sur 4 hôtes internes'),('Modifications sudo inattendues','10.20.1.33','low','resolved',28,'Élévation de privilèges autorisée et documentée'),('Exécution PowerShell encodée','10.20.7.21','high','investigating',88,'Commande encodée exécutée sur WS-FIN-12')]
        for a in alerts: con.execute('INSERT INTO alerts(title,source,severity,status,score,details,created_at) VALUES(?,?,?,?,?,?,?)',(*a,now))
        incidents=[('Activité SSH suspecte sur srv-prod-01','critical','open','Équipe SOC','Corréler les tentatives et vérifier les clés autorisées.'),('Investigation poste WS-FIN-12','high','investigating','A. Diallo','Analyser la commande PowerShell et préserver les journaux.')]
        for i in incidents: con.execute('INSERT INTO incidents(title,severity,status,owner,description,created_at) VALUES(?,?,?,?,?,?)',(*i,now))
        memories=[('Brute force SSH — indicateurs récurrents','Seuil utile : plus de 20 échecs en 5 minutes. Vérifier auth.log et les connexions réussies après la rafale.','IP source, horodatages UTC, extrait auth.log','A. Diallo'),('PowerShell encodé — triage initial','Décoder hors ligne dans un environnement isolé. Vérifier parent process, utilisateur et connexions réseau.','SHA-256 du script, arbre des processus','M. Chen')]
        for m in memories: con.execute('INSERT INTO memories(title,body,evidence,author,created_at) VALUES(?,?,?,?,?)',(*m,now))
    con.commit(); con.close()

def audit(action,target=''):
    con=db(); con.execute('INSERT INTO audit(actor,action,target,created_at) VALUES(?,?,?,?)',(session.get('user','anonymous'),action,target,datetime.now(timezone.utc).isoformat())); con.commit(); con.close()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if not session.get('user'): return jsonify({'error':'Authentification requise'}),401
        return fn(*args,**kwargs)
    return wrapper

@app.get('/')
def home(): return render_template('index.html')
@app.post('/api/login')
def login():
    data=request.get_json(silent=True) or {}; con=db(); user=con.execute('SELECT * FROM users WHERE username=?',(data.get('username',''),)).fetchone(); con.close()
    if not user or not check_password_hash(user['password'],data.get('password','')): audit('login_failed',data.get('username','')); return jsonify({'error':'Identifiants incorrects'}),401
    session['user']=user['username']; session['role']=user['role']; audit('login_success'); return jsonify({'user':user['username'],'role':user['role']})
@app.post('/api/logout')
def logout(): audit('logout'); session.clear(); return jsonify({'ok':True})
@app.get('/api/me')
def me(): return jsonify({'user':session.get('user'),'role':session.get('role')})
@app.get('/api/dashboard')
@login_required
def dashboard():
    con=db(); alerts=[dict(x) for x in con.execute('SELECT * FROM alerts ORDER BY id DESC')]; incidents=[dict(x) for x in con.execute('SELECT * FROM incidents ORDER BY id DESC')]; memories=[dict(x) for x in con.execute('SELECT * FROM memories ORDER BY id DESC')]; auditlog=[dict(x) for x in con.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 8')]; con.close()
    return jsonify({'alerts':alerts,'incidents':incidents,'memories':memories,'audit':auditlog,'stats':{'alerts':len(alerts),'critical':sum(a['severity']=='critical' for a in alerts if a['status']!='resolved'),'incidents':sum(i['status']!='closed' for i in incidents),'memories':len(memories)}})
@app.post('/api/alerts/<int:alert_id>/status')
@login_required
def alert_status(alert_id):
    status=(request.get_json(silent=True) or {}).get('status');
    if status not in ('new','investigating','resolved'): return jsonify({'error':'Statut invalide'}),400
    con=db(); cur=con.execute('UPDATE alerts SET status=? WHERE id=?',(status,alert_id)); con.commit(); con.close()
    if not cur.rowcount: return jsonify({'error':'Alerte introuvable'}),404
    audit('alert_status_changed',f'{alert_id}:{status}'); return jsonify({'ok':True})
@app.post('/api/incidents')
@login_required
def create_incident():
    d=request.get_json(silent=True) or {}; title=(d.get('title') or '').strip()
    if len(title)<4: return jsonify({'error':'Le titre doit contenir au moins 4 caractères'}),400
    con=db(); con.execute('INSERT INTO incidents(title,severity,status,owner,description,created_at) VALUES(?,?,?,?,?,?)',(title,d.get('severity','medium'),'open',session['user'],(d.get('description') or '').strip(),datetime.now(timezone.utc).isoformat())); con.commit(); con.close(); audit('incident_created',title); return jsonify({'ok':True}),201
@app.post('/api/memories')
@login_required
def create_memory():
    d=request.get_json(silent=True) or {}; title=(d.get('title') or '').strip(); body=(d.get('body') or '').strip()
    if len(title)<4 or len(body)<10: return jsonify({'error':'Ajoutez un titre et une note d’au moins 10 caractères'}),400
    con=db(); con.execute('INSERT INTO memories(title,body,evidence,author,created_at) VALUES(?,?,?,?,?)',(title,body,(d.get('evidence') or '').strip(),session['user'],datetime.now(timezone.utc).isoformat())); con.commit(); con.close(); audit('memory_created',title); return jsonify({'ok':True}),201
@app.post('/api/analyze')
@login_required
def analyze():
    text=(request.get_json(silent=True) or {}).get('text','')[:200000]; lines=[x for x in text.splitlines() if x.strip()]; findings=[]
    patterns=[('Échecs d’authentification',r'failed password|authentication failure|login failed',8),('Élévation de privilèges',r'sudo|privilege escalation|runas',5),('Activité PowerShell',r'powershell|encodedcommand',7),('Trafic refusé',r'blocked|denied|drop',2),('Requête web suspecte',r'\.\./|union select|<script|cmd\.exe',9)]
    for name,pattern,weight in patterns:
        count=sum(bool(re.search(pattern,line,re.I)) for line in lines)
        if count: findings.append({'name':name,'count':count,'score':min(100,count*weight)})
    total=min(100,sum(x['score'] for x in findings)); audit('logs_analyzed',f'{len(lines)} lignes'); return jsonify({'lines':len(lines),'findings':findings,'score':total,'level':'critique' if total>=70 else 'élevé' if total>=40 else 'modéré' if total else 'faible'})
@app.get('/health')
def health(): return jsonify({'status':'ok'})
init_db()
if __name__=='__main__': app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=os.environ.get('FLASK_DEBUG')=='1')

