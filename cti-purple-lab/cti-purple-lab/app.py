import base64, hashlib, os, secrets, sqlite3, threading, time
from functools import wraps
from flask import Flask, g, render_template, request, redirect, session, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
import orchestrator as orch

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-troque-esta-chave")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'participante', team TEXT);
CREATE TABLE IF NOT EXISTS challenges(id INTEGER PRIMARY KEY, title TEXT, category TEXT, side TEXT, points INTEGER, description TEXT, hint TEXT, url TEXT, flag_hash TEXT);
CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY, user_id INTEGER, challenge_id INTEGER, correct INTEGER, created_at INTEGER);
CREATE TABLE IF NOT EXISTS instances(id INTEGER PRIMARY KEY, user_id INTEGER, challenge_id INTEGER, container TEXT, port INTEGER, flag_hash TEXT, started_at INTEGER, expires_at INTEGER, active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS starts(user_id INTEGER, challenge_id INTEGER, started_at INTEGER, PRIMARY KEY(user_id, challenge_id));
CREATE TABLE IF NOT EXISTS evaluations(id INTEGER PRIMARY KEY, user_id INTEGER, mentor_id INTEGER, logica INTEGER, comunicacao INTEGER, colaboracao INTEGER, decisao INTEGER, notes TEXT, created_at INTEGER);
"""

LOG = """10.0.0.5 - login falhou - usuario=maria
192.168.56.23 - login falhou - usuario=admin
192.168.56.23 - login falhou - usuario=root
10.0.0.8 - login ok - usuario=joao
192.168.56.23 - login falhou - usuario=admin
172.16.0.4 - login falhou - usuario=ana
192.168.56.23 - login falhou - usuario=teste"""

# (titulo, categoria, lado, pontos, descricao, dica, url, flag)
SEED = [
    ("Boas-vindas", "Geral", "Aquecimento", 50,
     "Sua primeira flag: CTF{bem_vindo_ao_purple_lab}. Copie e envie abaixo.", "Copie e cole.", "",
     "CTF{bem_vindo_ao_purple_lab}"),
    ("Intranet esquecida", "Web", "Red Team", 100,
     "Suba o container deste desafio (veja o README) e acesse a intranet. Existe um arquivo que os robôs de busca "
     "foram instruídos a ignorar. Encontre a flag.", "Todo site pode ter um /robots.txt.", "http://localhost:5001",
     "CTF{robots_txt_entrega_segredos}"),
    ("Texto estranho", "Criptografia", "Red Team", 100,
     "Interceptamos esta mensagem: " + base64.b64encode(b"CTF{base64_nao_e_criptografia}").decode()
     + "\nDecodifique-a para obter a flag.", "Isso é uma codificação, não uma cifra.", "",
     "CTF{base64_nao_e_criptografia}"),
    ("Quem está atacando?", "Análise de logs", "Blue Team", 150,
     "O servidor registrou os logs abaixo. Identifique o IP com mais falhas de login e envie a flag no formato "
     "CTF{ip}.\n\n" + LOG, "Conte as linhas 'login falhou' por IP.", "", "CTF{192.168.56.23}"),
]

def h(flag):
    return hashlib.sha256(flag.strip().encode()).hexdigest()

def init_db():
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    if not con.execute("SELECT 1 FROM users").fetchone():
        con.execute("INSERT INTO users(name,email,password,role,team) VALUES(?,?,?,?,?)",
                    ("Mentor", "mentor@cti.local", generate_password_hash("mentor123"), "mentor", "Mentoria"))
    if not con.execute("SELECT 1 FROM challenges").fetchone():
        for t, c, s, p, d, hint, url, flag in SEED:
            con.execute("INSERT INTO challenges(title,category,side,points,description,hint,url,flag_hash) VALUES(?,?,?,?,?,?,?,?)",
                        (t, c, s, p, d, hint, url, h(flag)))
    cols = {r[1] for r in con.execute("PRAGMA table_info(challenges)")}
    for col, typ in (("image", "TEXT"), ("container_port", "INTEGER")):
        if col not in cols:
            con.execute(f"ALTER TABLE challenges ADD COLUMN {col} {typ}")
    con.execute("UPDATE challenges SET image='cti-lab/web-01', container_port=5000, url='', description=? "
                "WHERE title='Intranet esquecida' AND image IS NULL",
                ("Clique em 'Iniciar ambiente' para criar a sua intranet isolada e acesse o endereço mostrado. "
                 "Existe um arquivo que os robôs de busca foram instruídos a ignorar. Encontre a flag.",))
    con.execute("UPDATE instances SET active=0 WHERE active=1")
    con.commit(); con.close()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user_id" not in session:
            return redirect("/login")
        return f(*a, **k)
    return w

def mentor_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if session.get("role") != "mentor":
            abort(403)
        return f(*a, **k)
    return w

@app.route("/")
def index():
    return redirect("/challenges" if "user_id" in session else "/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        try:
            db().execute("INSERT INTO users(name,email,password,team) VALUES(?,?,?,?)",
                         (f["name"].strip(), f["email"].strip().lower(),
                          generate_password_hash(f["password"]), f.get("team", "").strip() or "Sem equipe"))
            db().commit()
            flash("Conta criada! Faça login.")
            return redirect("/login")
        except sqlite3.IntegrityError:
            flash("Este e-mail já está cadastrado.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = db().execute("SELECT * FROM users WHERE email=?", (request.form["email"].strip().lower(),)).fetchone()
        if u and check_password_hash(u["password"], request.form["password"]):
            session.clear()
            session.update(user_id=u["id"], name=u["name"], role=u["role"])
            return redirect("/")
        flash("E-mail ou senha inválidos.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/challenges")
@login_required
def challenges():
    d = db()
    solved = {r[0] for r in d.execute("SELECT challenge_id FROM attempts WHERE user_id=? AND correct=1", (session["user_id"],))}
    return render_template("challenges.html", items=d.execute("SELECT * FROM challenges ORDER BY id").fetchall(), solved=solved)

TTL = 60 * 60       # duração de cada ambiente: 60 minutos
MAX_ACTIVE = 10     # máximo de containers ao mesmo tempo
MAX_PER_USER = 2    # máximo por participante

def reap_expired():
    con = sqlite3.connect(DB)
    now = int(time.time())
    for (name,) in con.execute("SELECT container FROM instances WHERE active=1 AND expires_at<?", (now,)).fetchall():
        orch.stop(name)
    con.execute("UPDATE instances SET active=0 WHERE active=1 AND expires_at<?", (now,))
    con.commit(); con.close()

def reaper_loop():
    while True:
        time.sleep(60)
        try:
            reap_expired()
        except Exception:
            pass

def active_instance(d, uid, cid):
    return d.execute("SELECT * FROM instances WHERE user_id=? AND challenge_id=? AND active=1 AND expires_at>=?",
                     (uid, cid, int(time.time()))).fetchone()

def stop_instance(d, row):
    orch.stop(row["container"])
    d.execute("UPDATE instances SET active=0 WHERE id=?", (row["id"],))
    d.commit()

@app.route("/challenge/<int:cid>", methods=["GET", "POST"])
@login_required
def challenge(cid):
    d, uid = db(), session["user_id"]
    c = d.execute("SELECT * FROM challenges WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    d.execute("INSERT OR IGNORE INTO starts VALUES(?,?,?)", (uid, cid, int(time.time())))
    d.commit()
    solved = d.execute("SELECT 1 FROM attempts WHERE user_id=? AND challenge_id=? AND correct=1", (uid, cid)).fetchone() is not None
    if request.method == "POST" and not solved:
        flag = request.form.get("flag", "")
        if c["image"]:   # desafio com ambiente: a flag é única por participante
            hashes = [r[0] for r in d.execute("SELECT flag_hash FROM instances WHERE user_id=? AND challenge_id=?", (uid, cid))]
            if not hashes:
                flash("Inicie o seu ambiente antes de enviar a flag.")
                return redirect(f"/challenge/{cid}")
            ok = h(flag) in hashes
        else:
            ok = h(flag) == c["flag_hash"]
        d.execute("INSERT INTO attempts(user_id,challenge_id,correct,created_at) VALUES(?,?,?,?)", (uid, cid, int(ok), int(time.time())))
        d.commit()
        flash("Flag correta! 🎉" if ok else "Flag incorreta. Tente de novo.")
        return redirect(f"/challenge/{cid}")
    inst = active_instance(d, uid, cid) if c["image"] else None
    return render_template("challenge.html", c=c, solved=solved, inst=inst, now=int(time.time()))

@app.route("/challenge/<int:cid>/start", methods=["POST"])
@login_required
def start_env(cid):
    d, uid = db(), session["user_id"]
    c = d.execute("SELECT * FROM challenges WHERE id=?", (cid,)).fetchone()
    if not c or not c["image"]:
        abort(404)
    reap_expired()
    back = redirect(f"/challenge/{cid}")
    if active_instance(d, uid, cid):
        return back
    if d.execute("SELECT COUNT(*) FROM instances WHERE active=1").fetchone()[0] >= MAX_ACTIVE:
        flash("O laboratório está cheio no momento. Tente novamente em alguns minutos.")
        return back
    if d.execute("SELECT COUNT(*) FROM instances WHERE user_id=? AND active=1", (uid,)).fetchone()[0] >= MAX_PER_USER:
        flash(f"Você já tem {MAX_PER_USER} ambientes ativos. Encerre um antes de iniciar outro.")
        return back
    flag = "CTF{" + secrets.token_hex(8) + "}"
    name = f"lab-u{uid}-c{cid}-{secrets.token_hex(3)}"
    try:
        port = orch.start(name, c["image"], c["container_port"], flag)
    except orch.DockerError as e:
        flash(f"Não foi possível iniciar o ambiente: {e}")
        return back
    now = int(time.time())
    d.execute("INSERT INTO instances(user_id,challenge_id,container,port,flag_hash,started_at,expires_at,active) VALUES(?,?,?,?,?,?,?,1)",
              (uid, cid, name, port, h(flag), now, now + TTL))
    d.commit()
    flash(f"Ambiente iniciado! Ele expira em {TTL // 60} minutos.")
    return back

@app.route("/challenge/<int:cid>/stop", methods=["POST"])
@login_required
def stop_env(cid):
    d = db()
    row = d.execute("SELECT * FROM instances WHERE user_id=? AND challenge_id=? AND active=1", (session["user_id"], cid)).fetchone()
    if row:
        stop_instance(d, row)
        flash("Ambiente encerrado.")
    return redirect(f"/challenge/{cid}")

@app.route("/ambientes")
@mentor_required
def ambientes():
    reap_expired()
    rows = db().execute("""SELECT i.*, u.name uname, c.title FROM instances i
                           JOIN users u ON u.id=i.user_id JOIN challenges c ON c.id=i.challenge_id
                           WHERE i.active=1 ORDER BY i.id""").fetchall()
    return render_template("ambientes.html", rows=rows, now=int(time.time()), max=MAX_ACTIVE)

@app.route("/ambientes/<int:iid>/encerrar", methods=["POST"])
@mentor_required
def encerrar_ambiente(iid):
    d = db()
    row = d.execute("SELECT * FROM instances WHERE id=? AND active=1", (iid,)).fetchone()
    if row:
        stop_instance(d, row)
    return redirect("/ambientes")

@app.route("/ambientes/encerrar-todos", methods=["POST"])
@mentor_required
def encerrar_todos():
    d = db()
    for row in d.execute("SELECT * FROM instances WHERE active=1").fetchall():
        stop_instance(d, row)
    flash("Todos os ambientes foram encerrados.")
    return redirect("/ambientes")

def stats():
    d = db()
    rows = []
    for u in d.execute("SELECT * FROM users WHERE role='participante'").fetchall():
        solved = d.execute("""SELECT c.id cid, c.points, MIN(a.created_at) t FROM attempts a
                              JOIN challenges c ON c.id=a.challenge_id
                              WHERE a.user_id=? AND a.correct=1 GROUP BY c.id""", (u["id"],)).fetchall()
        attempts = d.execute("SELECT COUNT(*) FROM attempts WHERE user_id=?", (u["id"],)).fetchone()[0]
        times = []
        for s in solved:
            st = d.execute("SELECT started_at FROM starts WHERE user_id=? AND challenge_id=?", (u["id"], s["cid"])).fetchone()
            if st:
                times.append(s["t"] - st["started_at"])
        rating = d.execute("SELECT AVG((logica+comunicacao+colaboracao+decisao)/4.0) FROM evaluations WHERE user_id=?", (u["id"],)).fetchone()[0]
        rows.append(dict(id=u["id"], name=u["name"], team=u["team"], solved=len(solved),
                         points=sum(s["points"] for s in solved), attempts=attempts,
                         avg_min=round(sum(times) / len(times) / 60, 1) if times else None,
                         rating=round(rating, 1) if rating else None))
    return sorted(rows, key=lambda r: -r["points"])

@app.route("/dashboard")
@mentor_required
def dashboard():
    rows = stats()
    teams = {}
    for r in rows:
        t = teams.setdefault(r["team"], dict(team=r["team"], members=0, solved=0, points=0, attempts=0))
        t["members"] += 1
        for k in ("solved", "points", "attempts"):
            t[k] += r[k]
    total = db().execute("SELECT COUNT(*) FROM challenges").fetchone()[0]
    return render_template("dashboard.html", rows=rows, teams=sorted(teams.values(), key=lambda t: -t["points"]), total=total)

@app.route("/participante/<int:uid>", methods=["GET", "POST"])
@mentor_required
def participante(uid):
    d = db()
    u = d.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    if request.method == "POST":
        v = [min(5, max(1, int(request.form.get(k) or 3))) for k in ("logica", "comunicacao", "colaboracao", "decisao")]
        d.execute("INSERT INTO evaluations(user_id,mentor_id,logica,comunicacao,colaboracao,decisao,notes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                  (uid, session["user_id"], *v, request.form.get("notes", ""), int(time.time())))
        d.commit()
        flash("Avaliação registrada.")
        return redirect(f"/participante/{uid}")
    attempts = d.execute("""SELECT c.title, a.correct, a.created_at FROM attempts a JOIN challenges c ON c.id=a.challenge_id
                            WHERE a.user_id=? ORDER BY a.id DESC""", (uid,)).fetchall()
    evals = d.execute("SELECT * FROM evaluations WHERE user_id=? ORDER BY id DESC", (uid,)).fetchall()
    return render_template("participante.html", u=u, attempts=attempts, evals=evals,
                           s=next((r for r in stats() if r["id"] == uid), None), fmt=lambda t: time.strftime("%d/%m %H:%M", time.localtime(t)))

if __name__ == "__main__":
    init_db()
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":   # processo filho do modo debug
        try:
            orch.cleanup_all()   # remove containers que sobraram da última execução
        except Exception:
            pass
        threading.Thread(target=reaper_loop, daemon=True).start()
    app.run(debug=True)
