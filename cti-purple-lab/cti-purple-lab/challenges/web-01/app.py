import os
from flask import Flask, Response

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "CTF{teste_local}")   # cada participante recebe uma flag diferente

@app.route("/")
def index():
    return "<h1>Intranet CTI</h1><p>Nada de interessante por aqui... ou será?</p>"

@app.route("/robots.txt")
def robots():
    return Response("User-agent: *\nDisallow: /backup-interno\n", mimetype="text/plain")

@app.route("/backup-interno")
def backup():
    return f"FLAG: {FLAG}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
