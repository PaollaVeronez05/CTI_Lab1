# CTI Purple Security Lab (protótipo – Fase 2)

## Rodar
    python -m venv .venv
    .venv\Scripts\activate.bat      # Windows CMD  (Linux/Mac: source .venv/bin/activate)
    pip install -r requirements.txt
    python app.py
Acesse http://127.0.0.1:5000  |  Mentor de teste: mentor@cti.local / mentor123 (troque depois!)

## Ambientes isolados (Fase 2)
Requer o Docker Desktop aberto. No desafio "Intranet esquecida", o participante clica em
"Iniciar ambiente": o orquestrador (orchestrator.py) sobe um container próprio, com flag única,
acessível só em 127.0.0.1, e o derruba ao encerrar ou após 60 minutos.
Mentores acompanham e encerram ambientes em /ambientes.
