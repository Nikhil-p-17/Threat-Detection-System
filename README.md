# SentinelShield Threat Detection System

A full-stack defensive cybersecurity application for URL, phishing, email/message, and threat-intelligence analysis.

## Stack
- Backend: Python, FastAPI, SQLAlchemy, Pydantic
- Frontend: React + Vite
- Database: SQLite by default
- Reports: ReportLab PDF
- Optional threat intelligence: VirusTotal-compatible URL reputation adapter, DNS/WHOIS/SSL adapters can be added via environment variables

## Safety model
The default scanners perform **non-invasive analysis**. They do not submit credentials, exploit targets, crawl websites, or execute attachments. URL scanning analyzes the supplied URL string and domain metadata. External reputation lookups are optional.

## Run locally

### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

## Optional environment variables
Create `backend/.env` from `.env.example`.

- `VIRUSTOTAL_API_KEY` enables optional URL reputation lookup.
- `CORS_ORIGINS` defaults to `http://localhost:5173`.

## Project structure
```text
backend/
  app/
    main.py
    database.py
    models.py
    schemas.py
    risk_engine.py
    analyzers/
      url_analyzer.py
      text_analyzer.py
    services/
      threat_intel.py
      reports.py
frontend/
  src/
    App.jsx
    api.js
    main.jsx
    styles.css
```
# Threat-Detection-System
