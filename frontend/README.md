# AI Security Analyst Dashboard

React + TypeScript + Vite dashboard for the AI Security Analyst backend.

## Included views

- **Overview** — event/threat totals, severity summary, recent threats, source statistics.
- **Events** — normalized event stream from `GET /api/v1/events`.
- **Threats** — deterministic threat findings with risk score, MITRE ATT&CK mapping, and evidence timeline.
- **Ingestion** — JSON/CSV/LOG/TXT batch ingestion plus optional API-key storage.
- **Demo workflow** — synthetic brute-force and port-scan events can be loaded and analyzed with one button.

## Dev Container

When the repository is opened with the provided VS Code Dev Container, the dashboard starts automatically at:

```text
http://localhost:5173
```

The Vite proxy sends API requests to the FastAPI service at `http://api:8000` inside Docker Compose.

## Standalone local development

Start the backend on port 8000, then:

```bash
cd frontend
npm install
npm run dev
```

Vite will proxy `/api` and `/health` to `http://127.0.0.1:8000`.
