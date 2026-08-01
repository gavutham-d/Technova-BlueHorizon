# Threat Fusion CTI Platform

Threat Fusion is an automated Cyber Threat Intelligence (CTI) Aggregation Platform featuring Zero Trust access control, real-time STIX 2.1 normalization, threat intelligence enrichment, and AI-driven SOC analysis.

## Features
- **Zero Trust Security**: JWT-based session tokens with Least Privilege Role-Based Access Control (RBAC).
- **Log Parsing & STIX Normalization**: Automated extractors parsing Syslog, Firewalls, and SIEM logs into structured STIX 2.1 IOCs.
- **Vulnerability & ATT&CK Enrichment**: Live vulnerability CVSS calculations and MITRE ATT&CK technique matrix mapping.
- **Machine Learning Threat Hunting**:
  - **Random Forest**: Threat severity classification.
  - **XGBoost**: CTI risk rating regression.
  - **Isolation Forest**: User behavior audit log anomaly detection.
  - **DBSCAN**: Concentric threat campaign clustering.
- **Glassmorphic SOC Dashboard**: Cyberpunk UI featuring interactive Recharts visualization and high-performance Campaign relationship graphs.

---

## Technical Stack
- **Database**: MongoDB 6.0 (Docker-based).
- **Backend API**: FastAPI (Python 3.14), Uvicorn, Motor, Pydantic V2, JWT.
- **Frontend Client**: React 19, Vite, TypeScript, Tailwind CSS, Recharts, Axios.

---

## Execution Guide

### Prerequisites
Make sure you have [Docker](https://www.docker.com/) and [Node.js (v18+)](https://nodejs.org/) installed.

### 1. Database (MongoDB) Setup
Launch the MongoDB instance using Docker Compose:
```bash
docker compose up -d
```
This spins up the database container on port `27017` with persistent volumes.

### 2. Backend API Setup
Change to the backend directory, activate the Python virtual environment, and start the FastAPI dev server:
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
- The interactive Swagger docs will be available at: [http://localhost:8000/docs](http://localhost:8000/docs)
- Default credentials created on startup: `admin` / `admin123`

### 3. Frontend Client Setup
Change to the frontend directory, install npm packages, and run the Vite dev server:
```bash
cd frontend
npm install
npm run dev
```
- Open the client portal in your browser at: [http://localhost:5173/](http://localhost:5173/)

### 4. Running Automated Tests
To run the automated Python backend and ML validation test suites:
```bash
cd backend
source venv/bin/activate
python -m pytest
```

---

## Deployment Guide (Production)

### Option A: Dockerized Deployment (Recommended)
You can deploy both the API and MongoDB services in a production container stack. Create a production `docker-compose.prod.yml` or run standard containers behind an Nginx proxy:
1. Build and tag the backend container using standard docker definitions.
2. Serve the built React static assets via Nginx or a CDN (Cloudflare/AWS S3).

### Option B: Bare-Metal / Virtual Private Server (VPS)
1. **Frontend Bundle**:
   Build Vite production assets:
   ```bash
   cd frontend
   npm run build
   ```
   This generates a static bundle in `frontend/dist/`. Serve these static files using Nginx or Caddy.
2. **Backend Daemon (Uvicorn / Gunicorn)**:
   For production environments, run Uvicorn under Gunicorn as a process manager with multiple worker processes:
   ```bash
   gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --daemon
   ```
3. **Database Maintenance**:
   Enable indexing and replication filters in MongoDB config for production scaling.
