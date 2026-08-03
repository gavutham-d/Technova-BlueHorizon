# Threat Fusion CTI Platform

Threat Fusion is a Cyber Threat Intelligence (CTI) Aggregation Platform that centralizes threat indicators, performs STIX 2.1 normalization, enriches intelligence with MITRE ATT&CK and CVE information, and provides an interactive SOC dashboard for cybersecurity analysts.

---

## Features

- **Zero Trust Authentication**
  - JWT-based authentication
  - Role-Based Access Control (RBAC)
  - Default administrator account created during application initialization

- **Threat Intelligence Aggregation**
  - Centralized Indicator of Compromise (IOC) management
  - STIX 2.1 normalization
  - MITRE ATT&CK technique mapping
  - CVE and CVSS enrichment

- **Threat Hunting**
  - IOC search and filtering
  - Campaign relationship visualization
  - Threat feed monitoring
  - Interactive SOC dashboard

- **Machine Learning Analysis**
  - Random Forest for threat severity classification
  - XGBoost for CTI risk scoring
  - Isolation Forest for anomaly detection
  - DBSCAN for threat campaign clustering

- **Security Operations Center Dashboard**
  - Real-time analytics
  - Alert management
  - Threat feed status
  - Reports and metrics
  - User management
  - System settings

---

# Technical Stack

| Layer | Technology |
|--------|------------|
| Frontend | React 19, Vite, TypeScript |
| Styling | Tailwind CSS |
| Charts | Recharts |
| HTTP Client | Axios |
| Backend | FastAPI |
| Runtime | Python 3.14 |
| ASGI Server | Uvicorn |
| Validation | Pydantic V2 |
| Authentication | JWT |
| Database | MongoDB 6.0 |
| Database Driver | Motor |
| Containerization | Docker & Docker Compose |

---

# Project Structure

```
ThreatFusion/
│
├── backend/
│   ├── app/
│   ├── requirements.txt
│   └── ...
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── ...
│
├── mongo-init/
│   └── init.js
│
├── docker-compose.yml
└── README.md
```

---

# Prerequisites

Install the following software before running the project:

- Docker Desktop
- Docker Compose
- Python 3.14
- pip
- Node.js 18+
- npm

Verify installation:

```bash
docker --version
docker compose version
python --version
pip --version
node -v
npm -v
```

---

# Running the Project

## 1. Start MongoDB

From the project root:

```bash
docker compose up -d
```

Verify the container:

```bash
docker ps
```

You should see the MongoDB container running on port **27017**.

---

## 2. Start the Backend

Navigate to the backend directory:

```bash
cd backend
```

Create a virtual environment (first time only):

```bash
python -m venv venv
```

Activate it.

Linux / macOS

```bash
source venv/bin/activate
```

Windows

```cmd
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Start the FastAPI server:

```bash
uvicorn app.main:app --reload --port 8000
```

Backend URL

```
http://localhost:8000
```

Swagger API Documentation

```
http://localhost:8000/docs
```

---

## 3. Start the Frontend

Open another terminal.

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Run the development server:

```bash
npm run dev
```

Frontend URL

```
http://localhost:5173
```

---

# Default Login Credentials

The backend automatically creates the administrator account during initialization.

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |

---

# API Documentation

Once the backend is running, interactive API documentation is available at:

```
http://localhost:8000/docs
```

---

# Database

MongoDB runs inside Docker using Docker Compose.

The database is automatically initialized when the container starts.

Database documentation, schema, ER diagrams, and sample datasets are available in the repository's top-level **Database/** directory.

---

# Running Tests

Backend tests:

```bash
cd backend

source venv/bin/activate

pytest
```

---

# Notes

- Ensure Docker is running before starting the backend.
- Start MongoDB before launching the FastAPI server.
- Start the backend before running the frontend.
- The frontend communicates with the backend at `http://localhost:8000/api`.
- MongoDB data is persisted using Docker volumes.
