# Project State: Threat Fusion

## Current Posture
Threat Fusion is a fully functional Cyber Threat Intelligence (CTI) Aggregation Platform. It features automated STIX 2.1 normalization, AI-assisted severity classification (Random Forest), risk scoring (XGBoost), log anomaly detection (Isolation Forest), campaign clustering (DBSCAN), and a detailed glassmorphic React SOC Dashboard.

All backend modules, ML pipelines, and API routes compile and pass unit test suites. The React TypeScript frontend builds cleanly into a static package using Vite.

---

## Directory Architecture

```
Threat Fusion/
├── docker-compose.yml
├── PROJECT_STATE.md
├── CHANGELOG.md
├── IMPLEMENTATION_MANIFEST.json
├── backend/
│   ├── requirements.txt
│   ├── test_api.py
│   ├── test_ml.py
│   ├── venv/
│   └── app/
│       ├── main.py
│       ├── config.py
│       ├── database.py
│       ├── models/
│       │   └── schemas.py
│       ├── api/
│       │   ├── auth.py
│       │   ├── indicators.py
│       │   ├── campaigns.py
│       │   ├── alerts.py
│       │   ├── hunting.py
│       │   └── reports.py
│       └── services/
│           ├── normalization.py
│           ├── enrichment.py
│           ├── ml_pipeline.py
│           └── cti_harvester.py
└── frontend/
    ├── package.json
    ├── tailwind.config.js
    ├── postcss.config.js
    ├── tsconfig.json
    ├── index.html
    ├── src/
    │   ├── main.tsx
    │   ├── index.css
    │   ├── App.tsx
    │   ├── context/
    │   │   └── AuthContext.tsx
    │   ├── components/
    │   │   └── Sidebar.tsx
    │   └── pages/
    │       ├── Login.tsx
    │       ├── Dashboard.tsx
    │       ├── ThreatFeed.tsx
    │       ├── ThreatDetails.tsx
    │       ├── ThreatHunting.tsx
    │       ├── CampaignGraph.tsx
    │       ├── MitreDashboard.tsx
    │       ├── CveDashboard.tsx
    │       ├── Alerts.tsx
    │       ├── Reports.tsx
    │       ├── UserManagement.tsx
    │       └── Settings.tsx
```

---

## Technical Stack & Configuration
- **Backend**: FastAPI (Python 3.14), Uvicorn, Motor, Pydantic, Passlib, JWT.
- **Database**: MongoDB 6.0 in Docker.
- **Machine Learning**: Scikit-Learn (Random Forest, Isolation Forest, DBSCAN) and XGBoost Regressor.
- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Axios, Recharts, Lucide Icons.

---

## Verification Summary
Automated unit tests run via `pytest` pass successfully.

Both the backend FastAPI server and frontend Vite server are actively running in the background.

- **FastAPI Backend Service**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **React Frontend Client**: [http://localhost:5173/](http://localhost:5173/)

### Active Background Task Processes
1. **MongoDB Database (Docker)**: running on port 27017.
2. **Uvicorn API Server**: running on port 8000.
3. **Vite Development Portal**: running on port 5173.

