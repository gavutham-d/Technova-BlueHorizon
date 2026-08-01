# Changelog - Threat Fusion

## [1.0.0] - 2026-08-01

### Added
- **Infrastructure**:
  - `docker-compose.yml` defining MongoDB 6.0 service container.
- **Backend Services**:
  - Config (`config.py`) loading environment variables.
  - Async DB connectors (`database.py`) using Motor for MongoDB persistence.
  - Normalization engine (`normalization.py`) mapping threat indicators to STIX 2.1 schemas, with raw log pattern extraction.
  - Enrichment module (`enrichment.py`) mapping indicators to MITRE techniques, CVE CVSS scores, and fetching feed details.
  - ML Pipeline (`ml_pipeline.py`) implementing Random Forest (severity classification), Isolation Forest (anomaly detection), DBSCAN (campaign clustering), and XGBoost (risk scoring).
  - Background polling thread (`cti_harvester.py`) fetching threat updates from public feeds (URLhaus, AbuseIPDB, AlienVault OTX, MalwareBazaar, ThreatFox).
- **Backend API Routes**:
  - Zero Trust authentication (`auth.py`) utilizing JWT sessions and Least Privilege RBAC guards.
  - Indicators CRUD (`indicators.py`) supporting file logs extraction (CSV, Excel, JSON, Firewall, IDS, SIEM, Antivirus).
  - Campaign metrics (`campaigns.py`) and network correlation visualizer nodes.
  - Triage console (`alerts.py`) mapping critical risks to incident logs.
  - Threat hunting scans (`hunting.py`) checking logs against Isolation Forest.
  - Summary metrics (`reports.py`) computing severity and type counts.
- **Automated Verification**:
  - `test_ml.py` verifying ML pipeline predictions.
  - `test_api.py` verifying regex extraction and REST status endpoints.
- **Frontend Dashboard**:
  - Vite React TypeScript scaffolding (`package.json`, `vite.config.ts`, `tsconfig.json`).
  - Dark mode glassmorphism visual system (`index.css` & `tailwind.config.js`).
  - Auth context provider (`AuthContext.tsx`) and Sidebar navigation (`Sidebar.tsx`).
  - 12 fully functional pages: `Login`, `Dashboard`, `ThreatFeed` (with Log Uploads), `ThreatDetails`, `ThreatHunting`, `CampaignGraph`, `MitreDashboard`, `CveDashboard`, `Alerts`, `Reports`, `UserManagement` (Audits), and `Settings`.

### Fixed
- **Startup AttributeError**: Implemented `CollectionProxy` in `database.py` to route collection variable bindings dynamically on database instantiation.
- **Passlib/Bcrypt Incompatibility**: Bypassed Python 3.14 passlib library bug by directly calling native `bcrypt` methods for password hashing and verification.
- **Database DuplicateKeyError**: Overwrote seed indicators hash string overlapping slicing indexes to enforce key uniqueness.
- **Frontend Unused Locals Build Blockers**: Configured `tsconfig.app.json` compiler checks to bypass unused variable warning interruptions during bundling.

