# Threat Fusion
### AI-Powered Cyber Threat Intelligence Aggregation and Analysis Platform
Threat Fusion is a centralized Cyber Threat Intelligence (CTI) platform designed to aggregate, normalize, enrich, analyze, and visualize threat intelligence from multiple public sources. The platform assists Security Operations Centers (SOC) in identifying malicious Indicators of Compromise (IOCs), correlating attack campaigns, prioritizing security incidents, and supporting proactive threat hunting through machine learning and standardized intelligence processing.
The system combines automated threat intelligence collection with artificial intelligence models and an interactive SOC dashboard to reduce analyst workload and accelerate incident response.

# Project Overview
Modern organizations consume threat intelligence from numerous independent sources such as AbuseIPDB, OpenPhish, AlienVault OTX, CISA KEV, and MITRE ATT&CK. These sources often produce inconsistent, duplicated, and unstructured threat data, making manual analysis difficult and time-consuming.

# Objectives
The project aims to:
- Centralize threat intelligence collection
- Eliminate duplicate indicators
- Normalize multiple IOC formats
- Automate enrichment workflows
- Prioritize threats using machine learning
- Assist SOC analysts during investigation
- Support Zero Trust security architecture
- Provide an extensible CTI platform for future integrations

# Core Features

## Threat Intelligence Aggregation
Threat Fusion continuously gathers Indicators of Compromise from multiple threat intelligence sources.
Supported indicator types include:
- IPv4
- IPv6
- Domain names
- URLs
- File Hashes
- Malware Indicators
- CVEs

## STIX 2.1 Normalization
Collected intelligence is converted into standardized STIX 2.1 compliant objects.

Normalization includes:
- IOC standardization
- Type identification
- Timestamp normalization
- Threat metadata generation
- Source attribution
- Confidence scoring

## Threat Enrichment
Each indicator undergoes additional enrichment to improve analyst context.
Enrichment includes:
- Risk scoring
- CVSS information
- MITRE ATT&CK mapping
- Campaign correlation
- IOC confidence calculation
- Source reputation

## Machine Learning Pipeline
Threat Fusion integrates multiple machine learning models for automated analysis.

### Random Forest
Predicts threat severity.
Possible classifications:
- Low
- Medium
- High
- Critical

### XGBoost
Calculates continuous threat risk scores used for alert prioritization.

### Isolation Forest
Detects anomalous user activities from audit logs to identify suspicious behavior.

### DBSCAN
Groups related indicators into threat campaigns without requiring predefined labels.

# Security Architecture
Threat Fusion follows Zero Trust security principles.

Implemented security controls include:
- JWT Authentication
- Role-Based Access Control (RBAC)
- Password Hashing (bcrypt)
- Protected REST APIs
- CORS Configuration
- User Session Validation

Available roles include:
- Administrator
- SOC Analyst
- Read Only Observer

# SOC Dashboard
The web dashboard provides a real-time operational view of threat intelligence.

Available dashboards include:
- Threat Feed
- Dashboard Analytics
- Threat Hunting
- Campaign Graph
- MITRE ATT&CK Dashboard
- CVE Dashboard
- Alerts Management
- User Management
- Reports
- System Settings

Interactive visualizations include:
- Severity Distribution
- IOC Distribution
- Risk Metrics
- Campaign Relationships
- Feed Status
- Alert Statistics

# Technology Stack
## Frontend
- React 19
- TypeScript
- Vite
- Tailwind CSS
- Recharts
- Axios
- React Router
- Lucide Icons

## Backend
- FastAPI
- Python
- Motor
- PyMongo
- Pydantic V2
- JWT Authentication
- bcrypt
- Uvicorn

## Database
- MongoDB
- Docker Compose

## Machine Learning
- Scikit-Learn
- XGBoost
- NumPy
- Pandas

## Threat Intelligence Standards
- STIX 2.1
- MITRE ATT&CK
- CVSS
- Common Vulnerabilities and Exposures (CVE)

# Workflow
1. Collect threat intelligence from multiple feeds.
2. Normalize indicators into STIX 2.1 format.
3. Remove duplicate intelligence.
4. Enrich indicators with contextual metadata.
5. Store processed intelligence in MongoDB.
6. Execute machine learning models.
7. Generate SOC alerts.
8. Visualize intelligence through the dashboard.

# License
This project is intended for educational and research purposes.
