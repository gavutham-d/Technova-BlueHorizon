# Prerequisites
Install the following software before running the project:
- Docker Desktop
- Docker Compose
- Python 3.12
- pip
- Node.js 18+
- npm

Clone
```bash
git clone https://github.com/username/Blue-Horizon.git
```

# Running the Project
## 1. Start MongoDB
From the project root
Verify the container
```bash
docker compose up -d
docker ps
```
You should see the MongoDB container running on port **27017**.

## 2. Start the Backend
Navigate to the backend directory:
Create a virtual environment (first time only):
```bash
cd backend
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
Start the FastAPI server:
Backend URL
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
http://localhost:8000
```

Swagger API Documentation
```
http://localhost:8000/docs
```

## 3. Start the Frontend
Open another terminal.
Install dependencies.
Run the development server.
Frontend URL
```bash
cd frontend
npm install
npm run dev
http://localhost:5173
```

# Default Login Credentials
The backend automatically creates the administrator account during initialization.
| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Admin |


# API Documentation
Once the backend is running, interactive API documentation is available at:
```
http://localhost:8000/docs
```

# Database
MongoDB runs inside Docker using Docker Compose. The database is automatically initialized when the container starts.

# Running Tests
Backend tests:
```bash
cd backend
source venv/bin/activate
pytest
```

# Notes
- Ensure Docker is running before starting the backend.
- Start MongoDB before launching the FastAPI server.
- Start the backend before running the frontend.
- The frontend communicates with the backend at `http://localhost:8000/api`.
- MongoDB data is persisted using Docker volumes.
