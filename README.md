# Quick Start

Clone

```bash
git clone https://github.com/username/Blue-Horizon.git
```

Go into project

```bash
cd Blue-Horizon/ThreatFusion
```

Start MongoDB

```bash
docker compose up -d
```

Backend

```bash
cd backend

python -m venv venv

source venv/bin/activate

pip install -r requirements.txt

uvicorn app.main:app --reload
```

Frontend

```bash
cd frontend

npm install

npm run dev
```

Open

```
http://localhost:5173
```

Login

```
admin
admin123
```
