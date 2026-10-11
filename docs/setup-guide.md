# Setup and Deployment Guide

## 1. Overview

The **IDOR Virtual Lab** is designed to run in an isolated, containerized environment using **Docker** and **Docker Compose**, or natively using **Python 3.11+**.

No cloud account, paid API key, or external database is required. The entire environment is self-contained and disposable.

---

## 2. Prerequisites

### Option A: Docker Deployment (Recommended)
- **Docker Engine**: Version 24.0 or higher
- **Docker Compose**: Version 2.20 or higher
- Operating System: Windows (Docker Desktop / WSL2), macOS, or Linux

### Option B: Native Python Deployment (Local Host)
- **Python**: Version 3.11 or 3.12
- **pip**: Python package manager
- **virtualenv** or Python's built-in `venv` module

---

## 3. Quickstart with Docker Compose

### Step 1: Clone or Navigate to the Workspace
```bash
cd idor-virtual-lab
```

### Step 2: Configure Environment Variables (Optional)
The application includes safe defaults out of the box. You may copy `.env.example` to `.env` if custom parameters are required:
```bash
cp .env.example .env
```

### Step 3: Build and Start the Application Container
Execute the build and launch command:
```bash
docker compose up --build
```
*Note for detached background mode:*
```bash
docker compose up --build -d
```

### Step 4: Access the Application
Open your web browser and navigate to:
```
http://localhost:5000
```
or
```
http://127.0.0.1:5000
```

---

## 4. Operational Container Management

### Viewing Real-Time Logs
To follow stdout/stderr logs from the application and WSGI worker processes:
```bash
docker compose logs -f
```

### Checking Container Health Status
The container includes a built-in healthcheck executing against `/api/health`:
```bash
docker compose ps
```

### Stopping the Application
To gracefully terminate the containers while preserving database volume data:
```bash
docker compose down
```

### Resetting Persistent Lab Storage
To cleanly remove containers and the persistent SQLite volume (resetting the database to initial clean seed state):
```bash
docker compose down -v
```

---

## 5. Native Python Setup (Without Docker)

If Docker is not running or you prefer a lightweight local Python execution:

### Step 1: Create and Activate Virtual Environment
On Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On Linux / macOS (Bash):
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Initialize Database (Automatic on Startup)
The database initializes and seeds automatically upon first run. If you wish to manually seed it:
```bash
python -m app.seed
```

### Step 4: Run the Application Server
You can use the automated launcher (which automatically detects if port 5000 is occupied by Docker Desktop and uses port 5001):
```bash
python run.py
```

Or run directly with Python specifying port 5001:
```powershell
python -c "from app import create_app; app = create_app(); app.run(host='127.0.0.1', port=5001, debug=False)"
```

---

## 6. Running Automated Tests

Run the full pytest suite:
```bash
pytest tests -v
```

All 24 automated unit and integration tests will execute, confirming authentication, vulnerable IDOR behavior, secure access control, and the lab validation engine.

---

## 7. Troubleshooting & FAQs

| Symptom | Cause | Resolution |
|---|---|---|
| `Port 5000 is already in use` | Another service is using port 5000 (e.g. AirPlay on macOS). | Change host port mapping in `compose.yaml` (e.g. `"127.0.0.1:5001:5000"`). |
| `Permission denied` on SQLite DB | Docker user permissions issue. | Dockerfile runs as `labuser:labgroup` (UID 1000) and owns `/home/labuser/app/instance`. Run `docker compose down -v` and rebuild. |
| Database changes not reverting | Docker named volume persists across standard restarts. | Run `docker compose down -v` or use the in-app "Reset Lab Data" button. |
| Login sessions reset frequently | Secret key regenerated if not set. | Provide a persistent `SECRET_KEY` in `.env` or `compose.yaml`. |
