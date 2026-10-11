# Render Deployment Guide: IDOR Virtual Lab

This guide explains how to deploy the **IDOR Virtual Lab** to **Render** ([render.com](https://render.com)) for free.

---

## 1. Prerequisites

1. A free account on [Render](https://dashboard.render.com).
2. A free account on [GitHub](https://github.com) (or GitLab).
3. Git installed on your computer.

---

## 2. Step 1: Push Your Code to GitHub

If you have not already pushed your code to GitHub:

### Option A: Push the `idor-virtual-lab` folder as the repository root (Recommended)
Open a terminal inside the `idor-virtual-lab` directory:
```bash
cd idor-virtual-lab
git init
git add .
git commit -m "Initial commit: IDOR Virtual Lab"
git branch -M main
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

### Option B: Push the entire workspace root
If you initialize Git from the parent directory:
```bash
git init
git add .
git commit -m "Initial commit: Student Development Exp with IDOR Lab"
git branch -M main
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

---

## 3. Step 2: Deploy to Render

You can deploy using either **Method 1 (Render Blueprint - Easiest)** or **Method 2 (Manual Web Service)**.

---

### Method 1: Blueprint Deployment (One-Click with `render.yaml`)

Because this repository includes `render.yaml`, Render can configure everything automatically:

1. Log into your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** in the top-right corner and select **Blueprint**.
3. Connect your GitHub account and select your repository.
4. Render will automatically detect `render.yaml` and configure:
   - Runtime: **Python 3.11**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 2 "app:create_app()"`
   - Auto-generated `SECRET_KEY`
5. Click **Apply**.
6. Wait 1–2 minutes for the build to finish. Your lab URL will be `https://<service-name>.onrender.com`.

---

### Method 2: Manual Web Service Setup

If you prefer configuring the Web Service manually via the Render UI:

1. In the Render Dashboard, click **New +** &rarr; **Web Service**.
2. Select **Build and deploy from a Git repository** and connect your repo.
3. Configure the following settings:

| Setting | Value |
|---|---|
| **Name** | `idor-virtual-lab` (or your choice) |
| **Region** | Choose the closest region (e.g., Oregon, Frankfurt, Singapore) |
| **Branch** | `main` |
| **Root Directory** | `idor-virtual-lab` *(Leave blank if you pushed Option A)* |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 2 "app:create_app()"` |
| **Instance Type** | `Free` |

4. Scroll down to **Environment Variables** and add:

| Key | Value | Purpose |
|---|---|---|
| `PYTHON_VERSION` | `3.11.9` | Ensures stable Python 3.11 runtime |
| `SECRET_KEY` | *(Click "Generate" or enter a random string)* | Used for cryptographic session signing |
| `LAB_MODE` | `secure` | Launches in safe default mode |
| `FLASK_ENV` | `production` | Disables debug mode in cloud |

5. Under **Advanced**, you can optionally set:
   - **Health Check Path:** `/api/health`

6. Click **Create Web Service**.

---

## 4. Step 3: Verify Your Live Deployment

1. Once the deploy status turns green (**Live**), click your public service URL (e.g., `https://idor-virtual-lab.onrender.com`).
2. Verify the health endpoint:
   ```
   https://<your-service>.onrender.com/api/health
   ```
   Should return:
   ```json
   {
     "mode": "secure",
     "status": "healthy",
     "timestamp": "..."
   }
   ```
3. Navigate to the login page:
   ```
   https://<your-service>.onrender.com/login
   ```
4. Click **Auto-fill Alice** and click **Authenticate to Lab**.
5. You are now inside the live cloud-hosted IDOR Virtual Lab!

---

## 5. Important Notes on Render Free Tier

1. **Spin Down on Idle:**
   - On the Render Free plan, the web service automatically spins down after 15 minutes of inactivity.
   - When you visit the URL after it spins down, the first request may take 30–50 seconds to boot up.
2. **Ephemeral Disk vs. SQLite:**
   - Free instances use an ephemeral filesystem. When the container spins down or redeploys, SQLite restores to the clean, pre-seeded baseline (`alice` and `bob`).
   - This is actually ideal for disposable educational virtual labs, as each student session gets a clean state.
3. **HTTPS & Secure Cookies:**
   - Render automatically provides an SSL/TLS certificate. The application includes `ProxyFix` middleware and enables `SESSION_COOKIE_SECURE=True` automatically on Render.
