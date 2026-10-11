# Burp Suite Community Edition Testing Guide

## Manual HTTP Inspection & Request Replay for IDOR Analysis

---

## 1. Introduction

PortSwigger **Burp Suite Community Edition** is an industry-standard web penetration testing proxy. This guide provides step-by-step instructions for inspecting, intercepting, and replaying HTTP requests against the **IDOR Virtual Lab**.

> [!NOTE]
> All procedures in this guide require only the free **Community Edition** of Burp Suite. No commercial license or paid extension is needed.

---

## 2. Setup and Prerequisites

1. **Install Burp Suite Community Edition:**
   Download and install from the official PortSwigger website:  
   [https://portswigger.net/burp/communitydownload](https://portswigger.net/burp/communitydownload)
2. **Start the IDOR Lab:**
   ```bash
   docker compose up --build
   ```
   Confirm the application is accessible locally at: `http://localhost:5000`

---

## 3. Configuring Burp Suite

### Method A: Burp's Built-In Chromium Browser (Recommended)
This is the simplest configuration and requires zero manual certificate or proxy configuration:
1. Launch Burp Suite Community Edition.
2. Select **Temporary Project** &rarr; **Use Burp defaults** &rarr; **Start Burp**.
3. Navigate to the **Proxy** tab &rarr; **Intercept** sub-tab.
4. Ensure **Intercept is off** initially so normal page navigation is not blocked.
5. Click the **Open Browser** button.
6. A pre-configured Chromium browser will open. In its address bar, navigate to:
   ```
   http://localhost:5000
   ```

### Method B: External Browser via Proxy
If using your standard browser:
- Proxy host: `127.0.0.1`
- Proxy port: `8080`
- Import the Burp CA certificate from `http://burp/cert` into your browser's certificate authority store.

---

## 4. Capturing Legitimate Document Requests

1. In the Burp-controlled browser, log in as Alice:
   - **Username:** `alice`
   - **Password:** `AliceLab123!`
2. Navigate to the dashboard or request document `101`.
3. Switch back to Burp Suite and select the **Proxy** &rarr; **HTTP history** tab.
4. Look for the HTTP request to:
   ```
   GET /api/documents/101
   ```
5. Inspect the raw request:
   ```http
   GET /api/documents/101 HTTP/1.1
   Host: localhost:5000
   User-Agent: Mozilla/5.0 ...
   Accept: application/json
   Cookie: session=ey...<ALICE_SESSION_TOKEN>
   Connection: close
   ```
6. Inspect the raw server response:
   ```http
   HTTP/1.1 200 OK
   Content-Type: application/json
   Content-Length: ...

   {
     "status": "success",
     "document": {
       "id": 101,
       "owner_id": 1,
       "title": "Alice's Project Notes",
       "content": "Confidential Lab Notes..."
     }
   }
   ```

---

## 5. Replaying Requests in Burp Repeater

1. Right-click the `GET /api/documents/101` request in HTTP History.
2. Select **Send to Repeater** (Keyboard shortcut: `Ctrl + R` on Windows/Linux, `Cmd + R` on macOS).
3. Switch to the **Repeater** tab.

---

## 6. Exploiting IDOR in Vulnerable Mode

### Step 1: Ensure Vulnerable Mode is Active
In the web application UI, click **Switch to Vulnerable Mode** in the header.

### Step 2: Tamper with the Resource Identifier
In Burp Repeater, edit line 1 of the HTTP request, changing `101` to `201` (Bob's document):
```http
GET /api/documents/201 HTTP/1.1
Host: localhost:5000
Cookie: session=ey...<ALICE_SESSION_TOKEN>
Accept: application/json
```

### Step 3: Send the Replayed Request
Click the **Send** button in Burp Repeater.

### Step 4: Analyze the Vulnerable Response
```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: ...

{
  "status": "success",
  "mode": "vulnerable",
  "warning": "VULNERABLE MODE ACTIVE: Server returned resource without validating ownership.",
  "document": {
    "id": 201,
    "owner_id": 2,
    "owner_name": "Bob Martin (Peer Reviewer)",
    "title": "Bob's Private Notes",
    "content": "Bob's Personal Research Journal: Private notes on cryptographic tokens...",
    "classification": "CONFIDENTIAL - RESTRICTED TO BOB"
  },
  "security_analysis": {
    "authenticated_user_id": 1,
    "document_owner_id": 2,
    "ownership_match": false,
    "vulnerability_demonstrated": true
  }
}
```

#### Security Finding:
The HTTP response code is `200 OK`. Bob's confidential research notes were disclosed to Alice. This confirms horizontal privilege escalation via Insecure Direct Object Reference (CWE-634).

---

## 7. Verifying Access Control in Secure Mode

### Step 1: Switch to Secure Mode
In the web application UI, click **Switch to Secure Mode** in the header.

### Step 2: Re-send the Request in Repeater
Without modifying your session cookie or parameters, click **Send** again in Burp Repeater for:
```http
GET /api/documents/201 HTTP/1.1
Host: localhost:5000
Cookie: session=ey...<ALICE_SESSION_TOKEN>
```

### Step 3: Analyze the Secure Response
```http
HTTP/1.1 403 FORBIDDEN
Content-Type: application/json
Date: ...

{
  "error": "Forbidden",
  "message": "Access denied: you do not have permission to view this document.",
  "mode": "secure",
  "security_analysis": {
    "authenticated_user_id": 1,
    "access_control_evaluated": true,
    "authorization_passed": false
  }
}
```

#### Security Finding:
The server returned `HTTP 403 Forbidden` and blocked access to Bob's document. The backend verified Alice's session (`user_id = 1`) against the document's `owner_id = 2`, recognized the unauthorized access attempt, and denied the request.

---

## 8. Summary Comparison Table

| Parameter / Metric | Vulnerable Mode (Mode A) | Secure Mode (Mode B) |
|---|---|---|
| Request Path | `GET /api/documents/201` | `GET /api/documents/201` |
| Authenticated User | Alice (User ID: 1) | Alice (User ID: 1) |
| Resource Owner | Bob (User ID: 2) | Bob (User ID: 2) |
| HTTP Status Code | **200 OK** | **403 Forbidden** |
| Data Disclosed? | **YES** (Confidential leak) | **NO** (Zero data disclosed) |
| Authorization Evaluated | None | Strict Server-Side Check |
