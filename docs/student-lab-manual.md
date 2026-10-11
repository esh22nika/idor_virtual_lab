# Student Lab Manual: Insecure Direct Object References (IDOR)

## Web Application Security Experiment

---

## 1. Experiment Overview

- **Topic:** Broken Access Control / Insecure Direct Object References (IDOR)
- **CWE:** [CWE-634: Improper Restriction of Object References](https://cwe.mitre.org/data/definitions/634.html), [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- **OWASP Category:** OWASP Top 10:2021 [A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- **Estimated Completion Time:** 45 - 60 minutes
- **Environment:** Containerized Local Educational Lab (`http://localhost:5000`)

### Learning Objectives
By completing this virtual lab experiment, students will be able to:
1. Explain how web applications use resource identifiers in RESTful APIs.
2. Distinguish clearly between **Authentication** (identity verification) and **Authorization** (permission verification).
3. Identify and exploit an Insecure Direct Object Reference (IDOR) flaw in an isolated sandbox.
4. Explain why client-side checks and unguessable identifiers (UUIDs) do not replace server-side authorization.
5. Implement server-side session-bound query constraints to remediate IDOR vulnerabilities.
6. Verify access control defenses using automated unit testing and manual HTTP replay.

---

## 2. Seeded Test Accounts

The lab environment comes pre-seeded with two synthetic test accounts:

| Account | Username | Password | Role | Owned Resources |
|---|---|---|---|---|
| **Account A (Student)** | `alice` | `AliceLab123!` | Student Researcher | Documents `101`, `102` |
| **Account B (Target)** | `bob` | `BobLab123!` | Peer Reviewer | Documents `201`, `202` |

> [!WARNING]
> These credentials and synthetic records are for this disposable local lab environment only. Never reuse passwords across real-world systems.

---

## 3. Lab 1: Understand Object References

### Objective
Learn how web applications expose object identifiers in URL paths and parameters, and evaluate whether knowing an identifier implies authorization.

### Step-by-Step Instructions:
1. Open your browser and navigate to `http://localhost:5000`.
2. Log in using Alice's credentials:
   - Username: `alice`
   - Password: `AliceLab123!`
3. On the student dashboard, observe the **Your Private Documents** table. Note that Alice owns document ID `101` (*Alice's Project Notes*) and `102` (*Alice's Lab Report*).
4. Click **Launch Guided Exercises** and select **Lab 1: Understand Object References**.
5. Observe the REST URL structure:
   ```http
   GET /api/documents/101 HTTP/1.1
   Host: localhost:5000
   Cookie: session=<alice_cookie>
   ```
6. Complete the exercise by entering Alice's document identifier (`101`) and answering the conceptual question regarding whether possessing an ID proves ownership.
7. Click **Validate Lab 1 Answers**. Ensure you receive the green confirmation banner.

---

## 4. Lab 2: Exploit Broken Authorization (Vulnerable Mode)

### Objective
Demonstrate horizontal privilege escalation by requesting Bob's confidential document while authenticated as Alice.

### Step-by-Step Instructions:
1. Navigate to **Lab 2: Exploit Broken Authorization**.
2. Check your current mode. If in Secure Mode, click the **Switch to Vulnerable Mode** button in the top header or notification banner.
3. Review the scenario:
   - Alice is logged in (User ID: `1`).
   - Bob owns document ID `201` (*Bob's Private Notes*).
4. In the **Interactive HTTP Request Inspector**, change the target URL from `/api/documents/101` to:
   ```
   /api/documents/201
   ```
5. Click **Send Request**.
6. Observe the server response:
   - **HTTP Status:** `200 OK`
   - **Response Body:** The server returns Bob's private notes and research ideas directly to Alice!
   - **Security Analysis:** The banner highlights horizontal privilege escalation because the backend queried `SELECT * FROM documents WHERE id = 201` without validating ownership.
7. In the submission form, enter target document ID `201` and explain why this response demonstrates an authorization failure.
8. Click **Submit Lab 2 Verification** to register completion in the backend progress tracker.

---

## 5. Lab 3: Remediate IDOR

### Objective
Understand server-side authorization patterns and identify why client-side controls and UUID obfuscation fail to protect resources.

### Step-by-Step Instructions:
1. Navigate to **Lab 3: Remediate IDOR**.
2. Compare the side-by-side code snippets:
   - **Vulnerable Code:**
     ```python
     # Flawed: trusts client parameter alone
     doc = db.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
     ```
   - **Secure Code:**
     ```python
     # Remediated: enforces ownership using authenticated server session
     doc = db.execute(
         "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
         (doc_id, session["user_id"])
     ).fetchone()
     if not doc:
         return jsonify({"error": "Forbidden"}), 403
     ```
3. Complete the two review quiz questions:
   - *Question 1:* Server-side session verification (`session['user_id']`).
   - *Question 2:* Why UUIDs alone do not solve access control without server checks.
4. Click **Validate Remediation Concepts** to pass Lab 3.

---

## 6. Lab 4: Verify the Secure Implementation

### Objective
Confirm that Secure Mode completely mitigates unauthorized cross-user access, preserves legitimate user access, and protects against unauthorized modifications.

### Step-by-Step Instructions:
1. Navigate to **Lab 4: Verify the Fix**.
2. If currently in Vulnerable Mode, click **Switch to Secure Mode** in the header.
3. Click the green **Run Verification Suite** button.
4. The backend will evaluate the following security vectors:
   - **Scenario A:** Alice requests her own document (`101`) &rarr; `HTTP 200 OK` (Allowed).
   - **Scenario B:** Alice requests Bob's document (`201`) &rarr; `HTTP 403 Forbidden` (Blocked!).
   - **Scenario C:** Unauthenticated request for document (`201`) &rarr; `HTTP 401 Unauthorized` (Denied).
   - **Scenario D:** Alice requests nonexistent document (`999`) &rarr; `HTTP 404 Not Found`.
   - **Scenario E:** Alice attempts unauthorized update of document (`201`) &rarr; `HTTP 403 Forbidden` (Data integrity preserved).
5. Ensure all 5 scenarios display the green `PASSED` badge.

---

## 7. Results and Lab Report Export

1. Navigate to **Results & Report** in the sidebar.
2. Review the empirical test matrix comparing Vulnerable Mode vs Secure Mode.
3. Click **Export Experiment Report (.md)** to download your individualized lab report for grading.
4. Ensure the report includes your username, timestamp, and verification details.
