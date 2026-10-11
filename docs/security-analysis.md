# In-Depth Security Analysis: Broken Object-Level Authorization (IDOR)

## Academic & Engineering Report

---

## 1. Vulnerability Classification & Taxonomy

- **Vulnerability Name:** Insecure Direct Object Reference (IDOR) / Broken Object-Level Authorization (BOLA)
- **Common Weakness Enumeration:**
  - [CWE-634: Improper Restriction of Rendered UI Layers / Resource References](https://cwe.mitre.org/data/definitions/634.html)
  - [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
  - [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- **OWASP Ranking:**
  - OWASP Top 10:2021 &rarr; **A01: Broken Access Control** (Ranked #1 overall web application risk)
  - OWASP API Security Top 10:2023 &rarr; **API1:2023 Broken Object Level Authorization**

---

## 2. Authentication vs. Authorization

A critical vulnerability pattern observed in contemporary web applications and microservice architectures is the confusion between **Authentication** and **Authorization**:

```
+-------------------------------------------------------------+
| CLIENT REQUEST: GET /api/documents/201                      |
| Cookie: session=Alice_Token                                 |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
| AUTHENTICATION LAYER                                        |
| Question: "Is this request from a valid, recognized user?"   |
| Check: Session cookie valid? -> YES (Alice, User ID 1)      |
+-------------------------------------------------------------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
+---------------------------+ +-------------------------------+
| VULNERABLE MODE (IDOR)    | | SECURE MODE (ACCESS CONTROL)  |
| Flaw: Assumes valid login | | Question: "Does Alice have    |
| grants universal access.  | | permission for doc 201?"      |
| Query: WHERE id = 201     | | Query: WHERE id = 201         |
| Result: DATA LEAK (200)   | |        AND owner_id = 1       |
+---------------------------+ | Result: ACCESS DENIED (403)   |
                              +-------------------------------+
```

1. **Authentication (AuthN):** Establishes identity. In this virtual lab, both vulnerable and secure modes correctly authenticate Alice and reject anonymous requests (HTTP 401).
2. **Authorization (AuthZ):** Enforces policy and permissions on resources. In Vulnerable Mode, authorization is entirely omitted, permitting any authenticated actor to inspect any record by its primary key.

---

## 3. Root Cause Analysis

The root cause of IDOR in this application stems from three architectural flaws:

1. **Direct Parameter Exposure:** Exposing internal database keys (e.g. `101`, `201`) directly in client-modifiable URL segments (`/api/documents/<id>`).
2. **Lack of Server-Side Predicate Constraints:** The vulnerable SQL query is structured as:
   ```sql
   SELECT * FROM documents WHERE id = ?;
   ```
   The database engine is asked solely about record existence, never about record ownership.
3. **Implicit Trust in Client Parameters:** The application assumes that because the client requested identifier `201`, the client was legitimately presented with that link by the application UI. An attacker using proxy tools (e.g. Burp Suite) bypasses UI boundaries effortlessly.

---

## 4. Threat Modeling & Real-World Impact

In real-world environments, IDOR vulnerabilities have catastrophic impacts across multiple domains:

- **Confidentiality Loss:** Unauthorized viewing of financial statements, medical records, private messages, intellectual property, or billing receipts.
- **Horizontal Escalation:** A regular user accesses equivalent resources belonging to peer users (demonstrated in this lab between Alice and Bob).
- **Vertical Escalation:** If administrative objects (e.g. tenant configurations, user permission profiles) use direct references, an unprivileged user can modify administrative data.
- **Integrity Compromise:** When IDOR affects state-changing endpoints (`PUT`, `DELETE`, `POST`), attackers can tamper with or destroy other users' data (demonstrated in Lab 4 Scenario E).

---

## 5. Architectural Remediation Strategies

### Strategy A: Session-Bound Database Filtering (Recommended & Implemented)
Bind all database lookups to the server-side authenticated session context:
```python
# Secure database lookup
doc = db.execute(
    "SELECT * FROM documents WHERE id = ? AND owner_id = ?",
    (doc_id, session["user_id"])
).fetchone()

if not doc:
    # Fail closed: Do not disclose whether the record belongs to another user
    return jsonify({"error": "Forbidden"}), 403
```

### Strategy B: Indirect Reference Maps (Reference Tokens)
For applications that require preventing identifier enumeration:
- Generate ephemeral, session-specific tokens (e.g. Document #1 = `token_a78c`, Document #2 = `token_b91d`).
- Map tokens to real database primary keys inside the user's encrypted server session.
- Client submits `token_a78c`, and the server resolves the token within that user's session dictionary only.

### Strategy C: Declarative Policy Enforcement (ABAC / RBAC)
In enterprise applications:
- Implement an Attribute-Based Access Control (ABAC) or Role-Based Access Control (RBAC) middleware or policy engine (e.g. Open Policy Agent, Oso).
- Evaluate ownership policies uniformly before executing controller logic:
  ```python
  @authorize(action="read", resource="document", id_param="doc_id")
  def get_document(doc_id):
      ...
  ```

---

## 6. The "Unguessable ID" Fallacy

A frequent developer misconception is that replacing sequential IDs (e.g. `101`, `102`) with UUIDv4 (e.g. `9f8e4321-0a1b-4c2d-9e8f-7b6a5c4d3e2f`) eliminates IDOR.

| Myth | Reality |
|---|---|
| *"Attackers cannot guess UUIDs, so our API is secure."* | UUIDs leak regularly through URL referer headers, system access logs, web analytics, shoulder surfing, and browser histories. |
| *"Obscurity replaces authorization."* | Obscurity only prevents brute-force enumeration. The moment a UUID is known, an unauthorized actor will succeed in reading the object unless server-side authorization is enforced. |

**Guiding Rule:** Opaque identifiers are good defense-in-depth against enumeration, but **never** a substitute for server-side authorization checks.

---

## 7. Educational Scope and Deliberate Boundaries

To provide a safe learning environment:
- **Localhost Binding:** Container and server configurations bind only to `127.0.0.1`.
- **Synthetic Data Only:** All accounts, passwords, notes, and records are fictional.
- **Isolated Vulnerability:** The flaw is restricted specifically to `get_document_vulnerable`. Authentication, password hashing, and session management remain strictly secured.
- **Fail-Safe Defaults:** Default application configuration launches in Secure Mode.
