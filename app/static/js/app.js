/**
 * Web Application Security Virtual Lab: Broken Access Control (IDOR)
 * Interactive Client Logic, Request Inspector & Validation Engine
 */

document.addEventListener("DOMContentLoaded", () => {
    // Initialize common components
    initLabStatus();
    initModeSwitch();
    initRequestInspector();
    initExerciseForms();
    initResetModal();
});

// Helper: Get CSRF Token from meta tag or hidden input
function getCsrfToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (metaTag) return metaTag.getAttribute("content");
    const inputTag = document.querySelector('input[name="csrf_token"]');
    if (inputTag) return inputTag.value;
    return "";
}

// ---------------------------------------------------------------------------
// 1. Progress Status Engine
// ---------------------------------------------------------------------------
async function initLabStatus() {
    if (window.location.pathname.includes("/login")) return;
    try {
        const response = await fetch("/api/lab/status");
        if (!response.ok) return;
        const data = await response.json();

        // Update overall progress bar
        const progressBar = document.getElementById("overall-progress-bar");
        const progressPctText = document.getElementById("progress-pct-text");
        const completedCountText = document.getElementById("completed-count-text");

        if (progressBar) progressBar.style.width = `${data.progress_percentage}%`;
        if (progressPctText) progressPctText.textContent = `${data.progress_percentage}%`;
        if (completedCountText) completedCountText.textContent = `${data.completed_exercises}/${data.total_exercises}`;

        // Update individual exercise badges if present
        data.exercises.forEach(ex => {
            const badge = document.getElementById(`badge-${ex.id}`);
            if (badge) {
                if (ex.status === "passed") {
                    badge.className = "badge badge-secure";
                    badge.innerHTML = '<span class="pulse-dot"></span> Passed';
                } else if (ex.status === "in_progress") {
                    badge.className = "badge badge-warning";
                    badge.innerHTML = 'In Progress';
                } else {
                    badge.className = "badge badge-gray";
                    badge.innerHTML = 'Not Started';
                }
            }

            const alertBox = document.getElementById(`feedback-${ex.id}`);
            if (alertBox && ex.status === "passed") {
                alertBox.className = "alert alert-success";
                alertBox.style.display = "block";
                alertBox.innerHTML = `<strong>Status: PASSED</strong><br>${escapeHtml(ex.feedback || "Exercise validated successfully.")}`;
            }
        });
    } catch (err) {
        console.error("Failed to load lab status:", err);
    }
}

// ---------------------------------------------------------------------------
// 2. Mode Switching Engine
// ---------------------------------------------------------------------------
function initModeSwitch() {
    const modeButtons = document.querySelectorAll("[data-action='switch-mode']");
    modeButtons.forEach(btn => {
        btn.addEventListener("click", async (e) => {
            e.preventDefault();
            const targetMode = btn.getAttribute("data-mode");
            if (!targetMode) return;

            btn.disabled = true;
            try {
                const res = await fetch("/api/lab/mode", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": getCsrfToken()
                    },
                    body: JSON.stringify({ mode: targetMode, csrf_token: getCsrfToken() })
                });

                const data = await res.json();
                if (res.ok) {
                    window.location.reload();
                } else {
                    alert(data.message || "Failed to switch mode.");
                    btn.disabled = false;
                }
            } catch (err) {
                alert("Network error while changing lab mode.");
                btn.disabled = false;
            }
        });
    });
}

// ---------------------------------------------------------------------------
// 3. In-App HTTP Request/Response Inspector
// ---------------------------------------------------------------------------
function initRequestInspector() {
    const sendBtn = document.getElementById("inspector-send-btn");
    if (!sendBtn) return;

    sendBtn.addEventListener("click", async () => {
        const pathInput = document.getElementById("inspector-path-input");
        const methodSelect = document.getElementById("inspector-method-select") || { value: "GET" };
        const bodyInput = document.getElementById("inspector-body-input");
        const statusBadge = document.getElementById("inspector-status-badge");
        const headersViewer = document.getElementById("inspector-response-headers");
        const bodyViewer = document.getElementById("inspector-response-body");
        const annotationBox = document.getElementById("inspector-annotation");

        const path = pathInput ? pathInput.value.trim() : "";
        if (!path) return;

        sendBtn.disabled = true;
        sendBtn.textContent = "Sending...";

        try {
            const options = {
                method: methodSelect.value,
                headers: {
                    "Accept": "application/json",
                    "X-CSRF-Token": getCsrfToken()
                }
            };

            if (["POST", "PUT"].includes(methodSelect.value) && bodyInput) {
                options.headers["Content-Type"] = "application/json";
                options.body = bodyInput.value;
            }

            const startTime = performance.now();
            const response = await fetch(path, options);
            const duration = Math.round(performance.now() - startTime);

            let responseData;
            const contentType = response.headers.get("content-type");
            if (contentType && contentType.includes("application/json")) {
                responseData = await response.json();
            } else {
                responseData = await response.text();
            }

            // Render status badge
            if (statusBadge) {
                statusBadge.textContent = `${response.status} ${response.statusText}`;
                if (response.status >= 200 && response.status < 300) {
                    statusBadge.className = "response-status-badge status-200";
                } else if (response.status === 403) {
                    statusBadge.className = "response-status-badge status-403";
                } else {
                    statusBadge.className = "response-status-badge status-404";
                }
            }

            // Render response headers
            if (headersViewer) {
                let headersText = `HTTP/1.1 ${response.status} ${response.statusText}\n`;
                response.headers.forEach((val, key) => {
                    headersText += `${key}: ${val}\n`;
                });
                headersText += `X-Response-Time: ${duration}ms\n`;
                headersViewer.textContent = headersText;
            }

            // Render response JSON body
            if (bodyViewer) {
                if (typeof responseData === "object") {
                    bodyViewer.textContent = JSON.stringify(responseData, null, 2);
                } else {
                    bodyViewer.textContent = responseData;
                }
            }

            // Dynamic Security Analysis Annotation
            if (annotationBox) {
                renderSecurityAnnotation(annotationBox, response.status, path, responseData);
            }

        } catch (err) {
            console.error("Inspector error:", err);
            if (bodyViewer) bodyViewer.textContent = `Client network error: ${err.message}`;
        } finally {
            sendBtn.disabled = false;
            sendBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> Send Request';
        }
    });
}

function renderSecurityAnnotation(box, status, path, data) {
    box.style.display = "block";

    if (status === 200 && data && data.document && data.security_analysis) {
        if (data.security_analysis.vulnerability_demonstrated) {
            box.className = "alert alert-danger";
            box.innerHTML = `
                <div>
                    <strong>CRITICAL: Insecure Direct Object Reference (IDOR) Demonstrated!</strong><br>
                    You are authenticated as User ID <code>${data.security_analysis.authenticated_user_id}</code>, but the server returned document <code>${data.document.id}</code> owned by User ID <code>${data.document.owner_id}</code> (${escapeHtml(data.document.owner_name)}).<br>
                    <em>Root Cause: The endpoint retrieved the database record by primary key without validating ownership against the server-side session.</em>
                </div>
            `;
            return;
        } else {
            box.className = "alert alert-success";
            box.innerHTML = `
                <div>
                    <strong>Legitimate Authorized Access:</strong><br>
                    You accessed document <code>${data.document.id}</code> which belongs to your account. Ownership verified.
                </div>
            `;
            return;
        }
    }

    if (status === 403) {
        box.className = "alert alert-info";
        box.innerHTML = `
            <div>
                <strong>ACCESS DENIED (HTTP 403 Forbidden): Effective Object-Level Access Control!</strong><br>
                The server evaluated the request, checked the authenticated session against the document's <code>owner_id</code>, detected a mismatch, and rejected unauthorized access.
            </div>
        `;
        return;
    }

    if (status === 404) {
        box.className = "alert alert-warning";
        box.innerHTML = `
            <div>
                <strong>HTTP 404 Not Found:</strong><br>
                The requested resource does not exist in the database, or the application intentionally returned a non-disclosing 404 status.
            </div>
        `;
        return;
    }

    box.className = "alert alert-info";
    box.innerHTML = `<div><strong>Request Completed:</strong> Server returned HTTP status ${status}.</div>`;
}

// ---------------------------------------------------------------------------
// 4. Exercise Validation Forms Engine
// ---------------------------------------------------------------------------
function initExerciseForms() {
    // Lab 1 Validation
    const lab1Form = document.getElementById("form-lab1");
    if (lab1Form) {
        lab1Form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const identifier = document.getElementById("lab1-doc-id").value;
            const concept = document.querySelector('input[name="lab1_concept"]:checked');
            if (!concept) {
                alert("Please select an answer for the conceptual question.");
                return;
            }

            await submitValidation("lab1_inspect_ref", {
                identifier: identifier,
                concept_answer: concept.value
            }, "feedback-lab1_inspect_ref");
        });
    }

    // Lab 2 Validation
    const lab2Form = document.getElementById("form-lab2");
    if (lab2Form) {
        lab2Form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const targetId = document.getElementById("lab2-target-id").value;
            const explanation = document.getElementById("lab2-explanation").value;

            await submitValidation("lab2_exploit_idor", {
                target_doc_id: targetId,
                explanation: explanation
            }, "feedback-lab2_exploit_idor");
        });
    }

    // Lab 3 Validation
    const lab3Form = document.getElementById("form-lab3");
    if (lab3Form) {
        lab3Form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const checkQuery = document.querySelector('input[name="lab3_query"]:checked');
            const conceptUuid = document.querySelector('input[name="lab3_uuid"]:checked');

            if (!checkQuery || !conceptUuid) {
                alert("Please answer both remediation review questions.");
                return;
            }

            await submitValidation("lab3_remediate_check", {
                check_query: checkQuery.value,
                concept_uuid: conceptUuid.value
            }, "feedback-lab3_remediate_check");
        });
    }

    // Lab 4 Verification Suite
    const lab4Btn = document.getElementById("btn-run-lab4");
    if (lab4Btn) {
        lab4Btn.addEventListener("click", async () => {
            lab4Btn.disabled = true;
            lab4Btn.textContent = "Executing Verification Scenarios...";

            const res = await submitValidation("lab4_verify_scenarios", {}, "feedback-lab4_verify_scenarios");
            if (res && res.details && res.details.scenarios) {
                renderScenarioResults(res.details.scenarios);
            }
            lab4Btn.disabled = false;
            lab4Btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg> Run Verification Suite';
        });
    }
}

async function submitValidation(exerciseId, payload, feedbackElementId) {
    const feedbackBox = document.getElementById(feedbackElementId);
    try {
        const bodyData = {
            exercise_id: exerciseId,
            csrf_token: getCsrfToken(),
            ...payload
        };

        const res = await fetch("/api/lab/validate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify(bodyData)
        });

        const data = await res.json();

        if (feedbackBox) {
            feedbackBox.style.display = "block";
            if (data.passed) {
                feedbackBox.className = "alert alert-success";
                feedbackBox.innerHTML = `<strong>PASS - EXCELLENT WORK!</strong><br>${escapeHtml(data.feedback)}`;
            } else {
                feedbackBox.className = "alert alert-danger";
                feedbackBox.innerHTML = `<strong>VERIFICATION FAILED:</strong><br>${escapeHtml(data.feedback || data.message)}`;
            }
        }

        // Refresh global status
        initLabStatus();
        return data;

    } catch (err) {
        if (feedbackBox) {
            feedbackBox.style.display = "block";
            feedbackBox.className = "alert alert-danger";
            feedbackBox.textContent = `Network error: ${err.message}`;
        }
    }
}

function renderScenarioResults(scenarios) {
    const container = document.getElementById("scenario-results-table-body");
    if (!container) return;

    container.innerHTML = "";
    scenarios.forEach(s => {
        const row = document.createElement("tr");
        const statusBadge = s.passed 
            ? '<span class="badge badge-secure">PASSED</span>' 
            : '<span class="badge badge-vulnerable">FAILED</span>';
        
        row.innerHTML = `
            <td><strong>${escapeHtml(s.name)}</strong></td>
            <td><code>HTTP ${s.expected}</code></td>
            <td><code>HTTP ${s.actual || 'N/A'}</code></td>
            <td>${statusBadge}</td>
        `;
        container.appendChild(row);
    });
}

// ---------------------------------------------------------------------------
// 5. Reset Lab Confirmation Modal
// ---------------------------------------------------------------------------
function initResetModal() {
    const openBtns = document.querySelectorAll("[data-action='open-reset-modal']");
    const modal = document.getElementById("reset-modal");
    const cancelBtn = document.getElementById("reset-cancel-btn");
    const confirmBtn = document.getElementById("reset-confirm-btn");

    if (!modal) return;

    openBtns.forEach(b => b.addEventListener("click", () => modal.classList.add("active")));
    if (cancelBtn) cancelBtn.addEventListener("click", () => modal.classList.remove("active"));

    if (confirmBtn) {
        confirmBtn.addEventListener("click", async () => {
            confirmBtn.disabled = true;
            confirmBtn.textContent = "Resetting...";

            try {
                const res = await fetch("/api/lab/reset", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": getCsrfToken()
                    },
                    body: JSON.stringify({ csrf_token: getCsrfToken() })
                });

                if (res.ok) {
                    window.location.href = "/dashboard";
                } else {
                    alert("Reset failed.");
                    confirmBtn.disabled = false;
                }
            } catch (err) {
                alert("Network error while resetting lab.");
                confirmBtn.disabled = false;
            }
        });
    }
}

function escapeHtml(text) {
    if (!text) return "";
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}
