# SENTRIX × NEXUS — INTEGRATION & SECURITY VALIDATION RUNBOOK

**Target Application:** NEXUS Staging Environment (`http://127.0.0.1:9500` or `http://staging.nexus.local`)  
**Auditing Platform:** SENTRIX Core Engine (`http://127.0.0.1:9000`)  
**Document Type:** Technical Integration, Scope Authorization & Remediation Verification Guide  
**Lead DevOps / Security Engineer:** Antigravity Engineering Team  
**Primary Recipient:** Nikhil  
**Date & Timestamp:** 2026-10-31 03:25 UTC+05:30  

---

## 1. Overview: How SENTRIX Assesses NEXUS

SENTRIX is an independent, non-intrusive Automated Security Auditing and Remediation Verification Platform. It assesses NEXUS externally through authorised HTTP/REST interfaces, simulates controlled adversarial scenarios, collects raw cryptographic and technical evidence, and tracks vulnerabilities through a strict 9-stage remediation lifecycle.

```
+-------------------------------------------------------------------------------+
|                             SENTRIX CORE ENGINE                               |
|                                (Port 9000)                                    |
+-------------------------------------------------------------------------------+
        |                                                       ^
        | 1. Authorised Scope Handshake                         | 4. Technical
        |    (Token, Domain Whitelist, Synthetic Data Only)     |    Evidence
        v                                                       |    Collection
+-------------------------------------------------------------------------------+
|                           NEXUS STAGING APPLICATION                           |
|                                (Port 9500)                                    |
|   +-------------------+  +-------------------+  +-------------------------+   |
|   | Tenant Isolation  |  | RBAC / Auth Store |  | RAG / Vector Pipeline    |   |
|   | (PostgreSQL RLS)  |  | (Redis Sessions)  |  | (pgvector / Ollama LLM) |   |
|   +-------------------+  +-------------------+  +-------------------------+   |
+-------------------------------------------------------------------------------+
        |                                                       |
        v                                                       v
+-----------------------+                               +-----------------------+
|  VULNERABLE (DETECT)  |                               |   SECURE (REMEDIATE)  |
| 12 Core Findings      |                               | 0 False Positives     |
| 12 Advanced Findings  |                               | 100% Attack Rejection |
+-----------------------+                               +-----------------------+
```

---

## 2. Target Registration & Scope Authorization Guardrails

Before any audit traffic is dispatched, SENTRIX enforces strict safety constraints implemented in `core/pkg/models/target.go` and `deploy/core_server.js`.

### Scope Authorization Policy Rules
1. **Production Lock:** Targets declaring `environment: "production"` are **instantly rejected** (`400 Bad Request`).
2. **Domain Allowlist:** Requests can only target hosts explicitly defined in `allowed_hosts` (e.g., `127.0.0.1`, `localhost`, `staging.nexus.local`).
3. **Endpoint Pattern Whitelist:** Payloads are restricted to `allowed_endpoints` (e.g., `/api/v1/*`).
4. **Synthetic Data Only:** The flag `use_synthetic_data_only: true` is strictly mandatory.
5. **Rate Limiting:** Requests per second are hard-capped (default: 50 req/sec) to prevent server exhaustion.
6. **Authorization Scope Token:** The client must supply `scope_token: "AUTH-SCOPE-NEXUS-STAGING-CONFIRMED"`.

### Registration Payload (`POST /api/v1/audits/run`)
```json
{
  "target_id": "TARGET-NEXUS-STAGING",
  "name": "NEXUS Multi-Tenant AI Platform (Staging)",
  "base_url": "http://127.0.0.1:9500",
  "environment": "staging",
  "allowed_hosts": [
    "127.0.0.1",
    "localhost",
    "staging.nexus.local"
  ],
  "allowed_endpoints": [
    "/api/v1/*"
  ],
  "use_synthetic_data_only": true,
  "max_requests_per_second": 50,
  "safe_mode": true,
  "scope_token": "AUTH-SCOPE-NEXUS-STAGING-CONFIRMED"
}
```

---

## 3. Step-by-Step Execution: Running the Security Audit

### 3.1 Step 1 — Verify Both Services Are Online
Ensure both SENTRIX Core (port 9000) and NEXUS (port 9500) are healthy:
```powershell
# Check SENTRIX Core
curl.exe -i http://127.0.0.1:9000/healthz

# Check NEXUS Staging Target
curl.exe -i http://127.0.0.1:9500/healthz
```

### 3.2 Step 2 — Dispatch Automated 12-Category Core Audit
```powershell
curl.exe -i -X POST http://127.0.0.1:9000/api/v1/audits/run `
  -H "Content-Type: application/json" `
  -d '{
    "target_id": "TARGET-NEXUS-STAGING",
    "name": "NEXUS Staging",
    "base_url": "http://127.0.0.1:9500",
    "environment": "staging",
    "allowed_hosts": ["127.0.0.1", "localhost"],
    "allowed_endpoints": ["/api/v1/*"],
    "use_synthetic_data_only": true,
    "max_requests_per_second": 50,
    "safe_mode": true,
    "scope_token": "AUTH-SCOPE-NEXUS-STAGING-CONFIRMED"
  }'
```

### 3.3 Step 3 — Run Dedicated Phase 4 & Phase 6 Test Suites
SENTRIX provides two turn-key automated verification test runners:

```powershell
# 1. Run 12 Core Attacks + 9-Stage Remediation Cycle + Regression Suite
node scripts/test-adversarial-suite.js

# 2. Run 12 Advanced NEXUS Requirements (Tenant IDOR, RLS, Prompt Injection, RAG, Race Conditions)
node scripts/test-phase6-nexus-suite.js
```

---

## 4. Technical Evidence Collection & Credential Redaction

Whenever a vulnerability is identified, SENTRIX records an immutable SCSE (Security Common Schema for Events) record containing technical proof while automatically redacting sensitive credentials using the masking engine (`core/pkg/models/redact.go`):

### Redaction Rules
- **JWTs & Bearer Tokens:** Replaced with `[REDACTED_JWT]` or `[REDACTED_TOKEN]`.
- **Session Cookies:** Replaced with `[REDACTED_COOKIE]`.
- **Passwords & Secrets:** Replaced with `[REDACTED_SECRET]`.
- **Database URIs:** Connection strings masked to `postgres://user:***@host:5432/db`.

### Sample Captured SCSE Finding
```json
{
  "finding_id": "VULN-ADV-IDOR-01-1793396127",
  "category": "BROKEN_ACCESS_CONTROL_IDOR",
  "title": "Cross-Tenant Conversation Transcript Exposure",
  "description": "User Alpha retrieved conversation conv-9901 belonging to Tenant Beta",
  "severity": "CRITICAL",
  "state": "Detected",
  "cwe": "CWE-639",
  "technical_evidence": {
    "request_method": "GET",
    "request_url": "http://127.0.0.1:9500/api/v1/tenants/tenant-beta/conversations/conv-9901",
    "request_headers": {
      "Authorization": "Bearer [REDACTED_TOKEN]",
      "X-Tenant-ID": "tenant-alpha"
    },
    "response_status": 200,
    "response_body_sample": "{\"conversation_id\":\"conv-9901\",\"tenant_id\":\"tenant-beta\",\"leak_canary\":\"CANARY_TENANT_BETA_CONVERSATION_LEAK\"}",
    "latency_ms": 5
  },
  "detected_at": "2026-10-31T03:05:00.000Z"
}
```

---

## 5. The 9-Stage Remediation Lifecycle State Machine

SENTRIX enforces an auditable, bidirectional state machine for tracking and remediating every detected vulnerability:

```
[ Detected ]
     |
     v
[ Confirmed ] (Auditor verifies reproducible proof)
     |
     v
[ Reported ]  (Developer Markdown report generated)
     |
     v
[ Assigned ]  (Allocated to lead developer, e.g., Nikhil)
     |
     v
[ Fix In Progress ] <----------------------------+
     |                                           |
     v                                           |
  [ Fixed ]                                      | (Regression Retest FAILS:
     |                                           |  Exploit still reproduces)
     v                                           |
[ Retesting ] -----------------------------------+
     |
     | (Regression Retest PASSES: Exploit blocked / 0 leaks)
     v
[ Verified ]
     |
     v
 [ Closed ]   (Signed off and archived)
```

### State Machine Transition API
```powershell
# 1. Developer marks finding as Fixed
curl.exe -i -X POST http://127.0.0.1:9000/api/v1/findings/VULN-ADV-IDOR-01-1793396127/transition `
  -H "Content-Type: application/json" `
  -d '{"new_state": "Fixed", "actor": "nikhil", "comment": "Enforced tenant check in conversation query"}'

# 2. Trigger automated regression re-test
curl.exe -i -X POST http://127.0.0.1:9000/api/v1/remediation/retest/VULN-ADV-IDOR-01-1793396127 `
  -H "Content-Type: application/json" `
  -d '{"base_url": "http://127.0.0.1:9500", "scope_token": "AUTH-SCOPE-NEXUS-STAGING-CONFIRMED"}'

# 3. Final sign-off (moves Verified -> Closed)
curl.exe -i -X POST http://127.0.0.1:9000/api/v1/findings/VULN-ADV-IDOR-01-1793396127/transition `
  -H "Content-Type: application/json" `
  -d '{"new_state": "Closed", "actor": "lead-auditor", "comment": "Remediation verified; zero findings"}'
```

---

## 6. Regression Verification Playbook for Nikhil

When submitting code changes or pull requests for NEXUS:
1. Start NEXUS in staging mode: `npm run dev` or `docker compose up -d`.
2. Execute the test suite:
   ```powershell
   node scripts/test-adversarial-suite.js
   node scripts/test-phase6-nexus-suite.js
   ```
3. If any test reports `FAILED` or triggers a vulnerability:
   - Inspect the captured finding ID and the `technical_evidence.response_body_sample`.
   - Apply the recommended remediation from `documentation/PHASE-6-ADVANCED-NEXUS-SECURITY-ASSESSMENT.md`.
   - Re-run the test suite until `0 vulnerabilities found` and `100% secure rejection confirmed`.
