# SENTRIX: Automated Security Auditing & Adversarial Testing Platform

[![Version](https://img.shields.io/badge/version-v0.1.0--alpha-blue.svg)](documentation/PHASE-9-FINAL-RELEASE-REPORT.md)
[![Status](https://img.shields.io/badge/status-dev%2Fdemo%20ready-green.svg)](documentation/FINAL-HANDOVER-TO-NIKHIL.md)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Engines](https://img.shields.io/badge/engines-5%20integrated-orange.svg)](#multi-engine-status-matrix)

**SENTRIX** is an independent, automated security auditing, adversarial testing, vulnerability assessment, reporting, and remediation verification platform. It operates as an external, authorized security evaluator consolidating five production-grade engines around a high-performance orchestrator.

> [!NOTE]
> **Release Posture:** SENTRIX `v0.1.0-alpha` is engineered and validated for development, staging, and demonstration environments. It is **not** certified for unconstrained production use. All adversarial testing is strictly bounded by target scope authorization policies.

---

## Architecture & System Design

SENTRIX is structured around a central Go orchestrator (`sentrixd`, port 9000) that coordinates multi-engine telemetry, executes controlled attack probes, normalizes findings into the **SENTRIX Common Security Event (SCSE)** format, and manages the end-to-end vulnerability lifecycle.

```
+-----------------------------------------------------------------------------------+
|                                 SENTRIX CORE                                      |
|                            (Port 9000 / sentrixd)                                 |
|  - Multi-Engine Orchestrator       - Adversarial Test Runner                      |
|  - SCSE Event Normalizer           - Finding Lifecycle State Machine              |
|  - Target Scope Policy Enforcer    - Developer Advisory Generator                 |
+-----------------------------------------------------------------------------------+
       │                  │                  │                  │                  │
       ▼ (Port 8088)      ▼ (Port 8085)      ▼ (Port 8082)      ▼ (Port 15500)     ▼ (Port 55000)
+--------------+   +--------------+   +--------------+   +--------------+   +--------------+
| Coraza WAF   |   | CrowdSec     |   | ModSec 3     |   | Promptfoo AI |   | Wazuh API    |
| (SecLang     |   | (LAPI Schema |   | (C++ Engine  |   | (Offline CLI |   | (REST API    |
|  Inspection) |   |  Service)    |   |  Runner)     |   |  Runner)     |   |  Service)    |
| [LIVE]       |   | [MOCK]       |   | [LIVE]       |   | [LIVE]       |   | [MOCK]       |
+--------------+   +--------------+   +--------------+   +--------------+   +--------------+
```

### Core Architectural Pillars
1. **Pristine Vendor Codebases:** All five original upstream engines in `engines/` (`coraza-main`, `crowdsec-master`, `ModSecurity-3-master`, `promptfoo-main`, `wazuh-main`) remain 100% intact with their original licenses, build files, and copyright notices.
2. **Process & Copyleft Isolation:** Communication occurs strictly via HTTP REST, LAPI, and structured stdout/stderr pipes, preventing copyleft GPL/LGPL license contamination and guaranteeing process failure isolation.
3. **Resilience & Timeout Budgets:** Every engine probe is bounded by a 2,500ms timeout budget. If an engine goes offline or stalls, Core gracefully isolates the failure, increments failure metrics, and maintains continuous cluster operation.
4. **Scope Authorization Guardrails:** Target requests undergo mandatory environment validation (`POST /api/v1/audits/run`). Any request targeting a production environment is rejected immediately with `HTTP 403 Forbidden`.
5. **SCSE Schema Alignment:** Telemetry across all engines is normalized into the canonical **SENTRIX Common Security Event (SCSE)** format (`schemas/scse-event-schema.json`), aligned with OCSF v1.1.0 specifications.

---

## Multi-Engine Status Matrix

Core composite health monitoring (`GET /api/v1/health`) reports **`status: UP`** with transparent live vs. mock labeling:

| Engine | Port | Operational Status | Service Type | Latency | Verified Attack Capabilities | Upstream Engine Status |
|---|:---:|:---:|:---:|:---:|---|---|
| **Coraza WAF** | `8088` | **HEALTHY** | Live Engine | 8ms | Actively blocks SQLi (Rule 942100) and XSS (Rule 941100) with HTTP 403 Forbidden. | Native Go v3.3.3-dev SecLang rule evaluation verified. |
| **CrowdSec** | `8085` | **HEALTHY** | Schema Service (Mock) | 3ms | Responds to `/v1/heartbeat`, `/v1/health`, and decision queries. | `is_mock_service: true`. Upstream binary requires Docker/Linux. |
| **ModSecurity 3** | `8082` | **HEALTHY** | Live Engine | 2ms | Permits clean requests (200 OK); blocks XSS payloads (403 Forbidden, Rule 941100). | Native C++ architecture operational with restored submodules. |
| **Promptfoo** | `15500` | **HEALTHY** | Live Engine | 3ms | Offline prompt injection & RAG guardrail evaluation (2/2 PASS, 0s, 0 cloud calls). | Local CLI v0.125.1 operational without external cloud keys. |
| **Wazuh** | `55000` | **HEALTHY** | Schema Service (Mock) | 3ms | Serves `/`, basic auth JWT tokens, and daemon status queries. | `is_mock_service: true`. Monolithic manager backend unmounted. |

---

## Security Auditing & Adversarial Capabilities

SENTRIX features automated test runners validating both foundational web vulnerabilities and advanced multi-tenant AI systems:

### 1. 12 Core Attack Categories (Phase 4 Suite)
- **SQL Injection (SQLi):** Detection of error-based and boolean SQL injection payloads.
- **Cross-Site Scripting (XSS):** Reflected SVG/script tag injection vectors.
- **Broken Authentication:** Bypassing invalid session credentials.
- **Broken Access Control (IDOR):** Direct object reference parameter manipulation.
- **Cross-Tenant Data Leakage:** Canary token extraction across tenant boundaries.
- **Prompt Injection:** System prompt extraction and instruction override.
- **RAG Poisoning:** Retrieval context hijacking and poisoned data ingestion.
- **Sensitive Data Exfiltration:** Null-byte exception stack trace leaks.
- **API Abuse:** Mass assignment privilege escalation (`role: superadmin`).
- **Malicious File Upload:** Unrestricted executable upload attempts.
- **Server-Side Request Forgery (SSRF):** Metadata service access attempts.
- **Denial of Service (DoS):** Catastrophic regular expression backtracking probes.

### 2. 12 Advanced Enterprise AI Security Requirements (Phase 6 Suite)
- **`ADV-IDOR-01`:** Cross-tenant LLM conversation history isolation.
- **`ADV-PRIV-01`:** Role-based access control (RBAC) on tenant security configurations.
- **`ADV-SESS-01`:** Post-logout stateless JWT session replay and token blacklisting.
- **`ADV-AI-01`:** Indirect prompt injection via ingested document content.
- **`ADV-RAG-01`:** RAG chunk poisoning and cryptographic citation provenance.
- **`ADV-OUT-01`:** Reflected XSS in LLM assistant Markdown renderers.
- **`ADV-DB-01`:** PostgreSQL Row-Level Security (RLS) connection pool isolation.
- **`ADV-RACE-01`:** Concurrency race conditions in document state transitions.
- **`ADV-CACHE-01`:** Multi-tenant cache key namespace collisions in Redis.
- **`ADV-FILE-01`:** Decompression bomb / zip bomb resource exhaustion.
- **`ADV-LLM-01`:** Unmetered token flooding / GPU inference exhaustion.
- **`ADV-DEP-01`:** Container non-root security posture (`user: 10001:10001`).

---

## 9-Stage Finding Remediation Lifecycle

SENTRIX enforces the canonical 9-stage vulnerability tracking lifecycle defined in `core/pkg/models/vulnerability.go`:

```
[ 1. Detected ] ──> [ 2. Confirmed ] ──> [ 3. Reported ] ──> [ 4. Assigned ]
                                                                     │
                                                                     ▼
[ 8. Verified ] <── [ 7. Retesting ] <── [ 6. Fixed ] <── [ 5. Fix In Progress ]
       │
       ▼
[ 9. Closed ]
```

1. **Detected:** Vulnerability triggered during adversarial evaluation; technical evidence recorded.
2. **Confirmed:** Deterministic validation proves exploitability (response matches error/leak patterns).
3. **Reported:** Structured developer advisory markdown generated via `GET /api/v1/findings/:id/report`.
4. **Assigned:** Finding mapped to development owner and linked to regression scenario ID.
5. **Fix In Progress:** Development applies fixes; retests during this stage confirm ongoing vulnerability.
6. **Fixed:** Code patch applied to target application.
7. **Retesting:** Automated regression retest dispatched via `POST /api/v1/remediation/retest/:id`.
8. **Verified:** Retest against remediated target confirms vulnerability is mitigated.
9. **Closed:** Finding formally archived and resolved.

---

## Authoritative Target & Assessment Baseline

To maintain strict scientific integrity, SENTRIX enforces a clear separation between internal synthetic test harnesses and external target codebases:

- **Internal Synthetic Target:** `tests/mock-target/server.js` is the SENTRIX synthetic test target used to verify detection algorithms and state machine lifecycles. Synthetic-target findings must **not** be assumed to exist as vulnerabilities in external codebases.
- **Authoritative NEXUS Repository:**
  - **URL:** [`https://github.com/NikhilMana/NEXUS`](https://github.com/NikhilMana/NEXUS)
  - **Default Branch:** `main`
  - **Assessment Baseline Commit:** [`cb24f5caf980a513f2e76decedac0021ef7dea35`](https://github.com/NikhilMana/NEXUS/commit/cb24f5caf980a513f2e76decedac0021ef7dea35)
  - The 12 advanced requirements serve as the assessment checklist for source-code audits against the real NEXUS codebase.
- **Cloudflare Security Audit Skill Independence:** The official Cloudflare skill is installed globally in the agent environment (`~/.agents/skills/security-audit`). It is **not** an internal engine dependency of SENTRIX.

---

## Directory Layout

```
SENTRIX/
├── assessments/                        # Cloudflare Skill Security Audit Deliverables
│   └── nexus-security-audit/           # Validated schema reports (architecture, findings, coverage ledger)
├── core/                               # SENTRIX Core Go Application
│   ├── cmd/sentrixd/                   # Core server daemon entrypoint
│   ├── cmd/sentrix-waf/                # Standalone Coraza WAF reverse proxy
│   ├── internal/                       # Internal packages (auditor, config, orchestrator, reporter, remediation)
│   ├── pkg/models/                     # Domain models (scse, target, attack_category, vulnerability)
│   └── tests/core_test.go              # Core unit and integration test suite
├── deploy/                             # Runtime Services & Multi-Engine Deployments
│   ├── core_server.js                  # Core host daemon (Port 9000)
│   ├── coraza_server.py                # Native Coraza SecLang WAF runner (Port 8088)
│   ├── crowdsec_server.py              # CrowdSec LAPI schema service (Port 8085)
│   ├── modsec_server.py                # ModSecurity 3 C++ engine runner (Port 8082)
│   ├── wazuh_api_service.py            # Wazuh REST API schema service (Port 55000)
│   ├── config/                         # Engine configuration templates
│   └── docker/                         # Container Dockerfiles & entrypoints
├── documentation/                      # Technical Documentation & Handover Reports
│   ├── FINAL-HANDOVER-TO-NIKHIL.md     # Consolidated master handover document
│   ├── FINAL-DOCUMENTATION-INTEGRITY-REPORT.md # Final integrity audit report
│   ├── CLOUDFLARE-SECURITY-AUDIT-INTEGRATION.md # Cloudflare skill integration guide
│   ├── NEXUS-DEPLOYMENT-RUNBOOK.md     # Illustrative staging deployment runbook
│   ├── PHASE-6-FINAL-VERIFICATION.md   # Phase 6 verification & coverage matrix
│   ├── PHASE-7-IMPLEMENTATION-REPORT.md# Multi-engine stabilization report
│   ├── PHASE-8-VALIDATION-REPORT.md    # End-to-end validation report
│   └── PHASE-9-FINAL-RELEASE-REPORT.md # Release architecture & API reference
├── engines/                            # Original Upstream Repositories (100% Preserved)
│   ├── coraza-main/                    # OWASP Coraza WAF (Go)
│   ├── crowdsec-master/                # CrowdSec Security Engine (Go)
│   ├── ModSecurity-3-master/           # ModSecurity 3 WAF (C++)
│   ├── promptfoo-main/                 # Promptfoo AI Evaluation Engine (TypeScript)
│   └── wazuh-main/                     # Wazuh SIEM/XDR Platform (C/Python)
├── schemas/                            # SCSE Event Schemas (JSON Schema Draft-07)
├── scripts/                            # Automated Test & Validation Runners
│   ├── test-adversarial-suite.js       # Phase 4 12-core attack suite
│   ├── test-phase6-nexus-suite.js      # Phase 6 12-advanced scenario suite
│   └── validate-configs.js             # Static configuration integrity validator
└── tests/                              # Target & Engine Test Harnesses
    ├── mock-target/server.js           # SENTRIX Synthetic Multi-Tenant Target (Port 9500)
    └── promptfoo/                      # Promptfoo offline configuration & mock LLM
```

---

## Core API Reference (Port 9000)

| Endpoint | Method | Description | Sample Request / Parameters | Success Response |
|---|:---:|---|---|---|
| `/healthz` | `GET` | Core liveness probe. | None | `200 {"status":"UP"}` |
| `/api/v1/health` | `GET` | Composite 5-engine health with latency & mock flags. | None | `200 {"status":"UP","engines":{...}}` |
| `/api/v1/engines` | `GET` | Registered engine inventory. | None | `200 {"count":5,"engines":{...}}` |
| `/api/v1/events/normalize` | `POST` | Normalizes raw alerts into SCSE format. | `{"engine":"coraza","category":"SQLI"}` | `200 {"status":"NORMALIZED","event":{...}}` |
| `/api/v1/audits/run` | `POST` | Executes 12 adversarial scenarios against target. | `{"base_url":"http://127.0.0.1:9500","environment":"staging"}` | `200 {"status":"COMPLETED","findings_count":12}` |
| `/api/v1/findings` | `GET` | Lists all discovered findings and states. | None | `200 {"count":12,"findings":[...]}` |
| `/api/v1/findings/:id` | `GET` | Retrieves full finding detail with technical evidence. | Finding ID in URL path | `200 {"finding_id":"...",...}` |
| `/api/v1/findings/:id/report` | `GET` | Generates developer remediation advisory markdown. | Finding ID in URL path | `200 text/markdown` |
| `/api/v1/findings/:id/transition` | `POST` | Transitions finding through the 9-stage lifecycle. | `{"new_state":"Fixed"}` | `200 {"status":"TRANSITIONED","state":"Fixed"}` |
| `/api/v1/remediation/retest/:id` | `POST` | Executes regression retest against target. | `{"base_url":"http://127.0.0.1:9500"}` | `200 {"retest_passed":true,"state":"Verified"}` |

### Scope Rejection Response
```http
POST /api/v1/audits/run HTTP/1.1
Content-Type: application/json

{"base_url": "https://api.production.internal", "environment": "production"}

HTTP/1.1 403 Forbidden
{"error": "Scope policy violation: Audits cannot target production environments"}
```

---

## Quick Start & Verification Runbook

### 1. Launch Engine Cluster Locally (Native Run)
```powershell
# 1. Start Engine Microservices (Background Daemons)
python deploy/coraza_server.py &
python deploy/modsec_server.py &
python deploy/crowdsec_server.py &
python deploy/wazuh_api_service.py &
node tests/promptfoo/adapter_server.js &

# 2. Start SENTRIX Core Engine
node deploy/core_server.js &
```

### 2. Verify Composite Health
```powershell
curl.exe http://127.0.0.1:9000/api/v1/health
```

### 3. Run Automated Adversarial Suites
```powershell
# Run Original 12 OWASP/CWE Core Attacks & Remediation Lifecycle Test
node scripts/test-adversarial-suite.js

# Run Phase 6 Advanced AI & Architecture Security Suite
node scripts/test-phase6-nexus-suite.js

# Run Configuration & Upstream Integrity Checks
node scripts/validate-configs.js
```

### 4. Validate Cloudflare Audit Deliverables
```powershell
node assessments/nexus-security-audit/run-validator.cjs
```

---

## Documentation Index

- [Final Handover to Nikhil (Master Runbook)](documentation/FINAL-HANDOVER-TO-NIKHIL.md)
- [Final Documentation Integrity Report](documentation/FINAL-DOCUMENTATION-INTEGRITY-REPORT.md)
- [Phase 9: Final Release Architecture Report](documentation/PHASE-9-FINAL-RELEASE-REPORT.md)
- [Phase 8: End-to-End Validation Report](documentation/PHASE-8-VALIDATION-REPORT.md)
- [Phase 7: Multi-Engine Integration Report](documentation/PHASE-7-IMPLEMENTATION-REPORT.md)
- [Phase 6: Final Verification & Coverage Matrix](documentation/PHASE-6-FINAL-VERIFICATION.md)
- [Cloudflare Security Audit Skill Integration](documentation/CLOUDFLARE-SECURITY-AUDIT-INTEGRATION.md)
- [NEXUS Deployment & Operations Runbook](documentation/NEXUS-DEPLOYMENT-RUNBOOK.md)
- [Security Testing Model & Specification](documentation/SECURITY-TESTING-MODEL.md)
- [Phase 1: Architectural & Source-Code Inspection](documentation/PHASE-1-INSPECTION.md)
- [Phase 2: Architecture Blueprint](documentation/PHASE-2-ARCHITECTURE.md)
- [Phase 3: Implementation & Consolidation Report](documentation/PHASE-3-IMPLEMENTATION.md)
