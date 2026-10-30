# SENTRIX: Unified Cybersecurity Platform

SENTRIX is a backend-only, unified cybersecurity platform consolidating five production-grade detection and mitigation engines into a single cohesive defense mesh:

1. **[OWASP Coraza](engines/coraza-main)** – Pure Go Web Application Firewall (WAF) running OWASP CRS v4.
2. **[CrowdSec](engines/crowdsec-master)** – Collaborative IDS/IPS, Threat Intelligence, and AppSec engine.
3. **[OWASP ModSecurity 3](engines/ModSecurity-3-master)** – C++17 `libmodsecurity` WAF for legacy connectors and benchmarking.
4. **[Promptfoo](engines/promptfoo-main)** – TypeScript/Node.js GenAI/LLM automated red teaming and prompt guardrail engine.
5. **[Wazuh 5.1](engines/wazuh-main)** – Enterprise-scale SIEM, XDR, File Integrity Monitoring (FIM), and endpoint security platform.

---

## Architecture Overview

```
                                SENTRIX UNIFIED ARCHITECTURE
                                
       [ Client Web Traffic ]                    [ AI / LLM Traffic ]
                 │                                        │
                 ▼                                        ▼
    ┌─────────────────────────┐              ┌─────────────────────────┐
    │   sentrix-waf-coraza    │              │    sentrix-promptfoo    │
    │  (Ingress Proxy :8080)  │              │ (Guardrails & Red Team) │
    └────────────┬────────────┘              └────────────┬────────────┘
                 │ Audit Logs                             │ Threat Alerts
                 ▼                                        ▼
    ┌─────────────────────────┐              ┌─────────────────────────┐
    │    sentrix-crowdsec     │              │  sentrix-wazuh-manager  │
    │  (IDS/IPS Engine :8085) │              │    (SIEM / XDR :55000)  │
    └────────────┬────────────┘              └────────────┬────────────┘
                 │ Bouncer Decisions                      │ Host Telemetry
                 └───────────────────┐  ┌─────────────────┘
                                     ▼  ▼
                         ┌───────────────────────────┐
                         │       sentrix-core        │
                         │ (Supervisor & API :9000)  │
                         └───────────────────────────┘
```

- **Pristine Vendor Codebases:** All five original engines remain 100% intact in `engines/` with their original licenses, copyright notices, and build definitions.
- **Process Boundaries:** Communication occurs exclusively over HTTP REST, gRPC, and structured log pipes to guarantee failure isolation and prevent copyleft contamination.
- **Standardized Schema:** Telemetry across all engines is normalized into the **SENTRIX Common Security Event (SCSE)** format (`schemas/scse-event-schema.json`), aligned with OCSF v1.1.0.

---

## Directory Layout

```
SENTRIX/
├── Makefile                          # Top-level build orchestrator
├── documentation/                    # Project documentation
│   ├── PHASE-1-INSPECTION.md         # Source-code inspection report
│   ├── PHASE-2-ARCHITECTURE.md       # Architecture blueprint
│   └── PHASE-3-IMPLEMENTATION.md     # Phase 3 implementation report
├── engines/                          # Untouched upstream repositories
│   ├── coraza-main/                  # Coraza WAF
│   ├── crowdsec-master/              # CrowdSec Security Engine
│   ├── ModSecurity-3-master/         # ModSecurity 3 WAF
│   ├── promptfoo-main/               # Promptfoo AI Security
│   └── wazuh-main/                   # Wazuh SIEM / XDR
├── core/                             # SENTRIX Core Go orchestrator
│   ├── cmd/sentrixd/                 # Main daemon entrypoint
│   ├── cmd/sentrix-waf/              # Standalone Coraza WAF proxy
│   ├── internal/                     # Config, Logger, Orchestrator, API
│   ├── pkg/models/                   # SCSE Go data models
│   └── tests/                        # Core unit tests
├── schemas/                          # Canonical event schemas (SCSE)
├── deploy/                           # Docker Compose & engine configs
└── scripts/                          # Build, submodule, and run scripts
```

---

## Quick Start (Windows 11 + Docker Desktop + WSL2)

### Prerequisites
1. **Docker Desktop:** Ensure Docker Desktop is installed with the WSL2 backend enabled.
2. **Node.js (>=22.x):** Used for configuration and schema validation scripts.
3. **Git for Windows:** Required for submodule and repo operations.
4. **Go (1.24+):** Optional for native local binary compilation (otherwise handled via Docker).

### Verification & Launch
```powershell
# 1. Validate configuration files and repository integrity
node scripts/validate-configs.js

# 2. Stage ModSecurity submodules
.\scripts\init-submodules.ps1

# 3. Launch lightweight development cluster (Core, WAF, CrowdSec, Promptfoo)
.\scripts\run-dev.ps1
```

### Endpoints
- **Ingress WAF Proxy:** `http://localhost:8080`
- **SENTRIX Core API:** `http://localhost:9000/api/v1/health`
- **CrowdSec LAPI:** `http://localhost:8085/v1/health`
- **Promptfoo UI & API:** `http://localhost:15500`
- **Wazuh REST API:** `https://localhost:55000` (when running `all` profile)

---

## Documentation Index
- [Phase 1: Architectural & Source-Code Inspection](documentation/PHASE-1-INSPECTION.md)
- [Phase 2: Architecture Blueprint](documentation/PHASE-2-ARCHITECTURE.md)
- [Phase 3: Implementation & Consolidation Report](documentation/PHASE-3-IMPLEMENTATION.md)
- [Security Testing Model & Specification](documentation/SECURITY-TESTING-MODEL.md)

