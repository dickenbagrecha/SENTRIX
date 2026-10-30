# SENTRIX Phase 2: Architecture Finalisation and Consolidation Blueprint

**Project:** SENTRIX Unified Backend Cybersecurity Platform  
**Phase:** Phase 2 – Architecture Finalisation & Monorepository Consolidation Blueprint  
**Status:** Architecture Blueprint (Planning Only)  
**Reference Document:** `documentation/PHASE-1-INSPECTION.md`  

---

## Executive Overview

SENTRIX consolidates five diverse, production-proven cybersecurity engines into a unified backend platform while preserving 100% of their original source code, build chains, runtime autonomy, and licensing integrity:
1. **OWASP Coraza** (Pure Go WAF library & reverse proxy middleware)
2. **CrowdSec** (Go IDS/IPS, Local API, threat intelligence & Coraza-based AppSec)
3. **OWASP ModSecurity 3** (C++ `libmodsecurity` WAF engine for native connectors and benchmarking)
4. **Promptfoo** (TypeScript/Node.js GenAI/LLM adversarial red teaming & guardrail engine)
5. **Wazuh** (C/C++/Python enterprise SIEM, XDR, FIM, and endpoint telemetry manager)

### Core Architectural Principles
- **Pristine Engine Preservation:** Every original engine remains in its dedicated subdirectory under `engines/`. Source files, build recipes, configuration templates, licenses, and copyright notices remain untouched.
- **Process Boundaries Over In-Memory Linking:** All engine interactions occur across well-defined network boundaries (REST APIs, gRPC, Unix domain sockets, structured log pipes). No shared-memory linking across incompatible language or license boundaries.
- **Strict License Isolation:** Wazuh's copyleft obligations (GPL-2.0 / AGPL-3.0) are completely quarantined within its daemon process and container boundary, preventing copyleft contamination of MIT (CrowdSec, Promptfoo) or Apache 2.0 (Coraza, ModSecurity, SENTRIX Core) components.
- **Cross-Platform Development Support:** Native Windows support for local development tools (Go, Node.js, Docker Desktop WSL2), with Linux-native daemons (Wazuh Manager, CrowdSec daemon, ModSecurity compilation) encapsulated in standard OCI containers.

---

## Deliverable A: Final Monorepository Directory Structure

The monorepository layout maintains a clear separation between untouched upstream codebases, unified core services, deployment specifications, and schemas:

```
SENTRIX/
├── .gitignore
├── Makefile                                # Top-level polyglot orchestrator
├── README.md
│
├── documentation/                          # Architectural documentation
│   ├── PHASE-1-INSPECTION.md               # Read-only source code inspection report
│   ├── PHASE-2-ARCHITECTURE.md             # This architecture blueprint
│   └── api/                                # Unified API specifications (OpenAPI 3.1)
│
├── engines/                                # Untouched Upstream Vendor Codebases
│   ├── coraza-main/                        # Pure Go WAF Engine (Go 1.26)
│   ├── crowdsec-master/                    # Go IDS/IPS & LAPI (Go 1.27)
│   ├── ModSecurity-3-master/               # C++17 libmodsecurity WAF
│   ├── promptfoo-main/                     # TypeScript LLM Security Engine (Node >=22)
│   └── wazuh-main/                         # C/C++20/Python 3.12 SIEM/XDR Manager & Agent
│
├── core/                                   # SENTRIX Core Orchestration Layer (Go 1.24+)
│   ├── go.mod
│   ├── go.sum
│   ├── cmd/
│   │   ├── sentrixd/                       # Main orchestration daemon & API gateway
│   │   └── sentrix-waf/                    # Coraza-based standalone WAF reverse proxy
│   ├── internal/
│   │   ├── orchestrator/                   # Engine lifecycle manager & health supervisor
│   │   ├── gateway/                        # Unified REST & gRPC API gateway
│   │   ├── bus/                            # Internal asynchronous event bus
│   │   ├── normalizer/                     # Security event schema normalizer
│   │   ├── broker/                         # Unified remediation & action arbitration broker
│   │   └── adapters/                       # Engine-specific client adapters
│   │       ├── coraza/                     # Transaction & audit log consumer
│   │       ├── crowdsec/                   # CrowdSec LAPI REST/WebSocket client
│   │       ├── modsec/                     # ModSecurity audit log tailer
│   │       ├── promptfoo/                  # Promptfoo REST & guardrail client
│   │       └── wazuh/                      # Wazuh Manager API client & syslog forwarder
│   └── pkg/
│       └── models/                         # Shared Go data types for normalized events
│
├── schemas/                                # Canonical Security Event Schemas
│   ├── event-schema.json                   # SENTRIX Common Security Event (SCSE) JSON Schema
│   └── proto/                              # Protocol Buffer definitions for gRPC bus
│       └── sentrix_events.proto
│
├── deploy/                                 # Container & Deployment Definitions
│   ├── docker-compose.yml                  # Complete 5-engine unified local stack
│   ├── docker-compose.dev.yml              # Lightweight dev profile (Core + WAF + CrowdSec + Promptfoo)
│   ├── env.example                         # Environment configuration template
│   ├── docker/
│   │   ├── Dockerfile.core                 # SENTRIX Core container
│   │   ├── Dockerfile.coraza-waf           # Standalone Coraza WAF Proxy container
│   │   ├── Dockerfile.crowdsec             # CrowdSec engine container
│   │   ├── Dockerfile.modsecurity          # ModSecurity C++ test/proxy container
│   │   ├── Dockerfile.promptfoo            # Promptfoo evaluator & server container
│   │   └── Dockerfile.wazuh-manager        # Wazuh Manager Linux container
│   └── config/                             # Unified configuration overrides
│       ├── core.yaml                       # SENTRIX Core runtime configuration
│       ├── coraza/
│       │   └── waf.conf                    # Coraza WAF directives & CRS loader
│       ├── crowdsec/
│       │   ├── config.yaml                 # CrowdSec LAPI & engine settings
│       │   └── acquis.yaml                 # Ingestion sources (WAF logs, system logs)
│       ├── promptfoo/
│       │   └── promptfoo.config.yaml       # AI testing & guardrail settings
│       └── wazuh/
│           ├── ossec.conf                  # Wazuh Manager configuration overrides
│           └── local_rules.xml             # Custom rules for Coraza/CrowdSec correlation
│
└── scripts/                                # Maintenance & Setup Scripts
    ├── setup-prereqs.ps1                   # Windows prerequisite checker
    ├── setup-prereqs.sh                    # Linux/macOS prerequisite checker
    ├── init-submodules.sh                  # ModSecurity submodule fetcher
    └── run-dev.ps1                         # Windows local runner using Docker Compose
```

---

## Deliverable B: Engine-by-Engine Build and Execution Strategy

Each engine retains its native build mechanism and can be built and executed completely independently of SENTRIX Core.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      ENGINE BUILD & EXECUTION PARADIGM                          │
├─────────────────────┬──────────────┬────────────────────────┬───────────────────┤
│ Engine              │ Language     │ Native Build Tool      │ Execution Model   │
├─────────────────────┼──────────────┼────────────────────────┼───────────────────┤
│ Coraza WAF          │ Go 1.26      │ go build / mage        │ Embedded / Proxy  │
│ CrowdSec            │ Go 1.27      │ GNU Make / go build    │ Standalone Daemon │
│ ModSecurity 3       │ C++17        │ Autotools / CMake      │ Dynamic Library   │
│ Promptfoo           │ TypeScript   │ tsdown / npm / pnpm    │ CLI / REST Server │
│ Wazuh 5.1 Manager   │ C/C++20/Py   │ GNU Make / CMake / pip │ Multi-Daemon Svc  │
│ SENTRIX Core        │ Go 1.24+     │ go build               │ Supervisor Daemon │
└─────────────────────┴──────────────┴────────────────────────┴───────────────────┘
```

### 1. OWASP Coraza (`engines/coraza-main`)
- **Nature:** Go library / middleware (not a standalone daemon out-of-the-box).
- **Independent Build Command:**
  ```bash
  cd engines/coraza-main
  go build ./...
  go test ./...
  ```
- **SENTRIX Execution Strategy:**
  - Deployed in `core/cmd/sentrix-waf`, a dedicated, lightweight reverse proxy written in Go that imports Coraza (`github.com/corazawaf/coraza/v3`).
  - Intercepts inbound HTTP traffic on port `8080` (HTTP) and `8443` (HTTPS), evaluates OWASP CRS v4 rules, blocks malicious payloads, and pipes structured JSON audit logs to SENTRIX Core via Unix socket or stdout.

### 2. CrowdSec (`engines/crowdsec-master`)
- **Nature:** Standalone IDS/IPS daemon, Local API (LAPI) server, and AppSec WAF engine.
- **Independent Build Command:**
  ```bash
  cd engines/crowdsec-master
  # Standard build with CGo SQLite and RE2:
  make
  # Pure-Go build (portable, without CGo/libre2-dev):
  make BUILD_SQLITE=modernc BUILD_RE2_WASM=1
  ```
- **SENTRIX Execution Strategy:**
  - Runs as an independent daemon (`crowdsec -c deploy/config/crowdsec/config.yaml`).
  - LAPI binds to internal port `8085` (avoiding conflict with WAF ingress on `8080`).
  - Ingests system logs, syslog streams, and Coraza audit log files via `deploy/config/crowdsec/acquis.yaml`.
  - Emits real-time threat decisions and synchronizes community blocklists via CAPI.

### 3. OWASP ModSecurity 3 (`engines/ModSecurity-3-master`)
- **Nature:** C++17 shared dynamic library (`libmodsecurity.so`).
- **Submodule Prerequisite:** Must initialize submodules before compilation:
  ```bash
  cd engines/ModSecurity-3-master
  git submodule update --init --recursive
  ```
- **Independent Build Command:**
  - **Linux / OCI Container:**
    ```bash
    ./build.sh
    ./configure --prefix=/usr/local/modsecurity --without-lmdb
    make -j$(nproc)
    make check
    ```
  - **Windows:**
    ```cmd
    vcbuild.bat Release x86_64
    ```
- **SENTRIX Execution Strategy:**
  - Encapsulated within a dedicated container (`deploy/docker/Dockerfile.modsecurity`) linked to an Nginx reverse proxy using `modsecurity-nginx`.
  - Operates on a dedicated secondary inspection port (`8082`) for parallel benchmarking, syntax validation (`tools/rules_check`), and legacy C++ connector compatibility testing. Does not interfere with the primary Coraza WAF pipeline.

### 4. Promptfoo (`engines/promptfoo-main`)
- **Nature:** TypeScript / Node.js CLI toolkit, evaluation engine, and web server.
- **Independent Build Command:**
  ```bash
  cd engines/promptfoo-main
  npm install --legacy-peer-deps
  npm run build
  ```
- **SENTRIX Execution Strategy:**
  - Runs in server daemon mode: `node dist/src/entrypoint.js view --port 15500 --host 0.0.0.0`.
  - Exposes REST endpoints on port `15500` consumed by SENTRIX Core.
  - Serves two distinct operational flows:
    1. **Scheduled / On-Demand Red Teaming:** Batch adversarial attacks against configured LLM applications and agent targets.
    2. **Inline Guardrail Evaluation:** SENTRIX Core forwards incoming/outgoing AI prompts to Promptfoo's guardrail checking routines for real-time safety classification.

### 5. Wazuh 5.1 Manager (`engines/wazuh-main`)
- **Nature:** Distributed enterprise SIEM/XDR manager composed of C/C++ daemons and a Python 3.12 REST API.
- **Independent Build Command (Linux Container):**
  ```bash
  cd engines/wazuh-main/src
  make TARGET=manager deps -j$(nproc)
  make TARGET=manager -j$(nproc)
  cd ../framework
  pip install -r requirements.txt
  ```
- **SENTRIX Execution Strategy:**
  - Isolated within a Linux container (`sentrix-wazuh-manager`) running Ubuntu 24.04.
  - Managed via `/var/wazuh-manager/bin/wazuh-manager-control start`.
  - Ingests agent telemetry and network syslog on ports `1514` and `1515`.
  - Exposes Wazuh Manager REST API on port `55000` (`https://127.0.0.1:55000`).

---

## Deliverable C: Dependency and Runtime Installation Plan

### 1. Host System Requirements

| Environment | Purpose | Required Toolchains & Runtimes |
| :--- | :--- | :--- |
| **Windows Host** (Development Station) | Monorepo navigation, Core development, Container management | • Git for Windows 2.40+<br>• Go 1.24+ (recommended Go 1.26+ for Coraza/Core)<br>• Node.js 22.x LTS (>= 22.22.0) & npm 10+<br>• Docker Desktop (WSL2 engine enabled)<br>• PowerShell 7+ |
| **Linux Subsystem / OCI Containers** | Compiling & running C/C++ & Linux daemons (Wazuh, ModSecurity) | • Ubuntu 24.04 LTS base<br>• GCC 13+ / 14, G++, GNU Make, CMake 3.22.1+<br>• Python 3.12 with `python3-venv` and `pip`<br>• Flex, Bison, Autotools (`autoconf`, `automake`, `libtool`)<br>• Libraries: `libpcre2-dev`, `libre2-dev`, `libxml2-dev`, `libyajl-dev`, `libssl-dev` |

### 2. Dependency Isolation Plan
- **Go Version Alignment:**
  - Coraza requires Go `1.26.0`; CrowdSec requires Go `1.27.1`.
  - SENTRIX Core uses Go `1.24+`.
  - Each engine maintains its independent `go.mod` file and module cache. In container builds, each container uses its required Go base image (`golang:1.26` for Coraza, `golang:1.27` for CrowdSec).
- **Node.js Scope:**
  - Promptfoo dependencies are strictly contained in `engines/promptfoo-main/node_modules`. No Node.js dependencies leak into the root repository.
- **Python Scope:**
  - Wazuh's Python framework uses a dedicated virtual environment (`/var/wazuh-manager/framework/python` or `/opt/wazuh-venv`) isolated from any host Python installation.

---

## Deliverable D: Docker / Compose Deployment Strategy

A containerized deployment model is the foundation for unifying the five engines on any operating system, providing complete process, runtime, and filesystem isolation.

```
                                  SENTRIX NETWORK MESH
                                (sentrix-internal-net)
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    │                                             │
      ┌─────────────▼─────────────┐                 ┌─────────────▼─────────────┐
      │     sentrix-waf-coraza    │                 │       sentrix-core        │
      │   (Ingress Port 80/443)   │                 │    (API Gateway :9000)    │
      └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                    │ Audit Logs                                  │ API Integration
                    ▼                                             │
      ┌───────────────────────────┐                               │
      │      sentrix-crowdsec     │◄──────────────────────────────┤
      │    (LAPI Port 8085)       │      Decision Sync            │
      └───────────────────────────┘                               │
                                                                  │
      ┌───────────────────────────┐                               │
      │      sentrix-promptfoo    │◄──────────────────────────────┤
      │    (Guardrails :15500)    │      AI Eval & Red Team       │
      └───────────────────────────┘                               │
                                                                  │
      ┌───────────────────────────┐                               │
      │    sentrix-wazuh-manager  │◄──────────────────────────────┘
      │    (API Port 55000)       │      SIEM Alerts & Telemetry
      └───────────────────────────┘
```

### Complete `deploy/docker-compose.yml` Specification

```yaml
version: '3.8'

networks:
  sentrix-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16

volumes:
  sentrix-shared-logs:
  crowdsec-db:
  wazuh-etc:
  wazuh-var:

services:
  # -------------------------------------------------------------
  # 1. SENTRIX Core: Orchestrator, Unified Gateway & Event Hub
  # -------------------------------------------------------------
  sentrix-core:
    build:
      context: ..
      dockerfile: deploy/docker/Dockerfile.core
    container_name: sentrix-core
    restart: unless-stopped
    ports:
      - "9000:9000"   # SENTRIX Unified REST API
      - "9001:9001"   # SENTRIX gRPC Internal Event Bus
    environment:
      - SENTRIX_ENV=production
      - CROWDSEC_LAPI_URL=http://sentrix-crowdsec:8085
      - CROWDSEC_LAPI_KEY=${CROWDSEC_BOUNCER_KEY}
      - WAZUH_API_URL=https://sentrix-wazuh-manager:55000
      - WAZUH_API_USER=${WAZUH_API_USER:-wazuh-wui}
      - WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}
      - PROMPTFOO_URL=http://sentrix-promptfoo:15500
    volumes:
      - ./config/core.yaml:/etc/sentrix/core.yaml:ro
      - sentrix-shared-logs:/var/log/sentrix
    networks:
      sentrix-net:
        ipv4_address: 172.28.0.10
    depends_on:
      - sentrix-crowdsec
      - sentrix-promptfoo

  # -------------------------------------------------------------
  # 2. Coraza WAF: Edge Reverse Proxy Middleware
  # -------------------------------------------------------------
  sentrix-waf-coraza:
    build:
      context: ..
      dockerfile: deploy/docker/Dockerfile.coraza-waf
    container_name: sentrix-waf-coraza
    restart: unless-stopped
    ports:
      - "8080:8080"   # External HTTP Ingress
      - "8443:8443"   # External HTTPS Ingress
    environment:
      - WAF_MODE=On
      - BACKEND_URL=http://sentrix-core:9000
    volumes:
      - ./config/coraza/waf.conf:/etc/coraza/waf.conf:ro
      - sentrix-shared-logs:/var/log/coraza
    networks:
      sentrix-net:
        ipv4_address: 172.28.0.20

  # -------------------------------------------------------------
  # 3. CrowdSec: IDS/IPS Engine, Threat Intelligence & LAPI
  # -------------------------------------------------------------
  sentrix-crowdsec:
    build:
      context: ..
      dockerfile: deploy/docker/Dockerfile.crowdsec
    container_name: sentrix-crowdsec
    restart: unless-stopped
    ports:
      - "8085:8085"   # Local API (LAPI)
      - "6060:6060"   # Prometheus Metrics
    volumes:
      - ./config/crowdsec/config.yaml:/etc/crowdsec/config.yaml:ro
      - ./config/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro
      - crowdsec-db:/var/lib/crowdsec/data
      - sentrix-shared-logs:/var/log/sentrix:ro
    networks:
      sentrix-net:
        ipv4_address: 172.28.0.30

  # -------------------------------------------------------------
  # 4. Promptfoo: LLM Red Teaming & Guardrail Assessment Server
  # -------------------------------------------------------------
  sentrix-promptfoo:
    build:
      context: ..
      dockerfile: deploy/docker/Dockerfile.promptfoo
    container_name: sentrix-promptfoo
    restart: unless-stopped
    ports:
      - "15500:15500" # Promptfoo Web UI & REST API
    environment:
      - PROMPTFOO_DISABLE_TELEMETRY=true
      - PROMPTFOO_PORT=15500
    volumes:
      - ./config/promptfoo/promptfoo.config.yaml:/app/promptfoo.config.yaml:ro
    networks:
      sentrix-net:
        ipv4_address: 172.28.0.40

  # -------------------------------------------------------------
  # 5. Wazuh Manager: SIEM, XDR, FIM & Compliance Server
  # -------------------------------------------------------------
  sentrix-wazuh-manager:
    build:
      context: ..
      dockerfile: deploy/docker/Dockerfile.wazuh-manager
    container_name: sentrix-wazuh-manager
    restart: unless-stopped
    ports:
      - "1514:1514/tcp"  # Agent communication
      - "1515:1515/tcp"  # Agent registration
      - "55000:55000"    # Wazuh REST API
    volumes:
      - wazuh-etc:/etc/wazuh-manager
      - wazuh-var:/var/wazuh-manager
      - sentrix-shared-logs:/var/log/sentrix:ro
    networks:
      sentrix-net:
        ipv4_address: 172.28.0.50

  # -------------------------------------------------------------
  # 6. ModSecurity 3: Secondary C++ WAF & Benchmark Proxy (Optional)
  # -------------------------------------------------------------
  sentrix-modsec:
    build:
      context: ..
      dockerfile: deploy/docker/Dockerfile.modsecurity
    container_name: sentrix-modsec
    profiles: ["benchmark", "all"]
    restart: "no"
    ports:
      - "8082:8082"
    networks:
      sentrix-net:
        ipv4_address: 172.28.0.60
```

---

## Deliverable E: SENTRIX Core Architecture

SENTRIX Core (`core/`) is designed as an independent orchestration component that bridges all five engines without violating process or licensing boundaries.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SENTRIX CORE ARCHITECTURE                             │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                    UNIFIED INGRESS GATEWAY (PORT 9000)                    │  │
│  │    • Reverse proxy routing       • Health / Readiness endpoints           │  │
│  │    • Authentication / RBAC       • Unified Telemetry & Metrics            │  │
│  └─────────────────────────────────────┬─────────────────────────────────────┘  │
│                                        │                                        │
│  ┌─────────────────────────────────────▼─────────────────────────────────────┐  │
│  │                  EVENT DISPATCHER & ASYNCHRONOUS BUS                      │  │
│  │    • Go channel pub/sub          • Event deduplication & rate limiting    │  │
│  │    • Structured event batching   • Fail-safe persistent buffer            │  │
│  └───────┬─────────────────────────────┬─────────────────────────────┬───────┘  │
│          │                             │                             │          │
│  ┌───────▼─────────────┐       ┌───────▼─────────────┐       ┌───────▼───────┐  │
│  │   EVENT NORMALIZER  │       │  ACTION ARBITRATION │       │ ENGINE HEALTH │  │
│  │                     │       │       BROKER        │       │  SUPERVISOR   │  │
│  │ Transforms alerts   │       │ Resolves conflicts  │       │ Polls engine  │  │
│  │ into SCSE format    │       │ between WAF & IPS   │       │ liveness & api│  │
│  └───────┬─────────────┘       └───────┬─────────────┘       └───────┬───────┘  │
│          │                             │                             │          │
│  ┌───────▼─────────────────────────────▼─────────────────────────────▼───────┐  │
│  │                      ADAPTER ABSTRACTION INTERFACES                       │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐  │  │
│  │  │Coraza Adapter│ │CrowdSec Adapt│ │Wazuh Adapter │ │Promptfoo Adapter │  │  │
│  │  │ (Log Tailer) │ │ (LAPI Client)│ │ (REST / Sys) │ │  (HTTP Client)   │  │  │
│  │  └──────────────┘ └──────────────┘ └──────────────┘ └──────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Core Subsystems
1. **Engine Health Supervisor (`internal/orchestrator/`):**
   - Continuously evaluates health, uptime, and latency across all five engines via active polling.
   - Triggers circuit-breakers when an engine degrades or fails.
2. **Security Event Normalizer (`internal/normalizer/`):**
   - Translates diverse formats (Coraza JSON audit logs, CrowdSec LAPI alert models, Wazuh alert JSON, and Promptfoo evaluation results) into the **SENTRIX Common Security Event (SCSE)** standard.
3. **Action Arbitration Broker (`internal/broker/`):**
   - Resolves conflicts between automated remediation actions.
   - Prevents duplicate or conflicting IP bans between CrowdSec decisions and Wazuh Active Response scripts.
4. **Adapter Abstractions (`internal/adapters/`):**
   - Clean, decoupled interfaces connecting to each engine via its supported external API, log file, or network protocol.

---

## Deliverable F: Inter-Engine Communication Design

No engine directly reads the internal memory or calls proprietary shared libraries of another engine. All data exchange uses explicit protocols:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     INTER-ENGINE COMMUNICATION PROTOCOLS                        │
├──────────────────────┬──────────────────────┬───────────────────────────────────┤
│ Origin -> Target     │ Channel / Protocol   │ Payload / Data Description        │
├──────────────────────┼──────────────────────┼───────────────────────────────────┤
│ Coraza -> Core       │ Unix Socket / Pipe   │ Structured JSON WAF Audit Events  │
│ Coraza -> CrowdSec   │ Shared File Tail     │ HTTP Request Transactions (AppSec)│
│ CrowdSec <-> Core    │ HTTP REST / WS :8085 │ LAPI Alerts, Bouncer Decisions    │
│ Wazuh API <-> Core   │ HTTPS / TLS :55000   │ JWT Auth, SIEM Alerts, Agent Info │
│ Core -> Wazuh        │ Syslog UDP/TCP :514  │ Normalized Web & AI Threat Events │
│ Core <-> Promptfoo   │ HTTP REST :15500     │ Eval Job Trigger, Guardrail Check │
│ ModSecurity -> Core  │ File Mount / Syslog  │ ModSec 3 JSON Audit Logs          │
└──────────────────────┴──────────────────────┴───────────────────────────────────┘
```

### End-to-End Threat Mitigation Scenario
1. **Inbound HTTP Request:** An external client sends a malicious HTTP payload containing both an SQL injection string and a jailbreak prompt to `/api/v1/agent`.
2. **Layer 7 Inspection (Coraza):**
   - Coraza WAF detects the SQL injection attempt via OWASP CRS rule `942100`.
   - Generates an immediate disruptive 403 Forbidden intervention.
   - Flushes an audit log entry to the shared volume `/var/log/sentrix/coraza-audit.log`.
3. **Correlation & IP Reputation (CrowdSec):**
   - CrowdSec acquires the Coraza event via `deploy/config/crowdsec/acquis.yaml`.
   - The leaky-bucket scenario triggers: the offending IP is flagged for aggressive application scanning.
   - CrowdSec LAPI emits a 4-hour ban decision.
4. **Central Coordination (SENTRIX Core):**
   - Core's CrowdSec adapter receives the new decision via LAPI WebSocket.
   - Core normalizes the decision into an SCSE event.
   - Core dispatches the decision to:
     - Edge firewall / WAF blocklist table.
     - Wazuh Manager (injected via syslog as a high-severity MITRE ATT&CK T1190 event).
5. **AI Semantic Guardrail (Promptfoo):**
   - For requests that pass WAF inspection and reach the AI API, SENTRIX Core forwards the prompt to Promptfoo's guardrail checking endpoint (`POST http://sentrix-promptfoo:15500/api/guardrails/check`).
   - If a prompt-injection or data-exfiltration pattern is recognized, Promptfoo returns a risk score; SENTRIX Core suppresses the model invocation and logs an AI Threat alert.

---

## Deliverable G: Security Event Normalisation Schema

SENTRIX normalizes all incoming engine events into the **SENTRIX Common Security Event (SCSE)** schema (version 1.0.0), aligned with the Open Cybersecurity Schema Framework (OCSF) v1.1.0:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "SentrixCommonSecurityEvent",
  "type": "object",
  "required": [
    "event_id",
    "timestamp",
    "engine",
    "severity",
    "category",
    "action_taken",
    "source",
    "target"
  ],
  "properties": {
    "event_id": {
      "type": "string",
      "format": "uuid",
      "description": "Unique identifier for this normalized security event"
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of event detection"
    },
    "engine": {
      "type": "string",
      "enum": ["coraza", "crowdsec", "modsecurity", "promptfoo", "wazuh"],
      "description": "Source engine that generated the original telemetry"
    },
    "severity": {
      "type": "string",
      "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    },
    "category": {
      "type": "string",
      "enum": [
        "WEB_APPLICATION_ATTACK",
        "NETWORK_INTRUSION",
        "HOST_ENDPOINT_ANOMALY",
        "FILE_INTEGRITY_VIOLATION",
        "VULNERABILITY_CVE",
        "AI_PROMPT_INJECTION",
        "AI_JAILBREAK",
        "AI_DATA_LEAK",
        "POLICY_VIOLATION"
      ]
    },
    "action_taken": {
      "type": "string",
      "enum": ["BLOCKED", "DROPPED", "ALERTED", "REMEDIATED", "LOGGED", "PASSED"]
    },
    "source": {
      "type": "object",
      "properties": {
        "ip": { "type": "string" },
        "port": { "type": "integer" },
        "hostname": { "type": "string" },
        "user": { "type": "string" },
        "country": { "type": "string" }
      }
    },
    "target": {
      "type": "object",
      "properties": {
        "ip": { "type": "string" },
        "port": { "type": "integer" },
        "url": { "type": "string" },
        "endpoint": { "type": "string" },
        "file_path": { "type": "string" },
        "llm_model": { "type": "string" }
      }
    },
    "threat_details": {
      "type": "object",
      "properties": {
        "rule_id": { "type": "string" },
        "rule_name": { "type": "string" },
        "cve": { "type": "string" },
        "cwe": { "type": "string" },
        "mitre_attack": {
          "type": "object",
          "properties": {
            "tactic": { "type": "string" },
            "technique_id": { "type": "string" },
            "technique_name": { "type": "string" }
          }
        },
        "owasp_category": { "type": "string" },
        "confidence_score": { "type": "number", "minimum": 0.0, "maximum": 1.0 }
      }
    },
    "raw_event": {
      "type": "object",
      "description": "Original raw event payload from the detection engine"
    }
  }
}
```

---

## Deliverable H: Failure Isolation and Engine Health-Check Design

### 1. Process & Fault Isolation
- **Container Isolation:** Every engine runs in a separate Linux cgroup/container with enforced CPU and memory limits. A memory exhaustion crash or segmentation fault in ModSecurity (C++) or Promptfoo (Node.js) cannot crash the SENTRIX Core or disrupt other engines.
- **Fail-Open vs. Fail-Closed Routing Policies:**
  - **Coraza Ingress Proxy:** Defaults to **Fail-Closed** on critical engine crash (returns 503) for maximum security, with an operator toggle for **Fail-Open** in mission-critical availability environments.
  - **CrowdSec LAPI:** Operates with a **Local In-Memory Cache**; if CrowdSec restarts, existing active ban rules remain cached in firewall bouncers until lease expiration.
  - **Promptfoo AI Guardrails:** Defaults to **Fail-Safe Alert**; if Promptfoo is unreachable, inbound user prompts are permitted with an escalated security warning logged to Wazuh.
  - **Wazuh Agent Buffering:** If Wazuh Manager is temporarily offline or rebuilding, agents buffer events locally on disk (up to configured limits) without dropping security logs.

### 2. Engine Health-Check Specifications

| Component | Target URL / Probe | Expected Status | Check Interval | Timeout | Unhealthy Threshold |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Coraza WAF** | `GET http://sentrix-waf-coraza:8080/healthz` | `200 OK` | 5 sec | 2 sec | 3 failures |
| **CrowdSec LAPI**| `GET http://sentrix-crowdsec:8085/v1/health` | `200 OK` | 10 sec | 3 sec | 2 failures |
| **Promptfoo** | `GET http://sentrix-promptfoo:15500/healthz` | `200 OK` | 15 sec | 5 sec | 2 failures |
| **Wazuh API** | `GET https://sentrix-wazuh-manager:55000/` | `200 OK` | 15 sec | 5 sec | 3 failures |
| **SENTRIX Core**| `GET http://sentrix-core:9000/healthz` | `200 OK` | 5 sec | 1 sec | 2 failures |

### 3. Circuit Breaker Logic
SENTRIX Core implements an internal three-state circuit breaker (`Closed`, `Open`, `Half-Open`) for each engine adapter:
- **`Closed`:** Normal operation. Events and queries flow directly to the engine adapter.
- **`Open`:** Engine probe failed $\ge 3$ consecutive times. Outbound requests to this engine are temporarily halted; incoming events are buffered in a local disk queue; fallback policies activate.
- **`Half-Open`:** After a 30-second backoff, single test probes are dispatched. Success transitions the engine back to `Closed`; failure resets the timer.

---

## Deliverable I: Licensing and Distribution Boundary Documentation

To guarantee complete compliance with intellectual property laws and prevent viral copyleft licensing contamination, SENTRIX enforces strict legal boundaries:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          LICENSING BOUNDARY MATRIX                              │
├─────────────────────┬──────────────────┬─────────────────┬──────────────────────┤
│ Repository / Module │ License Type     │ Copyleft Scope  │ Distribution Boundary│
├─────────────────────┼──────────────────┼─────────────────┼──────────────────────┤
│ Coraza WAF          │ Apache 2.0       │ Permissive      │ Library / Container  │
│ CrowdSec            │ MIT              │ Permissive      │ Standalone Binary    │
│ ModSecurity 3       │ Apache 2.0       │ Permissive      │ Dynamic Library      │
│ Promptfoo           │ MIT              │ Permissive      │ Node Package / Svc   │
│ Wazuh (Core)        │ GPL-2.0          │ Strong Copyleft │ Isolated Daemon / Ctr│
│ Wazuh (Engine)      │ AGPL-3.0         │ Strong Network  │ Isolated Daemon / Ctr│
│ SENTRIX Core        │ Apache 2.0 / MIT │ Permissive      │ Orchestration Daemon │
└─────────────────────┴──────────────────┴─────────────────┴──────────────────────┘
```

### Legal Architecture Isolation Rules
1. **No In-Process Compilation with Wazuh:**
   - Under no circumstances should SENTRIX Core, Coraza, CrowdSec, or Promptfoo code be compiled into the same executable or statically linked with Wazuh's GPL-2.0 or AGPL-3.0 source code.
2. **Standardized Network Interfaces:**
   - All communication between SENTRIX Core and Wazuh is conducted exclusively over standard, documented network protocols:
     - Wazuh REST API over HTTPS (`https://127.0.0.1:55000`)
     - Standard Syslog over RFC 5424 UDP/TCP
     - Standard Unix domain sockets with JSON framing
   - Under established Free Software Foundation (FSF) and legal precedents, communicating across process boundaries using standard network protocols does not form a derivative work and prevents viral copyleft attachment.
3. **Preservation of Original Notices:**
   - Every directory under `engines/` retains its original `LICENSE`, `COPYING`, `AUTHORS`, and header copyright notices without alteration.

---

## Deliverable J: Prioritised Implementation Checklist

The remaining development effort is structured into prioritized, incremental phases:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     SENTRIX IMPLEMENTATION ROADMAP                             │
│                                                                                 │
│   PHASE 3: MONOREPO FOUNDATION & ENGINE CONTAINERIZATION                        │
│   ├── Task 3.1: Finalize monorepository directory structure and root Makefile   │
│   ├── Task 3.2: Create individual container build recipes (Dockerfiles)        │
│   ├── Task 3.3: Fetch ModSecurity submodules and create automated setup scripts │
│   └── Task 3.4: Validate independent compilation for all five engines           │
│                                                                                 │
│   PHASE 4: SENTRIX CORE SKELETON & ADAPTER INTERFACES                           │
│   ├── Task 4.1: Scaffold core/ module structure (Go 1.24+)                      │
│   ├── Task 4.2: Implement Engine Health Supervisor and circuit breakers         │
│   ├── Task 4.3: Implement Sentinel Common Security Event (SCSE) data structures │
│   └── Task 4.4: Implement CrowdSec LAPI and Coraza audit log adapters           │
│                                                                                 │
│   PHASE 5: EVENT PIPELINE & DUAL-WAF / AI ORCHESTRATION                         │
│   ├── Task 5.1: Deploy Coraza standalone WAF proxy (core/cmd/sentrix-waf)       │
│   ├── Task 5.2: Configure CrowdSec log acquisition from Coraza WAF              │
│   ├── Task 5.3: Integrate Promptfoo guardrail API for real-time prompt checks   │
│   └── Task 5.4: Integrate Wazuh REST API client & syslog alert forwarder        │
│                                                                                 │
│   PHASE 6: UNIFIED CLI, VERIFICATION & END-TO-END TESTING                       │
│   ├── Task 6.1: Build `sentrixctl` CLI for cross-engine health and status       │
│   ├── Task 6.2: Execute simulated multi-stage attack scenarios                  │
│   └── Task 6.3: Document production operational runbooks                        │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Detailed Implementation Checklist

- [ ] **Milestone 1: Repository Foundation & Verification (Immediate Next Step)**
  - [ ] Initialize root `Makefile` orchestrating engine-specific tasks.
  - [ ] Implement `scripts/init-submodules.sh` to initialize `engines/ModSecurity-3-master` submodules (`libinjection`, `mbedtls`).
  - [ ] Implement `scripts/setup-prereqs.ps1` and `scripts/setup-prereqs.sh` to validate developer toolchains.
  - [ ] Verify independent native builds of Coraza, CrowdSec, and Promptfoo on the local workstation.

- [ ] **Milestone 2: Containerization & Deployment Orchestration**
  - [ ] Author `deploy/docker/Dockerfile.coraza-waf` for standalone WAF proxying.
  - [ ] Author `deploy/docker/Dockerfile.crowdsec` with AppSec configurations.
  - [ ] Author `deploy/docker/Dockerfile.promptfoo` for headless evaluation and guardrail service.
  - [ ] Author `deploy/docker/Dockerfile.wazuh-manager` for isolated Linux SIEM execution.
  - [ ] Author `deploy/docker/Dockerfile.modsecurity` for benchmarking and verification.
  - [ ] Validate `docker-compose up` multi-container deployment on Windows (Docker Desktop WSL2).

- [ ] **Milestone 3: SENTRIX Core & Event Normalization**
  - [ ] Initialize `core/go.mod` with Go `1.24+`.
  - [ ] Codify `schemas/event-schema.json` and generate Go models in `core/pkg/models`.
  - [ ] Implement `core/internal/orchestrator` health checks for all five containers.
  - [ ] Implement `core/internal/normalizer` parsers for Coraza, CrowdSec, Promptfoo, and Wazuh.
  - [ ] Expose unified health and telemetry API on port `9000`.

- [ ] **Milestone 4: Unified Threat Pipeline & Integration**
  - [ ] Configure Coraza WAF to forward transaction audit logs to CrowdSec acquisition pipeline.
  - [ ] Implement Promptfoo guardrail middleware verifying AI prompts passing through SENTRIX Gateway.
  - [ ] Establish Wazuh Manager API client in SENTRIX Core to ingest host FIM and agent alerts.
  - [ ] Implement action arbitration broker preventing conflicting firewall bans between CrowdSec and Wazuh.

- [ ] **Milestone 5: Verification & End-to-End Validation**
  - [ ] Execute an automated test suite verifying each engine's independent build and run capability.
  - [ ] Run an automated penetration test (simulating Web exploit, AI prompt injection, and host file modification) confirming end-to-end normalization into SCSE events.
  - [ ] Verify zero licensing contamination across binary and package boundaries.

---

*End of Phase 2 Architecture Blueprint.*
