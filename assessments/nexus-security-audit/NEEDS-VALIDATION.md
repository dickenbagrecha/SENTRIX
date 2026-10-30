# NEXUS Security Audit — Needs Validation Guide

**Audit Target:** NEXUS Enterprise AI Platform  
**Standard:** Cloudflare Security Audit Specification (`NEEDS-VALIDATION.md`)  
**Audit Context:** Source-First Static Inspection on Local Windows Host  
**Status:** 2 Candidates Awaiting Safe Staging Validation

---

## Overview

Under Cloudflare Security Audit rules:
> *"If safe execution or independent verification is unavailable, record the limitation instead of inventing a result. Report the missing capability as a needs-validation blocker and give a safe validation plan."*

During the NEXUS source-code audit, 10 vulnerabilities were deterministically proven via static control-flow and sink analysis. However, 2 findings depend on runtime state, hardware characteristics, or external service daemons that cannot be safely simulated on a Windows development host without an OS-enforced network and process sandbox.

This document details the exact blockers and safe, non-destructive validation plans for both candidates.

---

## 1. Candidate: `nexus.db.rls.bypass`

### Metadata
- **Fingerprint:** `nexus.db.rls.bypass`
- **Candidate Title:** PostgreSQL Row-Level Security Isolation Bypass in Connection Pooling
- **Suspected Vulnerability Area:** [`tests/mock-target/server.js:381`](file:///c:/DICKEN-BAGRECHA/Local%20Disk%20%28D%29/Projects/SENTRIX/tests/mock-target/server.js#L381) / Database Connection Pool Wrapper
- **Suspected Impact:** Tenant context leakage across asynchronous pooled connections.

### Why It Could Not Be Confirmed Statically
1. **Missing Hardware / Service:** The audit environment is a read-only source checkout. A live PostgreSQL 16 server with active `pgvector` and PostgreSQL connection poolers (`pgBouncer` / `asyncpg`) is not currently provisioned or running.
2. **Missing OS-Enforced Sandbox:** Cloudflare audit rules mandate an OS-enforced sandbox (no external network, isolated loopback, low CPU/RAM limits) before executing database load tests or pool concurrency experiments. Windows does not provide native cgroups-based network namespaces without Docker/WSL2 configuration.

### Formal Blockers
- `blockers[0]`: A live PostgreSQL 16 server with active connection pooler is not running locally in this read-only source-code audit environment.
- `blockers[1]`: An OS-enforced network and process sandbox required by Cloudflare audit rules is unavailable on the local Windows host.

### Safe Validation Plan

#### Staging Local Plan
1. Launch PostgreSQL 16 using the official NEXUS compose manifest:
   ```bash
   docker compose -f deploy/docker/docker-compose.nexus.yml up -d nexus-postgres
   ```
2. Apply the RLS migrations:
   ```sql
   ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
   CREATE POLICY tenant_isolation_policy ON documents 
     FOR ALL 
     USING (tenant_id = current_setting('app.current_tenant_id', true));
   ```
3. Verify RLS is enabled:
   ```sql
   SELECT relname, relrowsecurity, relforcerowsecurity 
   FROM pg_class 
   WHERE relname = 'documents';
   ```
4. Execute pooled connection checkout test using synthetic personas:
   - Worker 1: Sets `SET LOCAL app.current_tenant_id = 'tenant-alpha'`; queries records.
   - Return connection to pool without `DISCARD ALL` or `RESET ALL`.
   - Worker 2: Acquires same physical connection without setting tenant context; queries records.
   - **Pass Criteria:** Worker 2 receives 0 rows or error.
   - **Fail Criteria (Vulnerability Confirmed):** Worker 2 receives records belonging to `tenant-alpha`.

#### Deployment / CI Plan
- In the staging Kubernetes cluster, deploy `pgBouncer` with `pool_mode = transaction`.
- Ensure connection pool parameters include `server_reset_query = DISCARD ALL`.

---

## 2. Candidate: `nexus.llm.token.flooding`

### Metadata
- **Fingerprint:** `nexus.llm.token.flooding`
- **Candidate Title:** LLM Inference Denial of Service via Massive Token Flooding
- **Suspected Vulnerability Area:** [`tests/mock-target/server.js:455`](file:///c:/DICKEN-BAGRECHA/Local%20Disk%20%28D%29/Projects/SENTRIX/tests/mock-target/server.js#L455) / Inference API Gateway
- **Suspected Impact:** Host GPU out-of-memory or API thread starvation.

### Why It Could Not Be Confirmed Statically
1. **Missing Hardware / GPU Weights:** The audit environment does not have a running Ollama daemon hosting the `llama3.2:3b` model weights. Inference latency and memory degradation cannot be directly observed without physical model execution.
2. **Denial-of-Service Prohibition:** Sending 50,000+ character payloads to live production or unisolated test services violates safety rules regarding unrestricted load tests.

### Formal Blockers
- `blockers[0]`: Local GPU and Ollama daemon hosting llama3.2:3b model weights are not mounted in this read-only source-code audit environment.
- `blockers[1]`: Unrestricted token flooding load tests are prohibited during static audit without an isolated OS sandbox.

### Safe Validation Plan

#### Staging Local Plan
1. Start a local Ollama daemon on loopback port 11434 with resource bounds:
   ```bash
   ollama run llama3.2:3b
   ```
2. In an isolated staging environment with GPU monitoring (`nvidia-smi -l 1`), dispatch a controlled test prompt of 50,000 characters to `/api/v1/assistant/chat-stream`.
3. Measure:
   - Request latency (does response time exceed 5,000ms?).
   - GPU VRAM consumption.
   - Whether the API gateway accepts the oversized payload or rejects it with HTTP 413 / 422 before dispatching to the model engine.
4. **Pass Criteria:** API gateway rejects prompt immediately (`HTTP 422: Prompt exceeds 4,096 token maximum`).
5. **Fail Criteria (Vulnerability Confirmed):** Gateway passes 50,000 characters to Ollama, causing VRAM spike and thread starvation.

#### Deployment / CI Plan
- Integrate Pydantic schema validation into the FastAPI gateway:
  ```python
  class ChatRequest(BaseModel):
      prompt: str = Field(..., max_length=16384) # Strict 4k token safety limit
  ```
- Run automated contract tests validating HTTP 422 on oversized inputs.
