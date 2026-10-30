# NEXUS — PRODUCTION-GRADE DEPLOYMENT & OPERATION RUNBOOK

**Target Platform:** NEXUS Enterprise AI Document Intelligence & Retrieval-Augmented Generation (RAG) Platform  
**Document Type:** Engineering Deployment Runbook & Environment Operations Manual  
**Author / DevOps Lead:** Antigravity Engineering Team  
**Primary Recipient:** Nikhil (Lead Developer & Operations Engineer)  
**Date & Timestamp:** 2026-10-31 03:20 UTC+05:30  
**Status:** Validated Technical Specification & Deployment Guide  

---

## 1. System Architecture & Prerequisites

NEXUS is designed as a secure, multi-tenant enterprise intelligence platform consisting of:
1. **Frontend:** Modern Single-Page Application (React 18 / Vite / TypeScript / Tailwind CSS).
2. **Backend API:** High-performance asynchronous API gateway (Python 3.11 / FastAPI or Node.js / Express).
3. **Primary Database:** PostgreSQL 16 with the `pgvector` extension for semantic embedding storage and Row-Level Security (RLS) policies.
4. **Cache & State Store:** Redis 7 (Alpine) for token blacklisting, session validation, and tenant-scoped caching.
5. **Local Inference Engine:** Ollama running quantized embedding models (`nomic-embed-text`) and LLM chat models (`llama3.2:3b` or `mistral:7b`).

### Minimum Hardware & Environment Requirements
- **Host OS:** Ubuntu 22.04 LTS / Debian 12 / Windows 11 with WSL2.
- **CPU:** 4+ Cores (x86_64 or ARM64).
- **RAM:** Minimum 8 GB (16 GB recommended when running local Ollama inference alongside PostgreSQL).
- **Disk:** 30 GB SSD free space (for vector indices and Ollama model weights).
- **Software Dependencies:**
  - Docker Engine v24+ and Docker Compose v2.20+
  - Node.js v20.x or v22.x LTS & npm v10+
  - Python 3.11+
  - PostgreSQL 16 client tools (`psql`)
  - `curl` / `git`

---

## 2. Environment Configuration (`.env`)

Create `.env` in the NEXUS root directory. Use the following validated template. **Never commit `.env` to source control.**

```bash
# ==============================================================================
# NEXUS PLATFORM CONFIGURATION (STAGING & PRODUCTION TEMPLATE)
# ==============================================================================

# Application Environment
NODE_ENV=production
NEXUS_ENVIRONMENT=staging
LOG_LEVEL=info
PORT=9500
HOST=0.0.0.0

# Security & Cryptography
# Generate via: openssl rand -hex 32
JWT_SECRET_KEY=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=60
REFRESH_TOKEN_EXPIRATION_DAYS=7

# Database Connection (PostgreSQL 16 + pgvector)
DATABASE_HOST=127.0.0.1
DATABASE_PORT=5432
DATABASE_NAME=nexus_db
DATABASE_USER=nexus_user
DATABASE_PASSWORD=NexusSecureDbPassword2026!
DATABASE_URL=postgresql://nexus_user:NexusSecureDbPassword2026!@127.0.0.1:5432/nexus_db
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# Redis Cache & Token Revocation
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=NexusRedisSecurePassword2026!
REDIS_URL=redis://:NexusRedisSecurePassword2026!@127.0.0.1:6379/0

# Generative AI & Local Ollama Inference
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_CHAT_MODEL=llama3.2:3b
OLLAMA_EMBED_MODEL=nomic-embed-text
LLM_MAX_PROMPT_TOKENS=4096
LLM_REQUEST_TIMEOUT_SECONDS=30

# File Upload & Document Ingestion Guardrails
MAX_UPLOAD_FILE_SIZE_MB=25
ALLOWED_FILE_EXTENSIONS=.pdf,.docx,.xlsx,.txt
DECOMPRESSION_MAX_RATIO=20
DECOMPRESSION_MAX_BYTES=52428800 # 50 MB

# SENTRIX Security Auditing Scope Guardrail
SENTRIX_SCOPE_TOKEN=AUTH-SCOPE-NEXUS-STAGING-CONFIRMED
SENTRIX_ALLOWED_AUDIT_HOSTS=127.0.0.1,localhost,staging.nexus.local
```

---

## 3. Database Setup: PostgreSQL 16 with pgvector & RLS

Execute the following commands to provision the database, install the vector extension, and configure tenant Row-Level Security.

### 3.1 Provision Database Container
```bash
docker run -d \
  --name nexus-postgres \
  -p 5432:5432 \
  -e POSTGRES_DB=nexus_db \
  -e POSTGRES_USER=nexus_user \
  -e POSTGRES_PASSWORD=NexusSecureDbPassword2026! \
  -v nexus_pgdata:/var/lib/postgresql/data \
  --restart unless-stopped \
  pgvector/pgvector:pg16
```

### 3.2 Initialize Extensions and Row-Level Security
Connect via `psql` and execute the schema initialization script:
```sql
-- Connect to nexus_db
\c nexus_db;

-- 1. Install pgvector extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS vector;

-- 2. Create Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Create Documents Table with Tenant Isolation
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    embedding vector(768), -- Dimension for nomic-embed-text
    status VARCHAR(32) DEFAULT 'pending',
    version INT DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Enable Row-Level Security (RLS)
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- 5. Define Strict Tenant Isolation Policy
CREATE POLICY tenant_isolation_policy ON documents
    AS RESTRICTIVE
    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid);

-- 6. Insert Synthetic Benchmarking Tenants
INSERT INTO tenants (slug, name) VALUES 
('tenant-alpha', 'Tenant Alpha Corp'),
('tenant-beta', 'Tenant Beta Logistics')
ON CONFLICT (slug) DO NOTHING;
```

---

## 4. Redis Cache & Session Invalidation Setup

```bash
docker run -d \
  --name nexus-redis \
  -p 6379:6379 \
  -v nexus_redisdata:/data \
  --restart unless-stopped \
  redis:7-alpine redis-server --requirepass "NexusRedisSecurePassword2026!" --appendonly yes
```

Verify Redis connectivity:
```bash
docker exec -it nexus-redis redis-cli -a "NexusRedisSecurePassword2026!" PING
# Expected response: PONG
```

---

## 5. Local AI Engine: Ollama Setup

### 5.1 Launch Ollama Container
```bash
docker run -d \
  --name nexus-ollama \
  -p 11434:11434 \
  -v nexus_ollama:/root/.ollama \
  --restart unless-stopped \
  ollama/ollama:latest
```

### 5.2 Pull Embedding and LLM Models
```bash
# Pull lightweight embeddings model (768 dimensions, ~274 MB)
docker exec -it nexus-ollama ollama pull nomic-embed-text

# Pull compact chat/instruction model (~2.0 GB)
docker exec -it nexus-ollama ollama pull llama3.2:3b
```

### 5.3 Test Local Inference
```bash
curl -s http://127.0.0.1:11434/api/generate -d '{
  "model": "llama3.2:3b",
  "prompt": "Respond with OK if online.",
  "stream": false
}' | grep -o '"response":"[^"]*"'
```

---

## 6. Docker Compose Deployment (Recommended)

To deploy the entire NEXUS backend stack in a single reproducible command, use `deploy/docker/docker-compose.nexus.yml`:

```yaml
version: '3.8'

services:
  nexus-postgres:
    image: pgvector/pgvector:pg16
    container_name: nexus-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: nexus_db
      POSTGRES_USER: nexus_user
      POSTGRES_PASSWORD: NexusSecureDbPassword2026!
    ports:
      - "127.0.0.1:5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nexus_user -d nexus_db"]
      interval: 5s
      timeout: 5s
      retries: 5

  nexus-redis:
    image: redis:7-alpine
    container_name: nexus-redis
    restart: unless-stopped
    command: ["redis-server", "--requirepass", "NexusRedisSecurePassword2026!", "--appendonly", "yes"]
    ports:
      - "127.0.0.1:6379:6379"
    volumes:
      - redisdata:/data
    healthcheck:
      test: ["CMD", "redis-cli", "-a", "NexusRedisSecurePassword2026!", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  nexus-ollama:
    image: ollama/ollama:latest
    container_name: nexus-ollama
    restart: unless-stopped
    ports:
      - "127.0.0.1:11434:11434"
    volumes:
      - ollamadata:/root/.ollama

  nexus-backend:
    build:
      context: ../../
      dockerfile: deploy/docker/Dockerfile.nexus-backend
    container_name: nexus-backend
    restart: unless-stopped
    ports:
      - "9500:9500"
    env_file:
      - ../../.env
    depends_on:
      nexus-postgres:
        condition: service_healthy
      nexus-redis:
        condition: service_healthy

volumes:
  pgdata:
  redisdata:
  ollamadata:
```

### Execution Command:
```bash
docker compose -f deploy/docker/docker-compose.nexus.yml up -d
```

---

## 7. Native Host Startup (Development & Testing)

If running outside Docker for rapid development:

### 7.1 Backend API (FastAPI / Node.js)
```bash
# If Python FastAPI:
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 9500 --reload

# If Node.js / Express:
npm install
npm run dev
```

### 7.2 Frontend (Vite / React)
```bash
cd frontend
npm install
npm run build # Validates TypeScript types and bundle integrity
npm run dev   # Starts dev server on http://localhost:5173
```

---

## 8. Post-Deployment Verification Checklist

Execute these exact verification commands to confirm all NEXUS subsystems are healthy before running SENTRIX security audits:

| Component | Test Command | Expected Output |
| :--- | :--- | :--- |
| **API Health** | `curl -i http://127.0.0.1:9500/healthz` | `HTTP/1.1 200 OK` `{"status":"HEALTHY"}` |
| **PostgreSQL RLS** | `docker exec nexus-postgres psql -U nexus_user -d nexus_db -c "SELECT relname, relrowsecurity FROM pg_class WHERE relname='documents';"` | `documents \| t` |
| **Redis Auth** | `docker exec nexus-redis redis-cli -a "NexusRedisSecurePassword2026!" ping` | `PONG` |
| **Ollama Health** | `curl -s http://127.0.0.1:11434/api/tags` | List of models including `nomic-embed-text` |

---

## 9. Troubleshooting & Operational Playbook

### 1. Database Connection Refused (`5432`)
- **Cause:** PostgreSQL container still initializing or volume permissions locked.
- **Fix:** Check container logs: `docker logs nexus-postgres`. Ensure port 5432 is not occupied by a host PostgreSQL instance.

### 2. Ollama Out of Memory (OOM)
- **Cause:** Loading 7B or 13B models on a system with <8 GB RAM.
- **Fix:** Default to quantized small models: `ollama run llama3.2:3b`. Set environment variable `OLLAMA_NUM_PARALLEL=1` to restrict concurrent inference threads.

### 3. Cross-Tenant Leakage During Audits
- **Cause:** Missing `SET LOCAL app.current_tenant_id = :id;` inside transactional blocks.
- **Fix:** Ensure the database connection pool reset hook issues `RESET ALL;` upon returning connections to the pool.
