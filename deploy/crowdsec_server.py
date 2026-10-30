#!/usr/bin/env python3
"""
SENTRIX CrowdSec Local API (LAPI) Integration Service (Port 8085)
Provides schema-compliant HTTP endpoints matching CrowdSec v1.6.0 LAPI:
- GET /v1/heartbeat: LAPI service heartbeat
- GET /v1/health: Core health probe
- GET /v1/decisions: Active IP remediation decisions
- GET /v1/alerts: Alert ingestion log
- POST /v1/watchers/login: Machine authentication

Clearly marked as a local schema-compliant mock service when upstream
Docker/Linux daemon is unmounted.
"""

import sys
import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from urllib.parse import urlparse

PORT = int(os.environ.get("CROWDSEC_PORT", "8085"))

class CrowdSecLAPIHandler(BaseHTTPRequestHandler):
    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-CrowdSec-Engine", "SENTRIX-CrowdSec-LAPI-Mock")
        self.send_header("X-CrowdSec-Version", "v1.6.0")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ["/v1/heartbeat", "/healthz"]:
            self.send_json(200, {
                "status": "ok",
                "version": "v1.6.0-mock",
                "engine": "crowdsec",
                "service": "sentrix-crowdsec-lapi",
                "is_mock_service": True,
                "notes": "Lightweight LAPI schema mock; upstream engine requires Docker/Linux environment.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        elif path == "/v1/health":
            self.send_json(200, {"status": "ok"})
        elif path == "/v1/decisions":
            self.send_json(200, [
                {
                    "id": 1,
                    "origin": "cscli",
                    "type": "ban",
                    "scope": "Ip",
                    "value": "198.51.100.42",
                    "duration": "4h",
                    "scenario": "sentrix/aggressive-sqli"
                }
            ])
        elif path == "/v1/alerts":
            self.send_json(200, [])
        else:
            self.send_json(404, {"error": "Not Found", "path": path})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/v1/watchers/login":
            self.send_json(200, {
                "code": 200,
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sentrix-mock-token",
                "expire": "2026-10-31T23:59:59Z"
            })
        elif path == "/v1/alerts":
            self.send_json(201, {"message": "alert created", "id": 101})
        else:
            self.send_json(404, {"error": "Not Found", "path": path})

def run():
    server_address = ('127.0.0.1', PORT)
    httpd = HTTPServer(server_address, CrowdSecLAPIHandler)
    print(f"[CROWDSEC-LAPI-MOCK] Serving CrowdSec LAPI on http://127.0.0.1:{PORT}...")
    sys.stdout.flush()
    httpd.serve_forever()

if __name__ == '__main__':
    run()
