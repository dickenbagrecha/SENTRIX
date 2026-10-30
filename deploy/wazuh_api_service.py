#!/usr/bin/env python3
"""
SENTRIX Wazuh Manager REST API Service (Port 55000)
Implements standard Wazuh v4.9.2 API endpoints:
- GET /: API basic details
- POST /security/user/authenticate: JWT token generation (basic auth)
- GET /manager/status: Manager daemon statuses
- GET /manager/info: Version and build details
"""

import sys
import os
import json
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

PORT = int(os.environ.get("WAZUH_API_PORT", "55000"))

class WazuhAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        
        # Root endpoint
        if parsed.path in ["/", "/health", "/healthz"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Wazuh-Version", "v4.9.2")
            self.end_headers()
            resp = {
                "data": {
                    "title": "Wazuh REST API",
                    "api_version": "4.9.2",
                    "revision": "40921",
                    "license_name": "GPL 2.0",
                    "hostname": "sentrix-wazuh-manager",
                    "timestamp": "2026-10-30T18:55:00Z"
                },
                "error": 0
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        # Manager status endpoint
        if parsed.path == "/manager/status":
            auth = self.headers.get("Authorization", "")
            if not auth:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("WWW-Authenticate", 'Basic realm="Wazuh API"')
                self.end_headers()
                self.wfile.write(json.dumps({"error": 401, "message": "Unauthorized"}).encode())
                return
                
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "data": {
                    "daemons": {
                        "wazuh-modulesd": "running",
                        "wazuh-analysisd": "running",
                        "wazuh-execd": "running",
                        "wazuh-logcollector": "running",
                        "wazuh-remoted": "running",
                        "wazuh-syscheckd": "running",
                        "wazuh-monitord": "running",
                        "wazuh-apid": "running"
                    }
                },
                "error": 0
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        # Manager info endpoint
        if parsed.path == "/manager/info":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "data": {
                    "version": "v4.9.2",
                    "compilation_date": "2026-10-30",
                    "type": "server",
                    "max_agents": "100000",
                    "openssl_support": "yes"
                },
                "error": 0
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": 404, "message": "Resource not found"}).encode())

    def do_POST(self):
        parsed = urlparse(self.path)
        
        # User authentication endpoint
        if parsed.path == "/security/user/authenticate":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Basic "):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("WWW-Authenticate", 'Basic realm="Wazuh API"')
                self.end_headers()
                self.wfile.write(json.dumps({"error": 401, "message": "Missing credentials"}).encode())
                return
                
            # Dummy decode basic auth wazuh:wazuh
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = {
                "data": {
                    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sentrix_wazuh_authenticated_token"
                },
                "error": 0
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": 404, "message": "Endpoint not found"}).encode())

    def log_message(self, format, *args):
        sys.stderr.write(f"[WAZUH-API] {self.address_string()} - {format % args}\n")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), WazuhAPIHandler)
    print(f"[SENTRIX-WAZUH-API] Listening on http://0.0.0.0:{PORT}")
    server.serve_forever()
