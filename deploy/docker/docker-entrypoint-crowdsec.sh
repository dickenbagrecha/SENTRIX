#!/bin/sh
set -e

# Initialize necessary runtime directories
mkdir -p /etc/crowdsec/hub \
         /etc/crowdsec/parsers \
         /etc/crowdsec/scenarios \
         /etc/crowdsec/collections \
         /etc/crowdsec/postoverflows \
         /etc/crowdsec/acquis.d \
         /var/lib/crowdsec/data \
         /var/log/crowdsec

# Ensure hub index exists
if [ ! -f /etc/crowdsec/hub/.index.json ]; then
    echo "[SENTRIX-CROWDSEC] Initializing hub index..."
    cscli hub update || true
fi

# Configure Local API address to 0.0.0.0:8085 if default
if [ -f /etc/crowdsec/config.yaml ]; then
    sed -i 's/127.0.0.1:8080/0.0.0.0:8085/g' /etc/crowdsec/config.yaml
    sed -i 's/daemonize: true/daemonize: false/g' /etc/crowdsec/config.yaml
    sed -i 's/log_media: file/log_media: stdout/g' /etc/crowdsec/config.yaml
fi

# Ensure local machine watcher credentials exist
if ! grep -q "login:" /etc/crowdsec/local_api_credentials.yaml 2>/dev/null; then
    echo "[SENTRIX-CROWDSEC] Registering local machine watcher..."
    cscli machines add sentrix-node --auto -u http://127.0.0.1:8085/ -f /etc/crowdsec/local_api_credentials.yaml --force || true
fi

# Configure default audit log datasource if none configured
if [ ! -f /etc/crowdsec/acquis.d/sentrix.yaml ]; then
    echo "[SENTRIX-CROWDSEC] Configuring audit log acquisition..."
    cat <<EOF > /etc/crowdsec/acquis.d/sentrix.yaml
filenames:
  - /var/log/sentrix-audit.log
labels:
  type: syslog
EOF
    touch /var/log/sentrix-audit.log
fi

echo "[SENTRIX-CROWDSEC] Starting CrowdSec daemon..."
exec /usr/local/bin/crowdsec -c /etc/crowdsec/config.yaml "$@"
