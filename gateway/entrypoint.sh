#!/bin/sh
set -eu

DATA_DIR=/data
TLS_MODE=$(echo "${TLS_MODE:-self-signed}" | tr '[:upper:]' '[:lower:]')

# Commandes utilitaires : docker compose run --rm -it gateway hash-password
case "${1:-}" in
  hash-password|generate-totp)
    exec node /app/bin/cli.js "$@"
    ;;
esac

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$DATA_DIR/tls"

  if [ "$TLS_MODE" = "self-signed" ]; then
    CERT="${TLS_CERT_FILE:-$DATA_DIR/tls/cert.pem}"
    KEY="${TLS_KEY_FILE:-$DATA_DIR/tls/key.pem}"
    if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
      CN="${TLS_COMMON_NAME:-remote-browser}"
      echo "Génération d'un certificat auto-signé (CN=$CN)…"
      openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
        -keyout "$KEY" -out "$CERT" -subj "/CN=$CN" \
        -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
      chmod 600 "$KEY"
    fi
  fi

  chown -R node:node "$DATA_DIR"
  exec su-exec node "$@"
fi

exec "$@"
