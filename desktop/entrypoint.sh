#!/bin/sh
# Prépare l'utilisateur non-root puis lance la session graphique sous son identité.
set -eu

PUID=${PUID:-1000}
PGID=${PGID:-1000}

if ! getent group "$PGID" >/dev/null 2>&1; then
  groupadd -o -g "$PGID" browser
fi
if ! getent passwd "$PUID" >/dev/null 2>&1; then
  useradd -o -u "$PUID" -g "$PGID" -d /data -M -s /bin/sh browser
fi

mkdir -p /data/profile /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix
if [ "$(stat -c %u /data)" != "$PUID" ] || [ "$(stat -c %u /data/profile)" != "$PUID" ]; then
  chown -R "$PUID:$PGID" /data
fi

exec setpriv --reuid="$PUID" --regid="$PGID" --init-groups --reset-env \
  env HOME=/data LANG="${LANG:-fr_FR.UTF-8}" TZ="${TZ:-Europe/Paris}" \
      SCREEN_RESOLUTION="${SCREEN_RESOLUTION:-1600x900}" START_URL="${START_URL:-}" \
      CHROMIUM_FLAGS="${CHROMIUM_FLAGS:-}" VNC_PASSWORD="${VNC_PASSWORD:-}" \
      PATH=/usr/local/bin:/usr/bin:/bin \
  /usr/local/bin/session.sh
