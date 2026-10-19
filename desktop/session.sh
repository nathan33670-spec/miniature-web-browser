#!/bin/sh
# Session graphique : serveur VNC (TigerVNC) + gestionnaire de fenêtres + Chromium.
set -eu

export DISPLAY=:1
export LANGUAGE="${LANG%%.*}"
RUNTIME=/tmp/session
mkdir -p "$RUNTIME"
chmod 700 "$RUNTIME"

# --- Serveur X/VNC --------------------------------------------------------------
if [ -n "${VNC_PASSWORD:-}" ]; then
  printf '%s\n' "$VNC_PASSWORD" | tigervncpasswd -f > "$RUNTIME/vncpasswd"
  chmod 600 "$RUNTIME/vncpasswd"
  SECURITY="-SecurityTypes VncAuth -PasswordFile $RUNTIME/vncpasswd"
else
  echo "ATTENTION : VNC_PASSWORD vide, le serveur VNC interne n'a pas de mot de passe."
  SECURITY="-SecurityTypes None"
fi

rm -f /tmp/.X1-lock /tmp/.X11-unix/X1
# shellcheck disable=SC2086
Xtigervnc :1 \
  -geometry "${SCREEN_RESOLUTION:-1600x900}" -depth 24 \
  -rfbport 5900 -UseIPv6=0 -AlwaysShared -AcceptSetDesktopSize=1 \
  -nolisten tcp $SECURITY &
XVNC_PID=$!

for _ in $(seq 1 50); do
  [ -S /tmp/.X11-unix/X1 ] && break
  sleep 0.2
done

openbox &

# --- Chromium ---------------------------------------------------------------------
# Le bac à sable de Chromium nécessite les espaces de noms utilisateur ; s'ils sont
# indisponibles dans le conteneur, on le désactive (le conteneur reste isolé).
SANDBOX_FLAG=""
if ! unshare --user --map-root-user true >/dev/null 2>&1; then
  echo "Espaces de noms utilisateur indisponibles : Chromium démarre avec --no-sandbox."
  SANDBOX_FLAG="--no-sandbox --test-type"
fi

# Arrêt du conteneur : on ferme Chromium proprement (profil et onglets sauvegardés).
STOPPING=0
CHROMIUM_PID=""
stop() {
  STOPPING=1
  [ -n "$CHROMIUM_PID" ] && kill -TERM "$CHROMIUM_PID" 2>/dev/null
}
trap stop TERM INT

while [ "$STOPPING" = 0 ] && kill -0 "$XVNC_PID" 2>/dev/null; do
  # Un seul Chromium tourne dans ce conteneur : les verrous restants viennent
  # d'un arrêt brutal ou d'un conteneur recréé (autre nom d'hôte).
  rm -f /data/profile/SingletonLock /data/profile/SingletonSocket /data/profile/SingletonCookie
  # shellcheck disable=SC2086
  chromium \
    --user-data-dir=/data/profile \
    --no-first-run --no-default-browser-check \
    --password-store=basic \
    --disable-gpu --disable-dev-shm-usage \
    --hide-crash-restore-bubble \
    --lang="${LANG%%_*}" \
    --start-maximized \
    $SANDBOX_FLAG ${CHROMIUM_FLAGS:-} \
    ${START_URL:-} &
  CHROMIUM_PID=$!
  # "wait" est interrompu par le signal : on attend ensuite la fin réelle de Chromium.
  wait "$CHROMIUM_PID" || true
  while kill -0 "$CHROMIUM_PID" 2>/dev/null; do sleep 0.2; done
  CHROMIUM_PID=""
  # Fenêtre fermée par l'utilisateur : on relance Chromium.
  [ "$STOPPING" = 0 ] && sleep 1
done

kill -TERM "$XVNC_PID" 2>/dev/null || true
