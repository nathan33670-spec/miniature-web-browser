FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      chromium chromium-l10n \
      tigervnc-standalone-server tigervnc-tools \
      openbox tint2 \
      fonts-noto-core fonts-noto-cjk fonts-noto-color-emoji fonts-liberation2 fonts-dejavu-core \
      locales tzdata ca-certificates tini util-linux xdg-utils \
 && sed -i 's/^# *\(fr_FR.UTF-8\)/\1/; s/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen \
 && locale-gen \
 && rm -rf /var/lib/apt/lists/*

COPY openbox-rc.xml /etc/xdg/openbox/rc.xml
COPY tint2rc /etc/xdg/tint2/tint2rc
COPY remote-chromium.desktop /usr/local/share/applications/remote-chromium.desktop
COPY chromium-window /usr/local/bin/chromium-window
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY session.sh /usr/local/bin/session.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/session.sh /usr/local/bin/chromium-window

ENV LANG=fr_FR.UTF-8 \
    TZ=Europe/Paris \
    SCREEN_RESOLUTION=1600x900 \
    START_URL=https://www.google.fr

EXPOSE 5900
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
