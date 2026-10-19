FROM node:22-alpine

RUN apk add --no-cache openssl su-exec tini

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src ./src
COPY public ./public
COPY bin ./bin
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV NODE_ENV=production \
    LISTEN_PORT=8443

EXPOSE 8443
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "/app/bin/healthcheck.js"]

ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
CMD ["node", "/app/src/index.js"]
