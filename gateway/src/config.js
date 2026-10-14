'use strict';

const DEFAULT_PUBLIC_IP_URLS = [
  'https://api.ipify.org',
  'https://ipv4.icanhazip.com',
  'https://v4.ident.me',
];

function list(value) {
  return String(value || '')
    .split(/[,;\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function bool(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  return ['1', 'true', 'yes', 'on', 'oui'].includes(String(value).trim().toLowerCase());
}

function num(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) throw new Error(`Valeur numérique invalide : "${value}"`);
  return n;
}

function loadConfig(env = process.env) {
  const config = {
    listen: {
      host: env.LISTEN_HOST || '0.0.0.0',
      port: num(env.LISTEN_PORT, 8443),
    },
    upstream: {
      url: env.UPSTREAM_URL || 'http://chromium:3000',
      username: env.UPSTREAM_USERNAME || '',
      password: env.UPSTREAM_PASSWORD || '',
    },
    auth: {
      username: env.AUTH_USERNAME || 'admin',
      passwordHash: env.AUTH_PASSWORD_HASH || '',
      password: env.AUTH_PASSWORD || '',
      totpSecret: (env.TOTP_SECRET || '').replace(/\s+/g, '').toUpperCase(),
    },
    session: {
      cookieName: env.SESSION_COOKIE_NAME || 'rb_session',
      ttlMs: num(env.SESSION_TTL_HOURS, 12) * 3600_000,
      idleMs: num(env.SESSION_IDLE_MINUTES, 120) * 60_000,
      cookieSecure: (env.COOKIE_SECURE || 'auto').toLowerCase(),
    },
    login: {
      maxAttempts: num(env.LOGIN_MAX_ATTEMPTS, 5),
      windowMs: num(env.LOGIN_WINDOW_MINUTES, 15) * 60_000,
      lockoutMs: num(env.LOGIN_LOCKOUT_MINUTES, 30) * 60_000,
      failureDelayMs: num(env.LOGIN_FAILURE_DELAY_MS, 1000),
    },
    access: {
      ipv4Only: bool(env.IPV4_ONLY, true),
      enabled: bool(env.IP_RESTRICTION_ENABLED, false),
      allowlist: list(env.IP_ALLOWLIST),
      nasIps: list(env.NAS_IPS),
      trustDockerGateway: bool(env.TRUST_DOCKER_GATEWAY, true),
      allowPublicIp: bool(env.ALLOW_SERVER_PUBLIC_IP, true),
      publicIps: list(env.SERVER_PUBLIC_IP),
      publicHostnames: list(env.SERVER_PUBLIC_HOSTNAMES),
      publicIpAutodetect: bool(env.PUBLIC_IP_AUTODETECT, true),
      publicIpUrls: env.PUBLIC_IP_DETECT_URLS ? list(env.PUBLIC_IP_DETECT_URLS) : DEFAULT_PUBLIC_IP_URLS,
      publicIpRefreshMs: num(env.PUBLIC_IP_REFRESH_MINUTES, 10) * 60_000,
      trustedProxies: list(env.TRUSTED_PROXIES),
    },
    tls: {
      mode: (env.TLS_MODE || 'self-signed').toLowerCase(),
      certFile: env.TLS_CERT_FILE || '/data/tls/cert.pem',
      keyFile: env.TLS_KEY_FILE || '/data/tls/key.pem',
    },
    logLevel: (env.LOG_LEVEL || 'info').toLowerCase(),
  };

  validate(config);
  return config;
}

function validate(config) {
  if (!config.auth.passwordHash && !config.auth.password) {
    throw new Error(
      'Aucun mot de passe configuré. Générez un hash avec :\n' +
        '  docker compose run --rm -it gateway hash-password\n' +
        'puis renseignez AUTH_PASSWORD_HASH dans le fichier .env'
    );
  }
  if (config.auth.passwordHash && !config.auth.passwordHash.startsWith('scrypt:')) {
    throw new Error('AUTH_PASSWORD_HASH doit être au format "scrypt:..." (utilisez la commande hash-password).');
  }
  if (config.auth.totpSecret && !/^[A-Z2-7]+=*$/.test(config.auth.totpSecret)) {
    throw new Error('TOTP_SECRET doit être une chaîne base32 (utilisez la commande generate-totp).');
  }
  if (!['self-signed', 'custom', 'off'].includes(config.tls.mode)) {
    throw new Error('TLS_MODE doit valoir "self-signed", "custom" ou "off".');
  }
  if (!['auto', 'true', 'false'].includes(config.session.cookieSecure)) {
    throw new Error('COOKIE_SECURE doit valoir "auto", "true" ou "false".');
  }
  if (config.access.ipv4Only) {
    const net = require('node:net');
    if (net.isIPv6(config.listen.host)) {
      throw new Error(`LISTEN_HOST=${config.listen.host} est une adresse IPv6 alors que IPV4_ONLY=true.`);
    }
    for (const [name, entries] of [
      ['IP_ALLOWLIST', config.access.allowlist],
      ['NAS_IPS', config.access.nasIps],
      ['SERVER_PUBLIC_IP', config.access.publicIps],
    ]) {
      const v6 = entries.filter((e) => e.includes(':'));
      if (v6.length) throw new Error(`${name} contient des adresses IPv6 (${v6.join(', ')}) alors que IPV4_ONLY=true.`);
    }
  }
  try {
    new URL(config.upstream.url);
  } catch {
    throw new Error(`UPSTREAM_URL invalide : "${config.upstream.url}"`);
  }
}

module.exports = { loadConfig, list, bool };
