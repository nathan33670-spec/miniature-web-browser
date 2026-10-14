'use strict';

const http = require('node:http');
const https = require('node:https');

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function stripHopByHop(headers) {
  const out = { ...headers };
  const connection = String(headers.connection || '');
  for (const name of connection.split(',')) delete out[name.trim().toLowerCase()];
  for (const name of HOP_BY_HOP) delete out[name];
  return out;
}

function removeCookie(cookieHeader, name) {
  if (!cookieHeader) return undefined;
  const kept = cookieHeader
    .split(';')
    .map((c) => c.trim())
    .filter((c) => c && c.split('=')[0] !== name);
  return kept.length ? kept.join('; ') : undefined;
}

class Proxy {
  constructor({ url, username, password, cookieName }) {
    this.target = new URL(url);
    this.module = this.target.protocol === 'https:' ? https : http;
    this.agent = new this.module.Agent({ keepAlive: true, maxSockets: 256 });
    this.cookieName = cookieName;
    this.basicAuth = password ? 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64') : null;
  }

  requestOptions(req, ctx, headers) {
    headers['x-forwarded-for'] = ctx.clientIp;
    headers['x-real-ip'] = ctx.clientIp;
    headers['x-forwarded-proto'] = ctx.secure ? 'https' : 'http';
    if (req.headers.host) headers['x-forwarded-host'] = req.headers.host;
    const cookie = removeCookie(req.headers.cookie, this.cookieName);
    if (cookie) headers.cookie = cookie;
    else delete headers.cookie;
    delete headers.authorization;
    if (this.basicAuth) headers.authorization = this.basicAuth;
    return {
      protocol: this.target.protocol,
      hostname: this.target.hostname,
      port: this.target.port || (this.target.protocol === 'https:' ? 443 : 80),
      method: req.method,
      path: req.url,
      headers,
      // Le conteneur Chromium utilise un certificat auto-signé sur son port HTTPS interne.
      rejectUnauthorized: false,
    };
  }

  web(req, res, ctx, onError) {
    const headers = stripHopByHop(req.headers);
    const options = { ...this.requestOptions(req, ctx, headers), agent: this.agent };
    const upstream = this.module.request(options, (upRes) => {
      res.writeHead(upRes.statusCode, upRes.statusMessage, stripHopByHop(upRes.headers));
      upRes.pipe(res);
      upRes.on('error', () => res.destroy());
    });
    upstream.on('error', (err) => onError(err));
    req.on('aborted', () => upstream.destroy());
    req.pipe(upstream);
  }

  ws(req, socket, head, ctx, onUpgraded) {
    const headers = stripHopByHop(req.headers);
    headers.connection = 'Upgrade';
    headers.upgrade = req.headers.upgrade;
    const options = { ...this.requestOptions(req, ctx, headers), agent: false };
    const upstream = this.module.request(options);

    upstream.on('upgrade', (upRes, upSocket, upHead) => {
      let out = `HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n`;
      for (let i = 0; i < upRes.rawHeaders.length; i += 2) {
        out += `${upRes.rawHeaders[i]}: ${upRes.rawHeaders[i + 1]}\r\n`;
      }
      socket.write(out + '\r\n');
      if (upHead && upHead.length) socket.write(upHead);
      if (head && head.length) upSocket.write(head);
      socket.setNoDelay(true);
      upSocket.setNoDelay(true);
      socket.setTimeout(0);
      upSocket.on('error', () => socket.destroy());
      socket.on('error', () => upSocket.destroy());
      upSocket.on('close', () => socket.destroy());
      socket.on('close', () => upSocket.destroy());
      upSocket.pipe(socket);
      socket.pipe(upSocket);
      onUpgraded();
    });

    // L'amont a refusé l'upgrade : on relaie sa réponse telle quelle.
    upstream.on('response', (upRes) => {
      let out = `HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage}\r\n`;
      const headersOut = stripHopByHop(upRes.headers);
      for (const [k, v] of Object.entries(headersOut)) {
        for (const value of [].concat(v)) out += `${k}: ${value}\r\n`;
      }
      socket.write(out + 'connection: close\r\n\r\n');
      upRes.pipe(socket);
    });

    upstream.on('error', () => {
      if (socket.writable) socket.end('HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\ncontent-length: 0\r\n\r\n');
      socket.destroy();
    });
    upstream.end();
  }
}

module.exports = { Proxy, stripHopByHop, removeCookie };
