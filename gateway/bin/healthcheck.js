'use strict';

const http = require('node:http');
const https = require('node:https');

const tls = (process.env.TLS_MODE || 'self-signed').toLowerCase() !== 'off';
const port = process.env.LISTEN_PORT || 8443;
const client = tls ? https : http;

const req = client.get(
  { host: '127.0.0.1', port, path: '/__auth/health', rejectUnauthorized: false, timeout: 4000 },
  (res) => process.exit(res.statusCode === 200 ? 0 : 1)
);
req.on('error', () => process.exit(1));
req.on('timeout', () => {
  req.destroy();
  process.exit(1);
});
