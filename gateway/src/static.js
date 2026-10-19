'use strict';

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function guacamoleLibraryPath() {
  // Fichier ESM (se termine par "export default Guacamole;").
  const cjsEntry = require.resolve('guacamole-common-js'); // .../dist/cjs/guacamole-common.js
  return path.join(path.dirname(cjsEntry), '..', 'esm', 'guacamole-common.min.js');
}

/** Charge les fichiers servis au navigateur une fois pour toutes (avec version gzip). */
function loadAssets() {
  const sources = {
    '/': path.join(PUBLIC_DIR, 'index.html'),
    '/static/client.js': path.join(PUBLIC_DIR, 'client.js'),
    '/static/client.css': path.join(PUBLIC_DIR, 'client.css'),
    '/static/guacamole-common.js': guacamoleLibraryPath(),
  };
  const assets = new Map();
  for (const [route, file] of Object.entries(sources)) {
    const body = fs.readFileSync(file);
    assets.set(route, {
      body,
      gzip: zlib.gzipSync(body, { level: 9 }),
      type: TYPES[path.extname(file)] || 'application/octet-stream',
      etag: `"${crypto.createHash('sha1').update(body).digest('base64url')}"`,
    });
  }
  return assets;
}

function serveAsset(req, res, asset, extraHeaders = {}) {
  const headers = {
    'content-type': asset.type,
    'cache-control': 'no-cache',
    etag: asset.etag,
    vary: 'accept-encoding',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  };
  if (req.headers['if-none-match'] === asset.etag) {
    res.writeHead(304, headers);
    return res.end();
  }
  const gzip = /\bgzip\b/.test(String(req.headers['accept-encoding'] || ''));
  const body = gzip ? asset.gzip : asset.body;
  if (gzip) headers['content-encoding'] = 'gzip';
  headers['content-length'] = String(body.length);
  res.writeHead(200, headers);
  res.end(req.method === 'HEAD' ? undefined : body);
}

module.exports = { loadAssets, serveAsset };
