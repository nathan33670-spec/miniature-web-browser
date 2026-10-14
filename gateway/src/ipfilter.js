'use strict';

const fs = require('node:fs');
const net = require('node:net');

// Toujours autorisés : boucle locale (le conteneur lui-même, le healthcheck).
const LOOPBACK = ['127.0.0.0/8', '::1/128'];

function normalizeIp(raw) {
  if (!raw) return '';
  let ip = String(raw).trim();
  if (ip.startsWith('[')) {
    const end = ip.indexOf(']');
    ip = ip.slice(1, end === -1 ? undefined : end);
  }
  const zone = ip.indexOf('%');
  if (zone !== -1) ip = ip.slice(0, zone);
  if (/^::ffff:/i.test(ip) && net.isIPv4(ip.slice(7))) ip = ip.slice(7);
  return net.isIP(ip) ? ip.toLowerCase() : '';
}

/** Ensemble d'adresses / réseaux CIDR (IPv4 et IPv6). */
class IpSet {
  constructor(entries = []) {
    this.blockList = new net.BlockList();
    this.entries = [];
    for (const entry of entries) this.add(entry);
  }

  add(entry) {
    const [addrPart, prefixPart] = String(entry).trim().split('/');
    const addr = normalizeIp(addrPart);
    if (!addr) throw new Error(`Adresse IP ou réseau invalide : "${entry}"`);
    const family = net.isIPv4(addr) ? 'ipv4' : 'ipv6';
    if (prefixPart === undefined) {
      this.blockList.addAddress(addr, family);
    } else {
      const prefix = Number(prefixPart);
      const max = family === 'ipv4' ? 32 : 128;
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) {
        throw new Error(`Préfixe CIDR invalide : "${entry}"`);
      }
      this.blockList.addSubnet(addr, prefix, family);
    }
    this.entries.push(String(entry).trim());
  }

  has(rawIp) {
    const ip = normalizeIp(rawIp);
    if (!ip) return false;
    return this.blockList.check(ip, net.isIPv4(ip) ? 'ipv4' : 'ipv6');
  }

  get size() {
    return this.entries.length;
  }
}

/**
 * Détermine l'IP réelle du client. X-Forwarded-For n'est pris en compte que si
 * la connexion provient d'un reverse proxy déclaré de confiance ; on remonte
 * alors la chaîne de droite à gauche jusqu'au premier saut non fiable.
 */
function resolveClientIp(remoteAddress, forwardedFor, trustedProxies) {
  let ip = normalizeIp(remoteAddress);
  if (!forwardedFor || !trustedProxies || trustedProxies.size === 0 || !trustedProxies.has(ip)) return ip;
  const chain = String(forwardedFor).split(',').map((s) => s.trim());
  for (let i = chain.length - 1; i >= 0; i--) {
    const hop = normalizeIp(chain[i]);
    if (!hop) break;
    ip = hop;
    if (!trustedProxies.has(hop)) break;
  }
  return ip;
}

/** Passerelle(s) par défaut du conteneur = adresse du NAS vue depuis le réseau Docker. */
function detectDockerGateways(routeFile = '/proc/net/route') {
  let content;
  try {
    content = fs.readFileSync(routeFile, 'utf8');
  } catch {
    return [];
  }
  const gateways = new Set();
  for (const line of content.split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 3 || cols[1] !== '00000000') continue;
    const hex = cols[2];
    if (!/^[0-9A-Fa-f]{8}$/.test(hex) || hex === '00000000') continue;
    const bytes = hex.match(/../g).map((b) => parseInt(b, 16)).reverse();
    gateways.add(bytes.join('.'));
  }
  return [...gateways];
}

class AccessControl {
  constructor({ enabled, allowlist = [], alwaysAllowed = [] }) {
    this.enabled = enabled;
    this.allowlist = new IpSet(allowlist);
    this.alwaysAllowed = new IpSet([...LOOPBACK, ...alwaysAllowed]);
    this.dynamicAllowed = new Set(); // IP publique du serveur (peut changer)
  }

  setDynamic(ips) {
    this.dynamicAllowed = new Set(ips.map(normalizeIp).filter(Boolean));
  }

  /** Retourne la raison de l'autorisation, ou null si refusé. */
  check(rawIp) {
    const ip = normalizeIp(rawIp);
    if (!this.enabled) return 'restriction désactivée';
    if (!ip) return null;
    if (this.alwaysAllowed.has(ip)) return 'local / NAS';
    if (this.dynamicAllowed.has(ip)) return 'IP publique du serveur';
    if (this.allowlist.has(ip)) return 'liste blanche';
    return null;
  }
}

module.exports = { normalizeIp, IpSet, resolveClientIp, detectDockerGateways, AccessControl, LOOPBACK };
