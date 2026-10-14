'use strict';

const dns = require('node:dns').promises;
const { normalizeIp } = require('./ipfilter');

async function fetchIp(url, timeoutMs = 5000) {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': 'curl/8' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ip = normalizeIp((await res.text()).trim());
  if (!ip) throw new Error('réponse invalide');
  return ip;
}

async function resolveHostname(hostname) {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((r) => normalizeIp(r.address)).filter(Boolean);
}

/**
 * Suit l'IP publique du serveur (NAS) : IP fixes déclarées, noms DNS (DynDNS)
 * et détection automatique via des services externes. Les appareils situés
 * derrière la même box sortent avec cette IP : ils sont donc toujours autorisés.
 */
class PublicIpTracker {
  constructor({ staticIps = [], hostnames = [], autodetect = true, urls = [], refreshMs = 600_000, logger, onChange }) {
    this.staticIps = staticIps.map(normalizeIp).filter(Boolean);
    this.hostnames = hostnames;
    this.autodetect = autodetect;
    this.urls = urls;
    this.refreshMs = refreshMs;
    this.logger = logger;
    this.onChange = onChange;
    this.current = [];
    this.lastDetected = [];
    this.timer = null;
  }

  async refresh() {
    const ips = new Set(this.staticIps);

    for (const hostname of this.hostnames) {
      try {
        for (const ip of await resolveHostname(hostname)) ips.add(ip);
      } catch (err) {
        this.logger.warn(`Résolution DNS de ${hostname} impossible : ${err.message}`);
      }
    }

    if (this.autodetect && this.urls.length) {
      let detected = null;
      for (const url of this.urls) {
        try {
          detected = await fetchIp(url);
          break;
        } catch (err) {
          this.logger.debug(`Détection IP publique via ${url} échouée : ${err.message}`);
        }
      }
      if (detected) {
        this.lastDetected = [detected];
      } else if (this.lastDetected.length) {
        this.logger.warn('Détection de l\'IP publique impossible, conservation de la dernière valeur connue.');
      } else {
        this.logger.warn('Détection de l\'IP publique impossible (aucun service joignable).');
      }
      for (const ip of this.lastDetected) ips.add(ip);
    }

    const next = [...ips].sort();
    if (next.join(',') !== this.current.join(',')) {
      this.logger.info(`IP publique du serveur autorisée : ${next.length ? next.join(', ') : '(aucune)'}`);
      this.current = next;
      this.onChange(next);
    }
    return next;
  }

  start() {
    const run = () => this.refresh().catch((err) => this.logger.error(`IP publique : ${err.message}`));
    run();
    this.timer = setInterval(run, this.refreshMs);
    this.timer.unref();
  }

  stop() {
    clearInterval(this.timer);
  }
}

module.exports = { PublicIpTracker, fetchIp };
