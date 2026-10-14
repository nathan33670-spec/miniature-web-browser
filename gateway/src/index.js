'use strict';

const { loadConfig } = require('./config');
const { createGateway, createLogger } = require('./server');

async function main() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error(`Configuration invalide : ${err.message}`);
    process.exit(1);
  }
  const logger = createLogger(config.logLevel);
  const gateway = await createGateway(config, { logger });
  const address = await gateway.listen();

  logger.info(`Passerelle à l'écoute sur ${config.tls.mode === 'off' ? 'http' : 'https'}://${address.address}:${address.port}`);
  logger.info(`Navigateur (amont) : ${config.upstream.url}`);
  logger.info(`Double authentification (TOTP) : ${config.auth.totpSecret ? 'activée' : 'désactivée'}`);
  logger.info(`Connexions entrantes : ${config.access.ipv4Only ? 'IPv4 uniquement' : 'IPv4 et IPv6'}`);
  if (config.access.enabled) {
    logger.info('Restriction IP : ACTIVÉE');
    logger.info(`  Toujours autorisés : localhost, NAS (${[...config.access.nasIps, ...gateway.gateways].join(', ') || 'aucune IP déclarée'})` +
      `${config.access.allowPublicIp ? ', IP publique du serveur' : ''}`);
    logger.info(`  Liste blanche : ${config.access.allowlist.join(', ') || '(vide)'}`);
  } else {
    logger.info('Restriction IP : désactivée (authentification seule)');
  }
  if (config.access.trustedProxies.length) logger.info(`Reverse proxies de confiance : ${config.access.trustedProxies.join(', ')}`);

  const shutdown = async (signal) => {
    logger.info(`${signal} reçu, arrêt…`);
    await gateway.close();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error(err.stack || err.message);
  process.exit(1);
});
