#!/usr/bin/env node
'use strict';

const readline = require('node:readline');
const { hashPassword, generateTotpSecret } = require('../src/auth');

function promptHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let muted = false;
    rl._writeToOutput = (s) => {
      if (!muted) process.stdout.write(s);
      else if (s.includes('\n')) process.stdout.write('\n');
    };
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
    muted = true;
  });
}

async function readPassword() {
  if (!process.stdin.isTTY) {
    // Lecture depuis un pipe : echo "motdepasse" | ... hash-password
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
  }
  const first = await promptHidden('Mot de passe : ');
  const second = await promptHidden('Confirmez le mot de passe : ');
  if (first !== second) throw new Error('Les mots de passe ne correspondent pas.');
  return first;
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  switch (command) {
    case 'hash-password': {
      const password = args[0] ?? (await readPassword());
      if (!password) throw new Error('Mot de passe vide.');
      if (password.length < 12) console.error('⚠️  Mot de passe court : 12 caractères minimum recommandés.');
      const hash = await hashPassword(password);
      console.log('\nAjoutez cette ligne à votre fichier .env :\n');
      console.log(`AUTH_PASSWORD_HASH=${hash}\n`);
      break;
    }
    case 'generate-totp': {
      const user = args[0] || 'admin';
      const secret = generateTotpSecret();
      const label = encodeURIComponent(`Navigateur distant:${user}`);
      const uri = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent('Navigateur distant')}&algorithm=SHA1&digits=6&period=30`;
      console.log('\nAjoutez cette ligne à votre fichier .env :\n');
      console.log(`TOTP_SECRET=${secret}\n`);
      console.log('Puis, dans votre application d\'authentification (Google Authenticator, Aegis, 2FAS, Bitwarden…),');
      console.log('ajoutez un compte manuellement avec la clé ci-dessus, ou importez cette URI :\n');
      console.log(`${uri}\n`);
      break;
    }
    default:
      console.log(`Usage :
  hash-password [motdepasse]   Génère AUTH_PASSWORD_HASH (demande le mot de passe si absent)
  generate-totp [utilisateur]  Génère TOTP_SECRET pour la double authentification`);
      process.exit(command ? 1 : 0);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
