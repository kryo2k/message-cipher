#!/usr/bin/env node
'use strict';

const yargs  = require('yargs');
const format = require('util').format;
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const pkg    = require('./package.json');

const CURVE = 'sect571r1';
const CIPHER = 'aes-256-ctr';
const HASH = 'sha256';
const FORMAT = 'uncompressed';
const ENCODING = 'hex';
const BIN = 'binary';
const PRIVATE_KEY = path.join(process.env.HOME, '.privatemessenger');
const SIGLEN = 64;

if(crypto.getCurves().indexOf(CURVE) === -1) {
  throw new Error(format('The supplied curve (%s) is not available.', CURVE));
}
else if(crypto.getCiphers().indexOf(CIPHER) === -1) {
  throw new Error(format('The supplied cipher (%s) is not available.', CIPHER));
}
else if(crypto.getHashes().indexOf(HASH) === -1) {
  throw new Error(format('The supplied hash (%s) is not available.', HASH));
}

exports.newEcdh = () => {
  return crypto.createECDH(CURVE);
};

exports.newCipher = (secret) => {
  return crypto.createCipher(CIPHER, secret);
};

exports.newDecipher = (secret) => {
  return crypto.createDecipher(CIPHER, secret);
};

exports.newHash = () => {
  return crypto.createHash(HASH);
};

exports.restoreEcdh = (privateKey, fromExport) => {
  const ecdh = exports.newEcdh();
  ecdh.setPrivateKey(privateKey, fromExport ? ENCODING : BIN);
  return ecdh;
};

exports.restoreEcdhFile = (filename) => {
  if(!fs.existsSync(filename)) {
    throw new Error(format('Private key file (%s) does not exist.', filename));
  }

  const data = fs.readFileSync(filename, { encoding: 'utf8' });

  if(!data) {
    throw new Error(format('Unable to read contents of private key file (%s).', filename))
  }

  const ecdh = exports.restoreEcdh(data, true);

  return ecdh;
};

exports.ecdhKeys = (ecdh, forExport) => {
  return ecdh.generateKeys(forExport ? ENCODING : BIN, FORMAT);
};

exports.ecdhCipher = (ecdh, pubkey, fromExport) => {
  return exports.newCipher(exports.ecdhComputeSecret(ecdh, pubkey, fromExport));
};

exports.ecdhDecipher = (ecdh, pubkey, fromExport) => {
  return exports.newDecipher(exports.ecdhComputeSecret(ecdh, pubkey, fromExport));
};

exports.ecdhPrivateKey = (ecdh, forExport) => {
  return ecdh.getPrivateKey(forExport ? ENCODING : BIN);
};

exports.ecdhPublicKey = (ecdh, forExport) => {
  return ecdh.getPublicKey(forExport ? ENCODING : BIN, FORMAT);
};

exports.ecdhComputeSecret = (ecdh, pubkey, fromExport, forExport) => {
  if(false === (pubkey instanceof Buffer)) {
    pubkey = exports.ecdhPublicKey(ecdh);
  }

  return ecdh.computeSecret(pubkey, fromExport ? ENCODING : BIN, forExport ? ENCODING : BIN);
};

const ARGVPUBKEY = (argv, ecdh) => {

  var pubkey = null;

  if(argv.pub) { // load from input
    pubkey = new Buffer(argv.pub, ENCODING);
  }
  else { // self-sign
    pubkey = exports.ecdhPublicKey(ecdh);
  }

  return pubkey;
};

const ARGVEDCH = (argv) => {

  var ecdh = false;

  if(argv.priv) { // load from string
    ecdh = exports.restoreEcdh(argv.priv, true);
  }
  else if(argv.path) { // load from file
    ecdh = exports.restoreEcdhFile(argv.path, true);
  }

  return ecdh;
};

const HASHSTR = (str) => {
  const hasher = exports.newHash();
  hasher.update(str);
  return hasher.digest(ENCODING);
};

const MSGENCODE = (message) => {
  return JSON.stringify([message, new Date()]);
};

const MSGDECODE = (message) => {
  var parsed = false;
  try {
    parsed = JSON.parse(message);
  }
  catch(e) {}

  if(!parsed || false === Array.isArray(parsed) || parsed.length < 2) {
    throw new Error('Message is invalid or not encrypted for the current private/public key pair.')
  }

  return parsed;
};

const MSGSIGN = (message) => {
  if(typeof message !== 'string' || message.length === 0) {
    throw new Error('Invalid message provided to sign. Must be non-zero length string.');
  }

  return message + HASHSTR(message);
};

const MSGUNSIGN = (message) => {
  if(typeof message !== 'string' || message.length < SIGLEN) {
    throw new Error(format('Invalid message provided to unsign. Must be a string atleast %d chars long.', SIGLEN));
  }

  const pos = message.length - SIGLEN;
  const raw = message.substring(0, pos);

  if(message.substring(pos) !== HASHSTR(raw)) {
    throw new Error('This message was not signed properly.');
  }

  return raw;
};

yargs
.usage('Usage: $0 <command> [options]')
.help('h')
.alias('h', 'help')

.command({
  command: 'generate [options]',
  describe: 'Generate a new private key.',
  builder: {
    path: {
      alias: 'p',
      describe: 'Path to private key',
      default: PRIVATE_KEY
    },
    force: {
      type: 'boolean',
      alias: 'f',
      default: false
    },
    'no-write': {
      type: 'boolean',
      alias: 'R',
      default: false
    }
  },
  handler: (argv) => {
    const readOnly = !!argv['no-write'];

    if(fs.existsSync(argv.path) && (!argv.force && !readOnly)) {
      throw new Error(format('Private key file (%s) already exists.', argv.path));
    }

    const ecdh = exports.newEcdh();
    const ecdh_pub  = exports.ecdhKeys(ecdh, true);
    const ecdh_priv = exports.ecdhPrivateKey(ecdh, true);

    if(!readOnly) {
      const file = fs.openSync(argv.path, 'w');
      fs.writeFileSync(file, ecdh_priv);
      fs.closeSync(file);
      console.log('File (%s) was written.', argv.path);
    }
    else {
      console.log('\nPrivate Key (secret):\n%s\n\nPublicKey:\n%s\n', ecdh_priv, ecdh_pub);
    }
  }
})

.command({
  command: 'read [options]',
  describe: 'Read information about an existing key.',
  builder: {
    path: {
      alias: 'p',
      describe: 'Path to private key',
      default: PRIVATE_KEY
    }
  },
  handler: (argv) => {
    const ecdh = exports.restoreEcdhFile(argv.path, true);
    const ecdh_pub  = exports.ecdhPublicKey(ecdh, true);
    const ecdh_priv = exports.ecdhPrivateKey(ecdh, true);

    console.log('\nPrivate Key (do not share):\n%s\n', ecdh_priv);
    console.log('Public Key:\n%s\n', ecdh_pub);
  }
})

.command({
  command: 'encrypt [options] <message>',
  describe: 'Encrypt a message.',
  builder: {
    priv: {
      type: 'string',
      describe: 'Override private key with hex-encoded private key value.',
      default: null
    },
    pub: {
      type: 'string',
      describe: 'Public key identity to encrypt for (if blank, uses public key from private key)'
    },
    path: {
      alias: 'p',
      describe: 'Path to private key',
      default: PRIVATE_KEY
    }
  },
  handler: (argv) => {
    const ecdh = ARGVEDCH(argv);
    const pubkey = ARGVPUBKEY(argv, ecdh);
    const cipher = exports.ecdhCipher(ecdh, pubkey);
    const encrypted = cipher.update(MSGENCODE(argv.message), 'utf8', ENCODING) + cipher.final(ENCODING);

    console.log('\nEncrypted Message:\n%s\n', MSGSIGN(encrypted));
  }
})

.command({
  command: 'decrypt [options] <message>',
  describe: 'Decrypts a message.',
  builder: {
    priv: {
      type: 'string',
      describe: 'Override private key with hex-encoded private key value.',
      default: null
    },
    pub: {
      type: 'string',
      describe: 'Public key identity to decrypt from (if blank, uses public key from private key)'
    },
    path: {
      alias: 'p',
      describe: 'Path to private key',
      default: PRIVATE_KEY
    }
  },
  handler: (argv) => {
    const ecdh = ARGVEDCH(argv);
    const pubkey = ARGVPUBKEY(argv, ecdh);
    const decipher = exports.ecdhDecipher(ecdh, pubkey);
    const decrypted = decipher.update(MSGUNSIGN(argv.message), ENCODING, 'utf8') + decipher.final('utf8');
    const loaded = MSGDECODE(decrypted);

    console.log('\nDecrypted Message (%j):\n%s\n', loaded[1], loaded[0]);
  }
})
.epilog(pkg.epilog)
.argv;
