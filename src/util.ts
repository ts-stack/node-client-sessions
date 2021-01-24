/**
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import * as crypto from 'crypto';
import { SessionOptions, ObjectAny } from './types';

const COOKIE_NAME_SEP = '=';

const KDF_ENC = 'cookiesession-encryption';
const KDF_MAC = 'cookiesession-signature';

/* map from cipher algorithm to exact key byte length */
export const ENCRYPTION_ALGORITHMS: ObjectAny = {
  aes128: 16, // implicit CBC mode
  aes192: 24,
  aes256: 32,
};
export const DEFAULT_ENCRYPTION_ALGO = 'aes256';

/* map from hmac algorithm to _minimum_ key byte length */
export const SIGNATURE_ALGORITHMS: ObjectAny = {
  sha256: 32,
  'sha256-drop128': 32,
  sha384: 48,
  'sha384-drop192': 48,
  sha512: 64,
  'sha512-drop256': 64,
};
export const DEFAULT_SIGNATURE_ALGO = 'sha256';

export function isObject(val: any) {
  return Object.prototype.toString.call(val) === '[object Object]';
}

function base64urlencode(arg: Buffer) {
  let s = arg.toString('base64');
  s = s.split('=')[0]; // Remove any trailing '='s
  s = s.replace(/\+/g, '-'); // 62nd char of encoding
  s = s.replace(/\//g, '_'); // 63rd char of encoding
  // TODO optimize this; we can do much better
  return s;
}

function base64urldecode(arg: string) {
  let s = arg;
  s = s.replace(/-/g, '+'); // 62nd char of encoding
  s = s.replace(/_/g, '/'); // 63rd char of encoding
  switch (
    s.length % 4 // Pad with trailing '='s
  ) {
    case 0:
      break; // No pad chars in this case
    case 2:
      s += '==';
      break; // Two pad chars
    case 3:
      s += '=';
      break; // One pad char
    default:
      throw new Error('Illegal base64url string!');
  }
  return Buffer.from(s, 'base64'); // Standard base64 decoder
}

function forceBuffer(binaryOrBuffer: Buffer) {
  if (Buffer.isBuffer(binaryOrBuffer)) {
    return binaryOrBuffer;
  } else {
    return Buffer.from(binaryOrBuffer, 'binary');
  }
}

function deriveKey(master: string, type: string) {
  // eventually we want to use HKDF. For now we'll do something simpler.
  const hmac = crypto.createHmac('sha256', master);
  hmac.update(type);
  return forceBuffer(hmac.digest());
}

export function setupKeys(opts: SessionOptions) {
  // derive two keys, one for signing one for encrypting, from the secret.
  if (!opts.encryptionKey) {
    opts.encryptionKey = deriveKey(opts.secret, KDF_ENC);
  }

  if (!opts.signatureKey) {
    opts.signatureKey = deriveKey(opts.secret, KDF_MAC);
  }

  if (!opts.signatureAlgorithm) {
    opts.signatureAlgorithm = DEFAULT_SIGNATURE_ALGO;
  }

  if (!opts.encryptionAlgorithm) {
    opts.encryptionAlgorithm = DEFAULT_ENCRYPTION_ALGO;
  }
}

export function checkConstraints(opts: SessionOptions) {
  if (!Buffer.isBuffer(opts.encryptionKey)) {
    throw new Error('encryptionKey must be a Buffer');
  }
  if (!Buffer.isBuffer(opts.signatureKey)) {
    throw new Error('signatureKey must be a Buffer');
  }

  if (constantTimeEquals(opts.encryptionKey, opts.signatureKey)) {
    throw new Error('Encryption and Signature keys must be different');
  }

  const encAlgo = opts.encryptionAlgorithm;
  const required = ENCRYPTION_ALGORITHMS[encAlgo];
  if (opts.encryptionKey.length !== required) {
    throw new Error(
      'Encryption Key for ' + encAlgo + ' must be exactly ' + required + ' bytes ' + '(' + required * 8 + ' bits)'
    );
  }

  const sigAlgo = opts.signatureAlgorithm;
  const minimum = SIGNATURE_ALGORITHMS[sigAlgo];
  if (opts.signatureKey.length < minimum) {
    throw new Error(
      'Encryption Key for ' + sigAlgo + ' must be at least ' + minimum + ' bytes ' + '(' + minimum * 8 + ' bits)'
    );
  }
}

export function encode(opts: SessionOptions, content: any, duration: number, createdAt: number) {
  // format will be:
  // iv.ciphertext.createdAt.duration.hmac

  if (!opts.cookieName) {
    throw new Error('cookieName option required');
  } else if (String(opts.cookieName).indexOf(COOKIE_NAME_SEP) !== -1) {
    throw new Error('cookieName cannot include "="');
  }

  setupKeys(opts);

  duration = duration || 24 * 60 * 60 * 1000;
  createdAt = createdAt || new Date().getTime();

  // generate iv
  const iv = crypto.randomBytes(16);

  // encrypt with encryption key
  const plaintext = Buffer.from(opts.cookieName + COOKIE_NAME_SEP + JSON.stringify(content), 'utf8');
  const cipher = crypto.createCipheriv(opts.encryptionAlgorithm, opts.encryptionKey, iv);

  const ciphertextStart = forceBuffer(cipher.update(plaintext));
  zeroBuffer(plaintext);
  const ciphertextEnd = forceBuffer(cipher.final());
  const ciphertext = Buffer.concat([ciphertextStart, ciphertextEnd]);
  zeroBuffer(ciphertextStart);
  zeroBuffer(ciphertextEnd);

  // hmac it
  const hmac = computeHmac(opts, iv, ciphertext, duration, createdAt);

  const result = [base64urlencode(iv), base64urlencode(ciphertext), createdAt, duration, base64urlencode(hmac)].join(
    '.'
  );

  zeroBuffer(iv);
  zeroBuffer(ciphertext);
  zeroBuffer(hmac);

  return result;
}

export function decode(opts: SessionOptions, content: any) {
  if (!opts.cookieName) {
    throw new Error('cookieName option required');
  }

  // stop at any time if there's an issue
  const components = content.split('.');
  if (components.length !== 5) {
    return;
  }

  setupKeys(opts);

  let iv: Buffer;
  let ciphertext: Buffer;
  let hmac: Buffer;

  try {
    iv = base64urldecode(components[0]);
    ciphertext = base64urldecode(components[1]);
    hmac = base64urldecode(components[4]);
  } catch (ignored) {
    cleanup();
    return;
  }

  const createdAt = parseInt(components[2], 10);
  const duration = parseInt(components[3], 10);

  function cleanup() {
    if (iv) {
      zeroBuffer(iv);
    }

    if (ciphertext) {
      zeroBuffer(ciphertext);
    }

    if (hmac) {
      zeroBuffer(hmac);
    }

    if (expectedHmac) {
      // declared below
      zeroBuffer(expectedHmac);
    }
  }

  // make sure IV is right length
  if (iv.length !== 16) {
    cleanup();
    return;
  }

  // check hmac
  // tslint:disable-next-line: no-var-keyword
  var expectedHmac = computeHmac(opts, iv, ciphertext, duration, createdAt);

  if (!constantTimeEquals(hmac, expectedHmac)) {
    cleanup();
    return;
  }

  // decrypt
  const cipher = crypto.createDecipheriv(opts.encryptionAlgorithm, opts.encryptionKey, iv);
  let plaintext = cipher.update(ciphertext, undefined, 'utf8');
  plaintext += cipher.final('utf8');

  const cookieName = plaintext.substring(0, plaintext.indexOf(COOKIE_NAME_SEP));
  if (cookieName !== opts.cookieName) {
    cleanup();
    return;
  }

  let result;
  try {
    result = {
      content: JSON.parse(plaintext.substring(plaintext.indexOf(COOKIE_NAME_SEP) + 1)),
      createdAt,
      duration,
    };
  } catch (ignored) {}

  cleanup();
  return result;
}

export function computeHmac(opts: SessionOptions, iv: Buffer, ciphertext: Buffer, duration: number, createdAt: number) {
  const hmacAlg = hmacInit(opts.signatureAlgorithm, opts.signatureKey as string);

  hmacAlg.update(iv);
  hmacAlg.update('.');
  hmacAlg.update(ciphertext);
  hmacAlg.update('.');
  hmacAlg.update(createdAt.toString());
  hmacAlg.update('.');
  hmacAlg.update(duration.toString());

  return hmacAlg.digest();
}

function constantTimeEquals(a: Buffer, b: Buffer) {
  // Ideally this would be a native function, so it's less sensitive to how the
  // JS engine might optimize.
  if (a.length !== b.length) {
    return false;
  }
  let ret = 0;
  for (let i = 0; i < a.length; i++) {
    ret |= a.readUInt8(i) ^ b.readUInt8(i);
  }
  return ret === 0;
}

// it's good cryptographic pracitice to not leave buffers with sensitive
// contents hanging around.
function zeroBuffer(buf: Buffer) {
  for (let i = 0; i < buf.length; i++) {
    buf[i] = 0;
  }
  return buf;
}

function hmacInit(algo: string, key: string) {
  const match = algo.match(/^([^-]+)(?:-drop(\d+))?$/);
  const baseAlg = match[1];
  const drop = match[2] ? parseInt(match[2], 10) : 0;

  const hmacAlg = crypto.createHmac(baseAlg, key);
  const origDigest = hmacAlg.digest;

  if (drop === 0) {
    // Before 0.10, crypto returns binary-encoded strings. Remove when dropping
    // 0.8 support.
    hmacAlg.digest = function () {
      return forceBuffer(origDigest.call(this)) as any;
    };
  } else {
    const N = drop / 8; // bits to bytes
    hmacAlg.digest = function dropN() {
      const result = forceBuffer(origDigest.call(this));
      // Throw away the second half of the 512-bit result, leaving the first
      // 256-bits.
      const truncated = Buffer.alloc(N);
      result.copy(truncated, 0, 0, N);
      zeroBuffer(result);
      return truncated as any;
    };
  }

  return hmacAlg;
}
