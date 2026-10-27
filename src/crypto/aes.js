const crypto = require('crypto');
const config = require('../config/env');

const ALGORITHM = 'aes-256-gcm';

function getMasterKey(keyOverride) {
  const hexKey = keyOverride || process.env.MASTER_ENCRYPTION_KEY || config.masterEncryptionKey;
  if (!hexKey) {
    throw new Error('MASTER_ENCRYPTION_KEY is required for AES-256-GCM operations');
  }
  const key = Buffer.from(hexKey, 'hex');
  if (key.length !== 32) {
    throw new Error(`Master key must be exactly 32 bytes (64 hex characters), received ${key.length} bytes`);
  }
  return key;
}

/**
 * Encrypts a plaintext string (like a base32 TOTP secret).
 * 
 * @param {string} plaintext - The secret to encrypt.
 * @param {string} [keyOverride] - Optional hex key for testing.
 * @returns {{ iv: string, ciphertext: string, authTag: string }} Hex-encoded object
 */
function encrypt(plaintext, keyOverride) {
  if (typeof plaintext !== 'string') {
    throw new TypeError('Plaintext must be a string');
  }

  const key = getMasterKey(keyOverride);
  // 1. Generate a random 12-byte IV (Standard for GCM)
  const iv = crypto.randomBytes(12);

  // 2. Create the Cipher instance
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  // 3. Encrypt the data
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');

  // 4. Extract the authentication tag (crucial for integrity)
  const authTag = cipher.getAuthTag().toString('hex');

  return {
    iv: iv.toString('hex'),
    ciphertext,
    authTag
  };
}

/**
 * Decrypts the ciphertext back to the plaintext secret.
 * 
 * @param {string} ivHex - The IV used during encryption.
 * @param {string} ciphertextHex - The encrypted data.
 * @param {string} authTagHex - The auth tag generated during encryption.
 * @param {string} [keyOverride] - Optional hex key for testing.
 * @returns {string} The original plaintext secret.
 * @throws {Error} Will throw if the auth tag is invalid (tampering detected).
 */
function decrypt(ivHex, ciphertextHex, authTagHex, keyOverride) {
  if (!ivHex || !ciphertextHex || !authTagHex) {
    throw new Error('iv, ciphertext, and authTag are all required for decryption');
  }

  const key = getMasterKey(keyOverride);
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  // Must set auth tag BEFORE calling decipher.final()
  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(ciphertextHex, 'hex', 'utf8');
  plaintext += decipher.final('utf8');

  return plaintext;
}

module.exports = {
  encrypt,
  decrypt,
  ALGORITHM
};
