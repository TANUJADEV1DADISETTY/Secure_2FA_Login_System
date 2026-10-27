const crypto = require('crypto');

// RFC 4648 Base32 alphabet
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encodes a Buffer to a Base32 string (without padding, RFC 4648)
 * @param {Buffer} buffer 
 * @returns {string}
 */
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decodes a Base32 string into a Buffer
 * @param {string} str 
 * @returns {Buffer}
 */
function base32Decode(str) {
  // Clean whitespace and padding, uppercase
  const cleanStr = str.replace(/[\s=]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const char = cleanStr[i];
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid Base32 character: ${char}`);
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generates a cryptographically secure Base32 TOTP secret (default 20 bytes = 160 bits)
 * @param {number} [byteLength=20]
 * @returns {string} Base32 encoded secret
 */
function generateTotpSecret(byteLength = 20) {
  const randomBytes = crypto.randomBytes(byteLength);
  return base32Encode(randomBytes);
}

/**
 * Generates an RFC 6238 TOTP code for a specific time window.
 * 
 * @param {string} base32Secret - The shared secret key in Base32.
 * @param {number|bigint} timeWindow - The integer time counter (usually Math.floor(epoch / 30)).
 * @param {number} [digits=6] - Number of digits (default 6).
 * @returns {string} 6-digit numeric TOTP code as string
 */
function generateTotpCode(base32Secret, timeWindow, digits = 6) {
  const secretBytes = base32Decode(base32Secret);

  // Time window as 8-byte big-endian buffer
  const timeBuf = Buffer.alloc(8);
  timeBuf.writeBigInt64BE(BigInt(timeWindow), 0);

  // HMAC-SHA1
  const hmac = crypto.createHmac('sha1', secretBytes).update(timeBuf).digest();

  // Dynamic Truncation
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * Verifies a user-provided TOTP code against the secret, allowing for clock drift.
 * Uses constant-time comparison (crypto.timingSafeEqual) against timing attacks.
 * 
 * @param {string} base32Secret - Plaintext Base32 secret
 * @param {string} userCode - 6-digit code provided by user
 * @param {number} [currentWindow] - Current epoch time step (defaults to Math.floor(Date.now() / 30000))
 * @param {number} [windowDrift=1] - Number of time steps backward and forward to allow (default 1: T-1, T, T+1)
 * @returns {{ valid: boolean, matchingWindow: number | null }}
 */
function verifyTotpCode(base32Secret, userCode, currentWindow, windowDrift = 1) {
  if (typeof userCode !== 'string' || !/^\d{6}$/.test(userCode)) {
    return { valid: false, matchingWindow: null };
  }

  const baseWindow = currentWindow !== undefined ? currentWindow : Math.floor(Date.now() / 30000);
  const targetBuffer = Buffer.from(userCode);

  for (let offset = -windowDrift; offset <= windowDrift; offset++) {
    const candidateWindow = baseWindow + offset;
    try {
      const expectedCode = generateTotpCode(base32Secret, candidateWindow);
      const expectedBuffer = Buffer.from(expectedCode);

      if (
        expectedBuffer.length === targetBuffer.length &&
        crypto.timingSafeEqual(expectedBuffer, targetBuffer)
      ) {
        return {
          valid: true,
          matchingWindow: candidateWindow
        };
      }
    } catch {
      // Continue checking
    }
  }

  return { valid: false, matchingWindow: null };
}

/**
 * Constructs an RFC-compliant otpauth:// URI for authenticator applications.
 * 
 * @param {string} email - User email address
 * @param {string} base32Secret - Base32 secret
 * @param {string} [issuer="Secure2FA"] - Issuer name
 * @returns {string} otpauth URI
 */
function generateOtpAuthUri(email, base32Secret, issuer = 'Secure2FA') {
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedEmail = encodeURIComponent(email);
  return `otpauth://totp/${encodedIssuer}:${encodedEmail}?secret=${base32Secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}

module.exports = {
  base32Encode,
  base32Decode,
  generateTotpSecret,
  generateTotpCode,
  verifyTotpCode,
  generateOtpAuthUri
};
