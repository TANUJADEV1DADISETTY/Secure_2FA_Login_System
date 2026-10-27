const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
const config = require('../config/env');
const { encrypt, decrypt } = require('../crypto/aes');
const {
  generateTotpSecret,
  verifyTotpCode,
  generateOtpAuthUri
} = require('../crypto/totp');
const {
  requireAuth,
  createChallengeToken,
  createAccessToken
} = require('../middleware/auth');

const router = express.Router();

/**
 * Helper to validate email format
 */
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * POST /api/auth/register
 * Registers a new user, hashing their password before storage.
 */
router.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ error: 'A valid email address is required' });
    }

    if (!password || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    // Check if user already exists
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'A user with this email already exists' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await db.query(
      `INSERT INTO users (email, password_hash, totp_enabled)
       VALUES ($1, $2, false)
       RETURNING id, email`,
      [email, passwordHash]
    );

    const newUser = result.rows[0];
    return res.status(201).json({
      id: newUser.id,
      email: newUser.email
    });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'Internal server error during registration' });
  }
});

/**
 * POST /api/auth/login
 * Primary login endpoint that branches response based on totp_enabled status.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Branching logic based on totp_enabled
    if (user.totp_enabled) {
      const challengeToken = createChallengeToken(user);
      return res.status(200).json({
        requires_2fa: true,
        challenge_token: challengeToken
      });
    }

    // 2FA not enabled -> full access JWT
    const token = createAccessToken(user);
    return res.status(200).json({
      token
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error during login' });
  }
});

/**
 * POST /api/auth/2fa/setup
 * Provisions TOTP for an authenticated user, returning secret and URI
 * while storing encrypted material at rest.
 */
router.post('/2fa/setup', requireAuth, async (req, res) => {
  try {
    const userId = req.user.userId;

    const userRes = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    const user = userRes.rows[0];

    // Generate new 20-byte Base32 secret
    const secret = generateTotpSecret(20);

    // Encrypt the secret using AES-256-GCM
    const { iv, ciphertext, authTag } = encrypt(secret);

    // Update user record with encrypted credentials, keeping totp_enabled as false
    await db.query(
      `UPDATE users 
       SET totp_secret_encrypted = $1,
           totp_iv = $2,
           totp_tag = $3
       WHERE id = $4`,
      [ciphertext, iv, authTag, userId]
    );

    const uri = generateOtpAuthUri(user.email, secret, 'Secure2FA');

    return res.status(200).json({
      secret,
      uri
    });
  } catch (err) {
    console.error('2FA setup error:', err);
    return res.status(500).json({ error: 'Internal server error during 2FA setup' });
  }
});

/**
 * POST /api/auth/2fa/verify
 * Verifies the first TOTP code after setup and officially activates 2FA.
 */
router.post('/2fa/verify', requireAuth, async (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.userId;

    if (!code || typeof code !== 'string' || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'A 6-digit numeric code is required' });
    }

    const userRes = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userRes.rows[0];
    if (!user.totp_secret_encrypted || !user.totp_iv || !user.totp_tag) {
      return res.status(400).json({ error: '2FA setup has not been initiated for this account' });
    }

    // Decrypt the secret
    const plaintextSecret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);

    // Verify the code
    const currentWindow = Math.floor(Date.now() / 30000);
    const { valid, matchingWindow } = verifyTotpCode(plaintextSecret, code, currentWindow, 1);

    if (!valid || matchingWindow === null) {
      return res.status(400).json({ error: 'Invalid TOTP verification code' });
    }

    // Activate 2FA and record initial window
    await db.query(
      `UPDATE users 
       SET totp_enabled = true,
           last_totp_window = $1
       WHERE id = $2`,
      [matchingWindow, userId]
    );

    return res.status(200).json({
      message: '2FA successfully enabled'
    });
  } catch (err) {
    console.error('2FA verify error:', err);
    return res.status(500).json({ error: 'Internal server error during 2FA verification' });
  }
});

/**
 * POST /api/auth/2fa/login
 * Secondary login endpoint that validates the TOTP code against the challenge token.
 * Strictly enforces replay protection within a database transaction.
 */
router.post('/2fa/login', async (req, res) => {
  const { challenge_token, code } = req.body;

  if (!challenge_token || !code) {
    return res.status(400).json({ error: 'challenge_token and code are both required' });
  }

  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) {
    return res.status(401).json({ error: 'Invalid TOTP code format (must be 6 digits)' });
  }

  // Verify challenge JWT
  let decoded;
  try {
    decoded = jwt.verify(challenge_token, config.jwtSecret);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired challenge token' });
  }

  if (decoded.scope !== '2fa_challenge') {
    return res.status(401).json({ error: 'Invalid token scope for 2FA login' });
  }

  // Acquire client for transaction with row-level lock
  const client = await db.getClient();
  try {
    await client.query('BEGIN');

    const userRes = await client.query(
      'SELECT * FROM users WHERE id = $1 FOR UPDATE',
      [decoded.userId]
    );

    if (userRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'User not found' });
    }

    const user = userRes.rows[0];

    if (!user.totp_enabled || !user.totp_secret_encrypted || !user.totp_iv || !user.totp_tag) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: '2FA is not enabled on this account' });
    }

    // Decrypt the secret
    const plaintextSecret = decrypt(user.totp_iv, user.totp_secret_encrypted, user.totp_tag);

    // Verify TOTP code
    const currentWindow = Math.floor(Date.now() / 30000);
    const { valid, matchingWindow } = verifyTotpCode(plaintextSecret, code, currentWindow, 1);

    if (!valid || matchingWindow === null) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Invalid TOTP code' });
    }

    // Replay Protection:
    // If matchingWindow <= last_totp_window, reject as replay attack
    if (user.last_totp_window !== null && matchingWindow <= user.last_totp_window) {
      await client.query('ROLLBACK');
      return res.status(401).json({
        error: 'TOTP code has already been used or expired (replay detected)'
      });
    }

    // Update last_totp_window
    await client.query(
      'UPDATE users SET last_totp_window = $1 WHERE id = $2',
      [matchingWindow, user.id]
    );

    await client.query('COMMIT');

    // Generate full access token
    const token = createAccessToken(user);
    return res.status(200).json({
      token
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('2FA login error:', err);
    return res.status(500).json({ error: 'Internal server error during 2FA login' });
  } finally {
    client.release();
  }
});

module.exports = router;
