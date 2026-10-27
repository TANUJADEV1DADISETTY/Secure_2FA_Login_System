const jwt = require('jsonwebtoken');
const config = require('../config/env');

/**
 * Middleware that requires a valid full-access JWT.
 * Strictly rejects challenge tokens (scope: '2fa_challenge').
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header with Bearer token is required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, config.jwtSecret);

    // Strictly enforce that challenge tokens cannot access protected routes
    if (decoded.scope === '2fa_challenge') {
      return res.status(403).json({
        error: 'Forbidden: 2FA challenge token cannot access protected routes. Complete 2FA verification first.'
      });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired authorization token' });
  }
}

/**
 * Creates a short-lived 2FA challenge JWT (valid for 5 minutes)
 */
function createChallengeToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      scope: '2fa_challenge'
    },
    config.jwtSecret,
    { expiresIn: '5m' }
  );
}

/**
 * Creates a full-access JWT (valid for 24 hours)
 */
function createAccessToken(user) {
  return jwt.sign(
    {
      userId: user.id,
      email: user.email,
      scope: 'full_access'
    },
    config.jwtSecret,
    { expiresIn: '24h' }
  );
}

module.exports = {
  requireAuth,
  createChallengeToken,
  createAccessToken
};
