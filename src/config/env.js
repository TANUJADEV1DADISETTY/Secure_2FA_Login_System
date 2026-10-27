const dotenv = require('dotenv');
const path = require('path');

dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/secure_auth',
  jwtSecret: process.env.JWT_SECRET || 'default_jwt_secret_change_me_in_production_min_32_chars',
  masterEncryptionKey: process.env.MASTER_ENCRYPTION_KEY || '2043d58bfc9a2326599b54bb0a7bf5250c3249b45772735b7d0c527678c31388',
  nodeEnv: process.env.NODE_ENV || 'development'
};

if (!config.masterEncryptionKey || config.masterEncryptionKey.length !== 64) {
  console.warn('WARNING: MASTER_ENCRYPTION_KEY should be a 64-character (32-byte) hex string');
}

module.exports = config;
