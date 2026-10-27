const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./index');
const { encrypt } = require('../crypto/aes');

async function seedDatabase() {
  console.log('Seeding database with test user...');
  try {
    const submissionPath = path.resolve(__dirname, '../../submission.json');
    let testUser = {
      email: 'test_2fa@example.com',
      password: 'securePassword123',
      plaintextTotpSecret: 'JBSWY3DPEHPK3PXP'
    };

    if (fs.existsSync(submissionPath)) {
      const data = JSON.parse(fs.readFileSync(submissionPath, 'utf8'));
      if (data.testUser) {
        testUser = data.testUser;
      }
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(testUser.password, saltRounds);
    const { iv, ciphertext, authTag } = encrypt(testUser.plaintextTotpSecret);

    // Upsert the seeded user
    const query = `
      INSERT INTO users (email, password_hash, totp_enabled, totp_secret_encrypted, totp_iv, totp_tag, last_totp_window)
      VALUES ($1, $2, true, $3, $4, $5, NULL)
      ON CONFLICT (email) 
      DO UPDATE SET 
        password_hash = EXCLUDED.password_hash,
        totp_enabled = EXCLUDED.totp_enabled,
        totp_secret_encrypted = EXCLUDED.totp_secret_encrypted,
        totp_iv = EXCLUDED.totp_iv,
        totp_tag = EXCLUDED.totp_tag,
        last_totp_window = NULL;
    `;

    await db.query(query, [testUser.email, passwordHash, ciphertext, iv, authTag]);
    console.log(`Seeded user ${testUser.email} with totp_enabled=true successfully.`);
  } catch (err) {
    console.error('Seeding failed:', err);
    throw err;
  }
}

if (require.main === module) {
  seedDatabase()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

module.exports = {
  seedDatabase
};
