const assert = require('assert');
const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const { pool, query } = require('../src/db');
const { encrypt, decrypt } = require('../src/crypto/aes');
const { generateTotpCode, verifyTotpCode } = require('../src/crypto/totp');
const config = require('../src/config/env');

const BASE_URL = `http://localhost:${config.port}`;

async function runTests() {
  console.log('====================================================');
  console.log(' RUNNING SECURE 2FA AUTHENTICATION CONTRACT TESTS');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  async function test(name, fn) {
    try {
      process.stdout.write(`Testing: ${name}... `);
      await fn();
      console.log('PASSED [OK]');
      passed++;
    } catch (err) {
      console.log('FAILED [X]');
      console.error(err);
      failed++;
    }
  }

  // Requirement 2: .env.example verification
  await test('Requirement 2: .env.example exists and contains required keys', async () => {
    const envExamplePath = path.resolve(__dirname, '../.env.example');
    assert.strictEqual(fs.existsSync(envExamplePath), true, '.env.example must exist');
    const content = fs.readFileSync(envExamplePath, 'utf8');
    const parsed = dotenv.parse(content);
    assert.ok(parsed.DATABASE_URL, 'DATABASE_URL must be defined');
    assert.ok(parsed.JWT_SECRET, 'JWT_SECRET must be defined');
    assert.ok(parsed.MASTER_ENCRYPTION_KEY, 'MASTER_ENCRYPTION_KEY must be defined');
  });

  // Requirement 12: submission.json verification
  let submissionUser;
  await test('Requirement 12: submission.json format and structure', async () => {
    const subPath = path.resolve(__dirname, '../submission.json');
    assert.strictEqual(fs.existsSync(subPath), true, 'submission.json must exist');
    const subData = JSON.parse(fs.readFileSync(subPath, 'utf8'));
    assert.ok(subData.testUser, 'testUser must be present');
    assert.ok(subData.testUser.email, 'testUser.email must be present');
    assert.ok(subData.testUser.password, 'testUser.password must be present');
    assert.ok(subData.testUser.plaintextTotpSecret, 'testUser.plaintextTotpSecret must be present');
    submissionUser = subData.testUser;
  });

  // Requirement 3: Database schema users table and columns
  await test('Requirement 3: users table and all 8 columns with correct types', async () => {
    const res = await query(`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns
      WHERE table_name = 'users';
    `);

    assert.ok(res.rows.length >= 8, 'users table must have at least 8 columns');
    const colMap = new Map(res.rows.map(r => [r.column_name, r]));

    const requiredColumns = [
      'id',
      'email',
      'password_hash',
      'totp_enabled',
      'totp_secret_encrypted',
      'totp_iv',
      'totp_tag',
      'last_totp_window'
    ];

    for (const col of requiredColumns) {
      assert.ok(colMap.has(col), `Column ${col} must exist in users table`);
    }

    // Verify types
    const emailCol = colMap.get('email');
    assert.strictEqual(emailCol.is_nullable, 'NO', 'email must be NOT NULL');

    const passCol = colMap.get('password_hash');
    assert.strictEqual(passCol.is_nullable, 'NO', 'password_hash must be NOT NULL');

    const totpEnabledCol = colMap.get('totp_enabled');
    assert.strictEqual(totpEnabledCol.data_type, 'boolean', 'totp_enabled must be boolean');

    const lastWindowCol = colMap.get('last_totp_window');
    assert.strictEqual(lastWindowCol.data_type, 'integer', 'last_totp_window must be integer');
  });

  // Requirement 4: Registration
  const testRegEmail = `test_reg_${Date.now()}@example.com`;
  const testRegPassword = 'superSecurePassword123';
  let registeredUserId;

  await test('Requirement 4: POST /api/auth/register creates user and hashes password', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testRegEmail,
        password: testRegPassword
      })
    });

    assert.strictEqual(res.status, 201, 'Response status must be 201 Created');
    const body = await res.json();
    assert.ok(body.id, 'Response must include user id');
    assert.strictEqual(body.email, testRegEmail, 'Response email must match');
    registeredUserId = body.id;

    // Check DB that password is not plaintext
    const dbRes = await query('SELECT password_hash FROM users WHERE email = $1', [testRegEmail]);
    assert.strictEqual(dbRes.rows.length, 1);
    const storedHash = dbRes.rows[0].password_hash;
    assert.notStrictEqual(storedHash, testRegPassword, 'Password must not be stored in plaintext');
    assert.ok(storedHash.startsWith('$2'), 'Password must be bcrypt hashed');
  });

  // Requirement 5: Primary login branching
  let standardUserToken;
  let challengeToken;

  await test('Requirement 5: POST /api/auth/login branches correctly', async () => {
    // 1. User without 2FA -> returns { token }
    const resNo2fa = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testRegEmail, password: testRegPassword })
    });
    assert.strictEqual(resNo2fa.status, 200);
    const bodyNo2fa = await resNo2fa.json();
    assert.ok(bodyNo2fa.token, 'Non-2FA login must return full access token');
    assert.strictEqual(bodyNo2fa.requires_2fa, undefined, 'Non-2FA login must not set requires_2fa');
    standardUserToken = bodyNo2fa.token;

    // 2. User with 2FA enabled (seeded test user) -> returns requires_2fa: true and challenge_token
    const res2fa = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: submissionUser.email,
        password: submissionUser.password
      })
    });
    assert.strictEqual(res2fa.status, 200);
    const body2fa = await res2fa.json();
    assert.strictEqual(body2fa.requires_2fa, true, 'requires_2fa must be true');
    assert.ok(body2fa.challenge_token, 'challenge_token must be present');
    assert.strictEqual(body2fa.token, undefined, 'token must NOT be returned when 2FA is required');
    challengeToken = body2fa.challenge_token;

    // 3. Incorrect password -> 401
    const resBadPass = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testRegEmail, password: 'WrongPassword999' })
    });
    assert.strictEqual(resBadPass.status, 401, 'Incorrect password must return 401');
  });

  // Requirement 6 & 7: 2FA Setup and Encryption at rest
  let setupSecret;
  let setupUri;
  let firstSetupIv;

  await test('Requirements 6 & 7: POST /api/auth/2fa/setup and Encryption at Rest', async () => {
    const res = await fetch(`${BASE_URL}/api/auth/2fa/setup`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${standardUserToken}`,
        'Content-Type': 'application/json'
      }
    });

    assert.strictEqual(res.status, 200);
    const data = await res.json();
    assert.ok(data.secret, 'secret must be returned');
    assert.ok(data.uri, 'uri must be returned');
    assert.ok(data.uri.startsWith('otpauth://totp/'), 'uri must start with otpauth://totp/');
    setupSecret = data.secret;
    setupUri = data.uri;

    // Check DB: encrypted, IV, tag populated, but totp_enabled STILL false
    const dbRes = await query('SELECT * FROM users WHERE email = $1', [testRegEmail]);
    const row = dbRes.rows[0];
    assert.strictEqual(row.totp_enabled, false, 'totp_enabled must still be false before verification');
    assert.ok(row.totp_secret_encrypted, 'totp_secret_encrypted must be set');
    assert.ok(row.totp_iv, 'totp_iv must be set');
    assert.ok(row.totp_tag, 'totp_tag must be set');
    firstSetupIv = row.totp_iv;

    // Requirement 7 asserts:
    assert.notStrictEqual(row.totp_secret_encrypted, setupSecret, 'Encrypted secret must not equal plaintext');
    assert.strictEqual(row.totp_secret_encrypted.includes(setupSecret), false, 'Ciphertext must not contain plaintext secret');

    // Test decryption returns the exact original secret
    const decrypted = decrypt(row.totp_iv, row.totp_secret_encrypted, row.totp_tag);
    assert.strictEqual(decrypted, setupSecret, 'Decrypted secret must match original setup secret');
  });

  // Requirement 8: 2FA Verify activates 2FA
  await test('Requirement 8: POST /api/auth/2fa/verify enables 2FA with valid code', async () => {
    const currentWindow = Math.floor(Date.now() / 30000);
    const validCode = generateTotpCode(setupSecret, currentWindow);

    const res = await fetch(`${BASE_URL}/api/auth/2fa/verify`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${standardUserToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ code: validCode })
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.message, '2FA successfully enabled');

    // Check DB: totp_enabled is now true!
    const dbRes = await query('SELECT totp_enabled, last_totp_window FROM users WHERE email = $1', [testRegEmail]);
    assert.strictEqual(dbRes.rows[0].totp_enabled, true, 'totp_enabled must now be true');
    assert.strictEqual(dbRes.rows[0].last_totp_window, currentWindow, 'last_totp_window must record current window');
  });

  // Requirement 9: Secondary login endpoint /api/auth/2fa/login
  let seededChallengeToken;
  await test('Requirement 9: POST /api/auth/2fa/login validates TOTP against challenge token', async () => {
    // 1. Get challenge token for seeded user
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: submissionUser.email,
        password: submissionUser.password
      })
    });
    const loginData = await loginRes.json();
    seededChallengeToken = loginData.challenge_token;

    // 2. Test invalid code returns 401
    const badCodeRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: seededChallengeToken,
        code: '000000'
      })
    });
    assert.strictEqual(badCodeRes.status, 401, 'Invalid TOTP code must return 401');

    // 3. Test valid code returns 200 and full access token
    const currentWindow = Math.floor(Date.now() / 30000);
    const validCode = generateTotpCode(submissionUser.plaintextTotpSecret, currentWindow);

    const goodRes = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: seededChallengeToken,
        code: validCode
      })
    });

    assert.strictEqual(goodRes.status, 200);
    const goodData = await goodRes.json();
    assert.ok(goodData.token, 'Must return full access token upon successful 2FA verification');
  });

  // Requirement 10: Strict 2FA Enforcement (Challenge token cannot access protected routes)
  await test('Requirement 10: Challenge token strictly rejected on protected routes', async () => {
    // Get a fresh challenge token
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: submissionUser.email,
        password: submissionUser.password
      })
    });
    const { challenge_token } = await loginRes.json();

    // Attempt to access /api/protected using challenge_token
    const resProtected = await fetch(`${BASE_URL}/api/protected`, {
      headers: { 'Authorization': `Bearer ${challenge_token}` }
    });
    assert.ok(
      resProtected.status === 401 || resProtected.status === 403,
      `Challenge token must be rejected with 401 or 403, got ${resProtected.status}`
    );

    // Attempt to access /api/auth/2fa/setup using challenge_token
    const resSetup = await fetch(`${BASE_URL}/api/auth/2fa/setup`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${challenge_token}`,
        'Content-Type': 'application/json'
      }
    });
    assert.ok(
      resSetup.status === 401 || resSetup.status === 403,
      `Challenge token must be rejected with 401 or 403 on setup, got ${resSetup.status}`
    );
  });

  // Requirement 11: Replay Protection
  await test('Requirement 11: System prevents replay of valid TOTP code within 30s window', async () => {
    // 1. Get challenge token for testRegEmail (now 2FA enabled)
    const loginRes = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testRegEmail,
        password: testRegPassword
      })
    });
    const { challenge_token } = await loginRes.json();

    // 2. Generate valid TOTP code
    const currentWindow = Math.floor(Date.now() / 30000);
    // Ensure last_totp_window in DB is set to currentWindow - 1 so currentWindow is fresh
    await query('UPDATE users SET last_totp_window = $1 WHERE email = $2', [currentWindow - 1, testRegEmail]);

    const code = generateTotpCode(setupSecret, currentWindow);

    // 3. First request: must succeed (200 OK)
    const firstReq = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_token, code })
    });
    assert.strictEqual(firstReq.status, 200, 'First submission must succeed with 200 OK');

    // 4. Immediately replay the identical request: must fail with 401 Unauthorized
    const replayReq = await fetch(`${BASE_URL}/api/auth/2fa/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_token, code })
    });
    assert.strictEqual(replayReq.status, 401, 'Replay of same code in same window must be rejected with 401');

    // 5. Verify database last_totp_window matches currentWindow
    const dbRes = await query('SELECT last_totp_window FROM users WHERE email = $1', [testRegEmail]);
    assert.strictEqual(dbRes.rows[0].last_totp_window, currentWindow, 'DB last_totp_window must record matching window');
  });

  console.log('\n====================================================');
  console.log(` RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================\n');

  await pool.end();
  if (failed > 0) {
    process.exit(1);
  }
}

if (require.main === module) {
  runTests().catch(err => {
    console.error('Test suite failed:', err);
    process.exit(1);
  });
}
