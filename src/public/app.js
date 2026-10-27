// Client-side application script

let state = {
  challengeToken: null,
  accessToken: null,
  seededSecret: 'JBSWY3DPEHPK3PXP',
  lastSubmittedCode: null
};

// Elements
const logConsole = document.getElementById('log-console');
const challengeBox = document.getElementById('challenge-box');
const liveCodeDisplay = document.getElementById('live-code-display');
const totpTimer = document.getElementById('totp-timer');
const displayChallengeToken = document.getElementById('display-challenge-token');
const displayAccessToken = document.getElementById('display-access-token');

// Tab Navigation
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

function log(type, message, details = null) {
  const entry = document.createElement('div');
  entry.className = `log-entry log-${type}`;
  const timestamp = new Date().toLocaleTimeString();
  let text = `[${timestamp}] ${message}`;
  if (details) {
    text += ` | ${typeof details === 'object' ? JSON.stringify(details) : details}`;
  }
  entry.textContent = text;
  logConsole.appendChild(entry);
  logConsole.scrollTop = logConsole.scrollHeight;
}

document.getElementById('btn-clear-logs').addEventListener('click', () => {
  logConsole.innerHTML = '';
  log('info', 'Logs cleared.');
});

// Update Token Displays
function updateTokenDisplays() {
  displayChallengeToken.textContent = state.challengeToken || 'None';
  displayAccessToken.textContent = state.accessToken || 'None';
}

// Autofill Test User
document.getElementById('btn-autofill-testuser').addEventListener('click', () => {
  document.getElementById('login-email').value = 'test_2fa@example.com';
  document.getElementById('login-password').value = 'securePassword123';
  log('info', 'Loaded pre-seeded test user credentials into login form.');
});

// TOTP Algorithm in Browser (for live preview of seeded secret)
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32ToBytes(base32) {
  let clean = base32.replace(/[\s=]/g, '').toUpperCase();
  let bits = 0, val = 0, bytes = [];
  for (let i = 0; i < clean.length; i++) {
    let idx = BASE32_CHARS.indexOf(clean[i]);
    if (idx === -1) continue;
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((val >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

async function computeBrowserTotp(secret) {
  try {
    const keyBytes = base32ToBytes(secret);
    const key = await window.crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );

    const epochSeconds = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epochSeconds / 30);
    const counterBuf = new ArrayBuffer(8);
    const view = new DataView(counterBuf);
    view.setUint32(0, Math.floor(counter / 0x100000000));
    view.setUint32(4, counter >>> 0);

    const signature = await window.crypto.subtle.sign('HMAC', key, counterBuf);
    const hmac = new Uint8Array(signature);
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = binary % 1000000;
    return otp.toString().padStart(6, '0');
  } catch (e) {
    return '------';
  }
}

// Live timer updater
setInterval(async () => {
  const secondsLeft = 30 - (Math.floor(Date.now() / 1000) % 30);
  totpTimer.textContent = `Window expires in: ${secondsLeft}s`;
  const code = await computeBrowserTotp(state.seededSecret);
  liveCodeDisplay.textContent = code;
}, 1000);

document.getElementById('btn-use-live-code').addEventListener('click', () => {
  document.getElementById('challenge-code').value = liveCodeDisplay.textContent;
});

// Step 1: Login Form Submission
document.getElementById('form-login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;

  log('info', `Submitting login request for ${email}...`);

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (!res.ok) {
      log('error', `Login failed (${res.status})`, data.error || data);
      return;
    }

    if (data.requires_2fa) {
      state.challengeToken = data.challenge_token;
      state.accessToken = null;
      updateTokenDisplays();
      challengeBox.classList.remove('hidden');
      log('warn', 'HTTP 200 OK: 2FA required. Restricted challenge_token issued.', {
        requires_2fa: true,
        challenge_token: data.challenge_token.substring(0, 30) + '...'
      });
      document.getElementById('challenge-code').focus();
    } else {
      state.accessToken = data.token;
      state.challengeToken = null;
      updateTokenDisplays();
      challengeBox.classList.add('hidden');
      log('success', 'HTTP 200 OK: Login successful (Single-Factor account). Full access token issued.');
    }
  } catch (err) {
    log('error', 'Network or server error during login', err.message);
  }
});

// Step 2: Verify TOTP Code
document.getElementById('form-challenge').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = document.getElementById('challenge-code').value;

  if (!state.challengeToken) {
    log('error', 'No active challenge token found. Please complete Step 1 first.');
    return;
  }

  log('info', `Submitting TOTP code ${code} for verification...`);

  try {
    const res = await fetch('/api/auth/2fa/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: state.challengeToken,
        code
      })
    });
    const data = await res.json();

    if (!res.ok) {
      log('error', `2FA verification failed (${res.status})`, data.error || data);
      return;
    }

    state.lastSubmittedCode = code;
    state.accessToken = data.token;
    state.challengeToken = null;
    updateTokenDisplays();
    challengeBox.classList.add('hidden');
    log('success', 'HTTP 200 OK: 2FA Verified! Full access JWT token issued.', {
      token: data.token.substring(0, 30) + '...'
    });
  } catch (err) {
    log('error', 'Network error during 2FA login', err.message);
  }
});

// Step 3: Simulate Replay Attack
document.getElementById('btn-test-replay').addEventListener('click', async () => {
  const code = document.getElementById('challenge-code').value || state.lastSubmittedCode;

  if (!code) {
    log('error', 'Please enter a 6-digit code or complete a login first to test replay.');
    return;
  }

  log('warn', `[ATTACK SIMULATION] Replaying previously used code ${code}...`);

  // First get a fresh challenge token if needed
  let challengeTokenToUse = state.challengeToken;
  if (!challengeTokenToUse) {
    const email = document.getElementById('login-email').value || 'test_2fa@example.com';
    const password = document.getElementById('login-password').value || 'securePassword123';
    try {
      const loginRes = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const loginData = await loginRes.json();
      if (loginData.challenge_token) {
        challengeTokenToUse = loginData.challenge_token;
      }
    } catch (e) {}
  }

  try {
    const res = await fetch('/api/auth/2fa/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_token: challengeTokenToUse,
        code
      })
    });
    const data = await res.json();

    if (res.status === 401) {
      log('success', `[DEFENSE PASSED] HTTP 401 Replay Rejected!`, data.error);
    } else if (res.ok) {
      log('error', `[DEFENSE FAILED] Replay attack succeeded when it should have failed!`);
    } else {
      log('warn', `Replay request returned ${res.status}:`, data);
    }
  } catch (err) {
    log('error', 'Error simulating replay attack', err.message);
  }
});

// Register Tab Handler
document.getElementById('form-register').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;

  log('info', `Registering new user ${email}...`);

  try {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (res.status === 201) {
      log('success', `HTTP 201 Created: User registered successfully!`, data);
      document.getElementById('login-email').value = email;
      document.getElementById('login-password').value = password;
      alert(`User ${email} created! Switching to Login tab.`);
      document.querySelector('[data-tab="login-tab"]').click();
    } else {
      log('error', `Registration failed (${res.status})`, data.error || data);
    }
  } catch (err) {
    log('error', 'Error registering user', err.message);
  }
});

// Provisioning (Setup 2FA)
document.getElementById('btn-start-setup').addEventListener('click', async () => {
  if (!state.accessToken) {
    log('error', 'Full access token required to setup 2FA. Please log in first.');
    alert('Please log in with a user first to obtain a full access session.');
    return;
  }

  log('info', 'Requesting 2FA secret provisioning via POST /api/auth/2fa/setup...');

  try {
    const res = await fetch('/api/auth/2fa/setup', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${state.accessToken}`,
        'Content-Type': 'application/json'
      }
    });
    const data = await res.json();

    if (!res.ok) {
      log('error', `2FA Setup failed (${res.status})`, data.error || data);
      return;
    }

    log('success', '2FA Setup secret generated. Encrypted at rest in database.', {
      secret: data.secret,
      uri: data.uri
    });

    document.getElementById('setup-secret-text').textContent = data.secret;
    document.getElementById('setup-uri-text').textContent = data.uri;
    state.seededSecret = data.secret; // update live generator preview

    // Render QR Code
    const qrEl = document.getElementById('qrcode');
    qrEl.innerHTML = '';
    new QRCode(qrEl, {
      text: data.uri,
      width: 140,
      height: 140,
      correctLevel: QRCode.CorrectLevel.M
    });

    document.getElementById('setup-details').classList.remove('hidden');
  } catch (err) {
    log('error', 'Network error during 2FA setup', err.message);
  }
});

// Confirm 2FA Setup
document.getElementById('btn-confirm-setup').addEventListener('click', async () => {
  const code = document.getElementById('setup-verify-code').value;
  if (!code || !state.accessToken) {
    log('error', 'Please enter the 6-digit code from your authenticator app.');
    return;
  }

  log('info', `Confirming 2FA activation with code ${code}...`);

  try {
    const res = await fetch('/api/auth/2fa/verify', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${state.accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ code })
    });
    const data = await res.json();

    if (res.ok) {
      log('success', `HTTP 200 OK: ${data.message}! Account is now 2FA protected.`);
      alert('2FA successfully enabled! Future logins will require TOTP.');
    } else {
      log('error', `Failed to verify code (${res.status})`, data.error || data);
    }
  } catch (err) {
    log('error', 'Network error verifying setup code', err.message);
  }
});

// Inspector: Test Protected Route with Access Token
document.getElementById('btn-test-protected-token').addEventListener('click', async () => {
  if (!state.accessToken) {
    log('warn', 'No access token available. Please log in first.');
    return;
  }

  log('info', 'Accessing GET /api/protected with Full Access Token...');
  try {
    const res = await fetch('/api/protected', {
      headers: { 'Authorization': `Bearer ${state.accessToken}` }
    });
    const data = await res.json();
    if (res.ok) {
      log('success', `HTTP 200 OK: Protected route accessed successfully!`, data);
    } else {
      log('error', `HTTP ${res.status}: Protected route rejected.`, data);
    }
  } catch (err) {
    log('error', 'Request failed', err.message);
  }
});

// Inspector: Test 2FA Bypass Attempt with Challenge Token
document.getElementById('btn-test-challenge-bypass').addEventListener('click', async () => {
  if (!state.challengeToken) {
    log('warn', 'No challenge token available. Submit step 1 password for a 2FA user first.');
    return;
  }

  log('warn', '[BYPASS ATTEMPT] Attempting to access GET /api/protected using challenge_token...');
  try {
    const res = await fetch('/api/protected', {
      headers: { 'Authorization': `Bearer ${state.challengeToken}` }
    });
    const data = await res.json();
    if (res.status === 403 || res.status === 401) {
      log('success', `[DEFENSE PASSED] HTTP ${res.status} Forbidden: Challenge token cannot access protected routes!`, data);
    } else {
      log('error', `[DEFENSE FAILED] HTTP ${res.status}: Bypass allowed!`, data);
    }
  } catch (err) {
    log('error', 'Request failed', err.message);
  }
});

// Check API Health
fetch('/health')
  .then(r => r.json())
  .then(data => {
    document.getElementById('system-health').textContent = `API Online (${data.database})`;
  })
  .catch(() => {
    document.getElementById('system-health').textContent = 'API Connecting...';
  });
