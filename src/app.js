const express = require('express');
const cors = require('cors');
const path = require('path');
const config = require('./config/env');
const db = require('./db');
const { runMigrations } = require('./db/migrate');
const { seedDatabase } = require('./db/seed');
const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static frontend UI
app.use(express.static(path.join(__dirname, 'public')));

// Health check endpoint for Docker Compose and monitoring
app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.status(200).json({ status: 'healthy', database: 'connected' });
  } catch (err) {
    res.status(503).json({ status: 'unhealthy', error: err.message });
  }
});

// Auth API routes
app.use('/api/auth', authRoutes);

// Protected route for token verification testing
app.get('/api/protected', requireAuth, (req, res) => {
  res.status(200).json({
    message: 'Access granted to protected resource',
    user: req.user
  });
});

// Root route fallback if public directory isn't serving index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialization function (runs migrations and seeds test user)
async function initServer() {
  try {
    await runMigrations();
    await seedDatabase();
    console.log('Database initialized and seeded.');
  } catch (err) {
    console.error('Initialization error:', err);
    // Continue or exit based on environment
  }
}

let server;
if (require.main === module) {
  initServer().then(() => {
    server = app.listen(config.port, () => {
      console.log(`Server listening on port ${config.port} (env: ${config.nodeEnv})`);
    });
  });
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  if (server) {
    server.close(() => {
      db.pool.end();
      process.exit(0);
    });
  }
});

module.exports = {
  app,
  initServer
};
