const express = require('express');
const router = express.Router();
const pool = require('../config/db');

// Protected endpoint
router.get('/', async (req, res) => {
  try {
    // Example: Query the database
    const result = await pool.query('SELECT NOW()');
    const user = req.kauth.grant.access_token.content; // Keycloak user info

    res.json({
      message: 'Hello from Node.js backend!',
      user: {
        id: user.sub,
        username: user.preferred_username,
        email: user.email,
      },
      databaseTime: result.rows[0].now,
    });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;