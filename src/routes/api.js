const express = require('express');
const router = express.Router();

// This route is automatically protected by Keycloak middleware from app.js
router.get('/', (req, res) => {
  res.json({ message: 'Hello from protected API!', user: req.kauth.grant.access_token.content });
});

module.exports = router;