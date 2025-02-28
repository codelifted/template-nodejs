const express = require('express');
const Keycloak = require('keycloak-connect');
const apiRoutes = require('./routes/api');

const app = express();

// Keycloak configuration from environment variables
const keycloak = new Keycloak({}, {
  'auth-server-url': process.env.IDP_URL, // From auth-creds secret
  'realm': 'saas-hello-world-auth',       // Matches controller-generated realm
  'clientId': process.env.CLIENT_ID,      // From auth-creds secret
  'secret': process.env.CLIENT_SECRET,    // From auth-creds secret
  'ssl-required': 'external',
  'resource': process.env.CLIENT_ID,
});

// Apply Keycloak middleware
app.use(keycloak.middleware());

// Mount API routes
app.use('/api', apiRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});