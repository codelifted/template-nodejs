const express = require('express');
const Keycloak = require('keycloak-connect');
const apiRoutes = require('./routes/api');

const app = express();

// Keycloak configuration with environment variables
const keycloak = new Keycloak({}, {
  'auth-server-url': process.env.IDP_URL, // e.g., http://idp.hello-world.local.codelifted.com
  'realm': 'saas-hello-world-auth',
  'clientId': process.env.CLIENT_ID, // e.g., saas-client
  'secret': process.env.CLIENT_SECRET, // From auth-creds secret
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