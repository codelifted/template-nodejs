const express = require('express');
const axios = require('axios');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://frontend.hello-world.local.codelifted.com',
  credentials: true
}));

// Function to get token for user management client
async function getUserManagementToken() {
  try {
    const tokenUrl = `${process.env.USER_MGMT_KEYCLOAK_URL}/realms/${process.env.USER_MGMT_KEYCLOAK_REALM}/protocol/openid-connect/token`;
    const requestBody = {
      client_id: process.env.USER_MGMT_KEYCLOAK_CLIENT_ID,
      client_secret: process.env.USER_MGMT_KEYCLOAK_CLIENT_SECRET,
      grant_type: 'client_credentials',
    };

    console.log('Token Request URL:', tokenUrl);
    console.log('Token Request Headers:', { 'Content-Type': 'application/x-www-form-urlencoded' });
    console.log('Token Request Body:', requestBody);

    const response = await axios.post(
      tokenUrl,
      new URLSearchParams(requestBody),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    return response.data.access_token;
  } catch (error) {
    console.error('Token Request Error:', error.response?.data || error.message);
    throw new Error('Failed to get user management token: ' + (error.response?.data?.error_description || error.message));
  }
}

// Registration endpoint with email verification
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    const token = await getUserManagementToken();
    const registerUrl = `${process.env.USER_MGMT_KEYCLOAK_URL}/admin/realms/${process.env.USER_MGMT_KEYCLOAK_REALM}/users`;
    const userData = {
      username,
      email,
      enabled: true,
      credentials: [{ type: 'password', value: password, temporary: false }],
      requiredActions: ["VERIFY_EMAIL"]
    };

    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    console.log('Register Request URL:', registerUrl);
    console.log('Register Request Headers:', headers);
    console.log('Register Request Body:', userData);

    // Create the user
    const createUserResponse = await axios.post(registerUrl, userData, { headers });
    const userId = createUserResponse.headers['location'].split('/').pop(); // Extract user ID from Location header

    // Trigger email verification
    const verifyEmailUrl = `${process.env.USER_MGMT_KEYCLOAK_URL}/admin/realms/${process.env.USER_MGMT_KEYCLOAK_REALM}/users/${userId}/execute-actions-email`;
    const verifyEmailData = ["VERIFY_EMAIL"];
    await axios.put(verifyEmailUrl, verifyEmailData, { headers });

    res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
  } catch (error) {
    console.error('Registration Request Error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// Login endpoint (unchanged)
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const response = await axios.post(
      `${process.env.AUTH_KEYCLOAK_URL}/realms/${process.env.AUTH_KEYCLOAK_REALM}/protocol/openid-connect/token`,
      new URLSearchParams({
        client_id: process.env.AUTH_KEYCLOAK_CLIENT_ID,
        client_secret: process.env.AUTH_KEYCLOAK_CLIENT_SECRET,
        grant_type: 'password',
        username,
        password,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Start the server
const PORT = process.env.PORT || 80;
app.listen(PORT, () => {
  console.log(`Backend server running at http://backend.hello-world.local.codelifted.com:${PORT}`);
});