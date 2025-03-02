const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const aws4 = require('aws4');
const https = require('https');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: 'https://frontend.hello-world.local.codelifted.com',
  credentials: true,
}));

// JWKS client for token validation
const client = jwksClient({
  jwksUri: `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

// Token validation middleware
function validateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Protected endpoint
app.get('/protected', validateToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});

// Optional: Fetch user info from Cognito using aws4
app.get('/user-info', validateToken, async (req, res) => {
  try {
    const username = req.user.sub;
    const opts = {
      host: `cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com`,
      path: '/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.AdminGetUser',
      },
      body: JSON.stringify({ UserPoolId: process.env.COGNITO_USER_POOL_ID, Username: username }),
    };

    aws4.sign(opts, {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    });

    const response = await new Promise((resolve, reject) => {
      const req = https.request(opts, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve(JSON.parse(data)));
      });
      req.on('error', reject);
      req.write(opts.body);
      req.end();
    });

    res.json(response);
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: 'Failed to fetch user info' });
  }
});

// Start the server
const PORT = process.env.PORT || 80;
app.listen(PORT, () => {
  console.log(`Backend server running at https://backend.hello-world.local.codelifted.com:${PORT}`);
});