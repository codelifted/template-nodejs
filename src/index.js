const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const aws4 = require('aws4');
const https = require('https');
const { pool, initializeSchema } = require('./db');

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

// Helper function to get or create user
async function getOrCreateUser(cognitoUserId) {
  const client = await pool.connect();
  try {
    const res = await client.query('SELECT id FROM users WHERE cognito_user_id = $1', [cognitoUserId]);
    if (res.rows.length > 0) {
      return res.rows[0];
    }
    const insertRes = await client.query(
      'INSERT INTO users (cognito_user_id) VALUES ($1) RETURNING id',
      [cognitoUserId]
    );
    return { id: insertRes.rows[0].id };
  } finally {
    client.release();
  }
}

// Endpoints

// /me: Get or create user info
app.get('/me', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId);
    res.json({ id: user.id, cognitoUserId });
  } catch (error) {
    console.error('Error in /me:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// /projects: List user's projects
app.get('/projects', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId);
    const client = await pool.connect();
    try {
      const resProjects = await client.query(
        'SELECT id, name FROM projects WHERE owner_id = $1',
        [user.id]
      );
      res.json({ projects: resProjects.rows });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error in /projects:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// /projects: Create a project
app.post('/projects', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId);
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Project name is required' });
    const client = await pool.connect();
    try {
      const insertRes = await client.query(
        'INSERT INTO projects (name, owner_id) VALUES ($1, $2) RETURNING id, name',
        [name, user.id]
      );
      res.status(201).json({ project: insertRes.rows[0] });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error in /projects POST:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// /projects/:id: Delete a project
app.delete('/projects/:id', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId);
    const client = await pool.connect();
    try {
      const resProject = await client.query(
        'SELECT owner_id FROM projects WHERE id = $1',
        [req.params.id]
      );
      if (resProject.rows.length === 0) return res.status(404).json({ error: 'Project not found' });
      if (resProject.rows[0].owner_id !== user.id) return res.status(403).json({ error: 'Forbidden' });
      await client.query('DELETE FROM projects WHERE id = $1', [req.params.id]);
      res.json({ message: 'Project deleted' });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error in /projects/:id DELETE:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// /protected: Protected route example
app.get('/protected', validateToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});

// /user-info: Fetch Cognito user info
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

app.post('/recover', async (req, res) => {
  const { username } = req.body;
  const opts = {
    host: `cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com`,
    path: '/',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Target': 'AWSCognitoIdentityProviderService.ForgotPassword',
    },
    body: JSON.stringify({
      ClientId: process.env.COGNITO_CLIENT_ID,
      Username: username,
    }),
  };

  aws4.sign(opts, {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  });

  try {
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
    console.error('Error in password recovery:', error);
    res.status(500).json({ error: 'Failed to initiate password recovery' });
  }
});

// Start the server after schema initialization
const PORT = process.env.PORT || 80;
initializeSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Backend server running at https://backend.hello-world.local.codelifted.com:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to start server due to schema initialization error:', err);
    process.exit(1); // Exit with failure code if schema creation fails
  });