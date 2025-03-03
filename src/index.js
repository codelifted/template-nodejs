const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const aws4 = require('aws4');
const https = require('https');
const stripe = require('stripe')(process.env.STRIPE_API_KEY);
const { CognitoUserPool, CognitoUser } = require('amazon-cognito-identity-js');
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

// Cognito User Pool
const userPool = new CognitoUserPool({
  UserPoolId: process.env.COGNITO_USER_POOL_ID,
  ClientId: process.env.COGNITO_CLIENT_ID,
});

// Helper function to get user attributes from Cognito
async function getUserAttributes(cognitoUserId) {
  const user = new CognitoUser({ Username: cognitoUserId, Pool: userPool });
  return new Promise((resolve, reject) => {
    user.getUserAttributes((err, attributes) => {
      if (err) reject(err);
      else {
        const attrMap = {};
        attributes.forEach(attr => attrMap[attr.getName()] = attr.getValue());
        resolve(attrMap);
      }
    });
  });
}

// Helper function to get or create user
async function getOrCreateUser(cognitoUserId) {
  const client = await pool.connect();
  try {
    const res = await client.query('SELECT id, stripe_customer_id, plan FROM users WHERE cognito_user_id = $1', [cognitoUserId]);
    if (res.rows.length > 0) {
      return res.rows[0];
    }
    const insertRes = await client.query(
      'INSERT INTO users (cognito_user_id) VALUES ($1) RETURNING id, stripe_customer_id, plan',
      [cognitoUserId]
    );
    const user = insertRes.rows[0];
    // Create Stripe customer for new user
    const attributes = await getUserAttributes(cognitoUserId);
    const email = attributes.email;
    const name = `${attributes.given_name} ${attributes.family_name}`;
    const customer = await stripe.customers.create({ email, name });
    await client.query(
      'UPDATE users SET stripe_customer_id = $1 WHERE id = $2',
      [customer.id, user.id]
    );
    user.stripe_customer_id = customer.id;
    return user;
  } catch (error) {
    console.error('Error in getOrCreateUser:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Endpoints

// /me: Get or create user info, including plan
app.get('/me', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId);
    res.json({ id: user.id, cognitoUserId, plan: user.plan });
  } catch (error) {
    console.error('Error in /me:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// /set-plan: Set user's plan
app.post('/set-plan', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId);
    const { plan } = req.body;
    if (!['free', 'pro'].includes(plan)) {
      return res.status(400).json({ error: 'Invalid plan' });
    }
    const client = await pool.connect();
    try {
      await client.query('UPDATE users SET plan = $1 WHERE id = $2', [plan, user.id]);
      res.json({ message: 'Plan set successfully' });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error in /set-plan:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// /stripe-checkout: Initiate Stripe checkout for pro plan
app.post('/stripe-checkout', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId);
    if (!user.stripe_customer_id) {
      throw new Error('User does not have a Stripe customer ID');
    }
    const session = await stripe.checkout.sessions.create({
      customer: user.stripe_customer_id,
      line_items: [{
        price: process.env.STRIPE_PRO_PLAN_PRICE_ID,
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: 'https://frontend.hello-world.local.codelifted.com/dashboard',
      cancel_url: 'https://frontend.hello-world.local.codelifted.com/pricing',
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error('Error in /stripe-checkout:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// /stripe-webhook: Handle Stripe webhook events
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPEWEBHOOK_SIGNING_SECRET);
  } catch (err) {
    console.error(`Webhook signature verification failed: ${err.message}`);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  const client = await pool.connect();
  try {
    const customerID = event.data.object.customer;
    let userID = null;
    if (customerID) {
      const res = await client.query('SELECT id FROM users WHERE stripe_customer_id = $1', [customerID]);
      if (res.rows.length > 0) userID = res.rows[0].id;
    }
    await client.query(
      'INSERT INTO stripe_events (event_type, event_data, user_id) VALUES ($1, $2, $3)',
      [event.type, JSON.stringify(event.data.object), userID]
    );
    switch (event.type) {
      case 'customer.subscription.created':
        if (userID) await client.query('UPDATE users SET plan = \'pro\' WHERE id = $1', [userID]);
        break;
      case 'customer.subscription.deleted':
        if (userID) await client.query('UPDATE users SET plan = \'free\' WHERE id = $1', [userID]);
        break;
      default:
        console.log(`Unhandled event type: ${event.type}`);
    }
    res.sendStatus(200);
  } catch (error) {
    console.error('Error handling webhook:', error);
    res.status(500).send('Internal server error');
  } finally {
    client.release();
  }
});

// Existing endpoints (unchanged for brevity, but included for completeness)

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

// /recover: Password recovery
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
    process.exit(1);
  });

// Database schema (assumed in db.js)
const db = {
  initializeSchema: async () => {
    const client = await pool.connect();
    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          cognito_user_id VARCHAR(255) NOT NULL UNIQUE,
          stripe_customer_id VARCHAR(255),
          plan VARCHAR(50) DEFAULT 'free'
        );
        CREATE TABLE IF NOT EXISTS projects (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          owner_id INTEGER REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS stripe_events (
          id SERIAL PRIMARY KEY,
          event_type VARCHAR(255) NOT NULL,
          event_data JSON NOT NULL,
          user_id INTEGER REFERENCES users(id),
          created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
      `);
    } finally {
      client.release();
    }
  },
  pool,
};

module.exports = db;