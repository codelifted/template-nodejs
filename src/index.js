const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const aws4 = require('aws4');
const https = require('https');
const stripe = require('stripe')(process.env.STRIPE_API_KEY);
const { CognitoUserPool } = require('amazon-cognito-identity-js');
const { pool, initializeSchema } = require('./db');

// Global URL constants
const WEBHOOK_URL = 'https://backend.hello-world.local.codelifted.com/stripe-webhook';
const CHECKOUT_SUCCESS_URL = 'https://frontend.hello-world.local.codelifted.com/dashboard';
const CHECKOUT_CANCEL_URL = 'https://frontend.hello-world.local.codelifted.com/pricing';
const SERVER_BASE_URL = 'https://backend.hello-world.local.codelifted.com';
const CORS_ORIGIN = 'https://frontend.hello-world.local.codelifted.com';
const COGNITO_JWKS_URL = `https://cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`;
const COGNITO_IDP_HOST = `cognito-idp.${process.env.COGNITO_REGION}.amazonaws.com`;

const app = express();

// Middleware for webhook (raw body) - must come before bodyParser.json
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
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

// General middleware (after webhook route)
app.use(bodyParser.json());
app.use(cors({
  origin: CORS_ORIGIN,
  credentials: true,
}));

// JWKS client for token validation
const client = jwksClient({
  jwksUri: COGNITO_JWKS_URL,
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

// Cognito User Pool (kept for potential future use)
const userPool = new CognitoUserPool({
  UserPoolId: process.env.COGNITO_USER_POOL_ID,
  ClientId: process.env.COGNITO_CLIENT_ID,
});

// Global variables for Stripe configuration
let proPlanPriceId;
let webhookSecret;

// Helper function to get or create user, using token attributes
async function getOrCreateUser(cognitoUserId, tokenAttributes) {
  const client = await pool.connect();
  try {
    const res = await client.query('SELECT id, stripe_customer_id, plan FROM users WHERE cognito_user_id = $1', [cognitoUserId]);
    let user = res.rows[0];

    if (!user) {
      const insertRes = await client.query(
        'INSERT INTO users (cognito_user_id) VALUES ($1) RETURNING id, stripe_customer_id, plan',
        [cognitoUserId]
      );
      user = insertRes.rows[0];
    }

    if (!user.stripe_customer_id) {
      const email = tokenAttributes.email || 'unknown@example.com';
      const name = `${tokenAttributes.given_name || ''} ${tokenAttributes.family_name || ''}`.trim() || 'Unnamed User';
      const customer = await stripe.customers.create({ email, name });
      await client.query(
        'UPDATE users SET stripe_customer_id = $1 WHERE id = $2',
        [customer.id, user.id]
      );
      user.stripe_customer_id = customer.id;
    }

    return user;
  } catch (error) {
    console.error('Error in getOrCreateUser:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Stripe initialization functions
async function ensureProPlanPrice() {
  try {
    const prices = await stripe.prices.list({
      lookup_keys: ['pro_plan_monthly'],
      limit: 1,
    });
    if (prices.data.length > 0) {
      console.log('Using existing Pro Plan Price ID:', prices.data[0].id);
      return prices.data[0].id;
    }

    const product = await stripe.products.create({
      name: 'Pro Plan',
      description: 'Premium subscription for advanced features',
    });

    const price = await stripe.prices.create({
      product: product.id,
      unit_amount: 1000,
      currency: 'usd',
      recurring: { interval: 'month' },
      lookup_key: 'pro_plan_monthly',
    });

    console.log('Created Pro Plan Price ID:', price.id);
    return price.id;
  } catch (error) {
    console.error('Error ensuring Pro Plan price:', error);
    throw error;
  }
}

async function ensureWebhookEndpoint() {
  const client = await pool.connect();
  try {
    const res = await client.query('SELECT stripe_webhook_secret FROM config WHERE key = $1', ['stripe_webhook_secret']);
    if (res.rows.length > 0) {
      console.log('Using stored webhook secret from DB');
      return res.rows[0].stripe_webhook_secret;
    }

    const endpoints = await stripe.webhookEndpoints.list({ limit: 10 });
    const existing = endpoints.data.find(e => e.url === WEBHOOK_URL);
    if (existing) {
      await stripe.webhookEndpoints.del(existing.id);
      console.log('Deleted existing webhook endpoint:', existing.id);
    }

    const webhook = await stripe.webhookEndpoints.create({
      url: WEBHOOK_URL,
      enabled_events: [
        'customer.subscription.created',
        'customer.subscription.deleted',
      ],
      description: 'Webhook for Hello World backend',
    });

    const secret = webhook.secret;
    console.log('Created new webhook endpoint:', webhook.id, 'with secret:', secret);

    await client.query(
      'INSERT INTO config (key, stripe_webhook_secret) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET stripe_webhook_secret = $2',
      ['stripe_webhook_secret', secret]
    );
    return secret;
  } catch (error) {
    console.error('Error ensuring webhook endpoint:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Endpoints
app.get('/me', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId, req.user);
    res.json({ id: user.id, cognitoUserId, plan: user.plan });
  } catch (error) {
    console.error('Error in /me:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/set-plan', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId, req.user);
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

app.post('/stripe-checkout', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId, req.user);
    const session = await stripe.checkout.sessions.create({
      customer: user.stripe_customer_id,
      line_items: [{
        price: proPlanPriceId,
        quantity: 1,
      }],
      mode: 'subscription',
      success_url: CHECKOUT_SUCCESS_URL,
      cancel_url: CHECKOUT_CANCEL_URL,
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error('Error in /stripe-checkout:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/projects', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId, req.user);
    const client = await pool.connect();
    try {
      const resProjects = await client.query('SELECT id, name FROM projects WHERE owner_id = $1', [user.id]);
      res.json({ projects: resProjects.rows });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error in /projects:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/projects', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId, req.user);
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

app.delete('/projects/:id', validateToken, async (req, res) => {
  try {
    const cognitoUserId = req.user.sub;
    const user = await getOrCreateUser(cognitoUserId, req.user);
    const client = await pool.connect();
    try {
      const resProject = await client.query('SELECT owner_id FROM projects WHERE id = $1', [req.params.id]);
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

app.get('/protected', validateToken, (req, res) => {
  res.json({ message: 'Access granted', user: req.user });
});

app.get('/user-info', validateToken, async (req, res) => {
  try {
    const username = req.user.sub;
    const opts = {
      host: COGNITO_IDP_HOST,
      path: '/',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityProviderService.AdminGetUser',
      },
      body: JSON.stringify({ UserPoolId: process.env.COGNITO_USER_POOL_ID, Username: username }),
    };
    aws4.sign(opts, { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY });
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
    host: COGNITO_IDP_HOST,
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
  aws4.sign(opts, { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY });
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
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start the server after initialization
const PORT = process.env.PORT || 80;
initializeSchema()
  .then(() => Promise.all([ensureProPlanPrice(), ensureWebhookEndpoint()]))
  .then(([priceId, secret]) => {
    proPlanPriceId = priceId;
    webhookSecret = secret;
    app.listen(PORT, () => {
      console.log(`Backend server running at ${SERVER_BASE_URL}:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to start server due to initialization error:', err);
    process.exit(1);
  });