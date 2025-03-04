const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.main_HOST,
  port: process.env.main_PORT,
  database: process.env.main_DATABASE,
  user: process.env.main_USERNAME,
  password: process.env.main_PASSWORD,
  ssl: {
    rejectUnauthorized: false // Allows self-signed certificates
  }
});

async function initializeSchema() {
  const client = await pool.connect();
  try {
    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        cognito_user_id VARCHAR(255) UNIQUE NOT NULL,
        stripe_customer_id VARCHAR(255),
        plan VARCHAR(50) DEFAULT 'free',
        CONSTRAINT unique_stripe_customer_id UNIQUE (stripe_customer_id)
      );
    `);

    // Projects table
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    // Stripe events table (fixed: removed TELEPATHY)
    await client.query(`
      CREATE TABLE IF NOT EXISTS stripe_events (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(255) NOT NULL,
        event_data JSONB NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Config table for storing webhook secret
    await client.query(`
      CREATE TABLE IF NOT EXISTS config (
        key VARCHAR(255) PRIMARY KEY,
        stripe_webhook_secret VARCHAR(255) NOT NULL
      );
    `);

    console.log('Database schema initialized successfully');
  } catch (error) {
    console.error('Error initializing schema:', error);
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { pool, initializeSchema };