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
    // Users table with Stripe-related fields
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        cognito_user_id VARCHAR(255) UNIQUE NOT NULL,
        stripe_customer_id VARCHAR(255),
        plan VARCHAR(50) DEFAULT 'free',
        CONSTRAINT unique_stripe_customer_id UNIQUE (stripe_customer_id)
      );
    `);

    // Projects table (unchanged)
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    // Stripe events table for webhook event logging
    await client.query(`
      CREATE TABLE IF NOT EXISTS stripe_events (
        id SERIAL PRIMARY KEY,
        event_type VARCHAR(255) NOT NULL,
        event_data JSONB NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('Database schema initialized successfully');
  } catch (error) {
    console.error('Error initializing schema:', error);
    throw error; // Re-throw to halt startup if schema creation fails
  } finally {
    client.release();
  }
}

module.exports = { pool, initializeSchema };