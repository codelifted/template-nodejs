const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.main_HOST,
  port: process.env.main_PORT,
  database: process.env.main_DATABASE,
  user: process.env.main_USERNAME,
  password: process.env.main_PASSWORD,
});

async function initializeSchema() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        cognito_user_id VARCHAR(255) UNIQUE NOT NULL
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE
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