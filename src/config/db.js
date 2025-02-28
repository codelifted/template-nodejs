const { Pool } = require('pg');

// Database configuration from environment variables (from main-db-creds secret)
const pool = new Pool({
  user: process.env.main_db_USERNAME,
  host: process.env.main_db_HOST,
  database: process.env.main_db_DATABASE,
  password: process.env.main_db_PASSWORD,
  port: process.env.main_db_PORT,
});

module.exports = pool;