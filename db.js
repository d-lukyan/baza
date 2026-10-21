const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://admin_1:p-SSw0RD@postgres_db:5432/baza_db'
});

pool.connect((err, client, release) => {
  if (err) {
    return console.error('[!] ERROR! PostgreSQL connection: ', err);
  }
  console.log('PostgreSQL connected successfully');
  release();
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};
