const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://admin_baza:3AX-pZbz_Yy_3-e9k2-rV9VS3-P_JZpsT-WM_b@localhost:5432/baza_db'
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
