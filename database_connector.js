import pg from 'pg';

const { Pool } = pg;
let pool;

export function initializeDatabase() {
  if (pool) {
    return;
  }
  
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    throw new Error('DATABASE_URL environment variable is not set.');
  }

  pool = new Pool({
    connectionString: dbUrl,
    ssl: {
      rejectUnauthorized: false
    },
    max: 10, // Max number of clients in the pool
    idleTimeoutMillis: 30000, // How long a client is allowed to remain idle before being closed
    connectionTimeoutMillis: 2000, // How long to wait for a client to connect
  });

  pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client', err);
    process.exit(-1);
  });
}

export async function closeDatabase() {
  if (pool) {
    await pool.end();
    pool = null;
    console.log('Database pool has been closed.');
  }
}

export function getPool() {
  if (!pool) {
    initializeDatabase();
  }
  return pool;
}
