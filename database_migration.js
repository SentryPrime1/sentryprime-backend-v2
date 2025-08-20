// Database Migration Script for Alt Text AI
// Run this script to set up all required tables and indexes

import { getPool, initializeDatabase, closeDatabase } from './database_connector.js';
import fs from 'fs/promises';
import path from 'path';

// Main migration function
export async function runMigration() {
  console.log('🚀 Starting database migration...');
  
  // Ensure the database is initialized before proceeding
  initializeDatabase();
  const pool = getPool();
  const client = await pool.connect();
  
  console.log('📋 Executing database schema...');

  try {
    // Resolve path from the root of the project
    const schemaPath = path.resolve(process.cwd(), 'database_schema.sql');
    const schemaSql = await fs.readFile(schemaPath, 'utf-8');
    
    // The schema file should be transactional, so we wrap it in BEGIN/COMMIT
    await client.query('BEGIN');
    await client.query(schemaSql);
    await client.query('COMMIT');
    
    console.log('✅ Database migration completed successfully.');
    
    // Optional: Verify tables were created
    const verificationResult = await client.query(`
      SELECT table_name FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_name IN 
      ('users', 'websites', 'scans', 'alt_text_jobs', 'alt_text_suggestions', 'image_cache', 'api_usage', 'user_settings');
    `);
    
    console.log(`✅ Verified ${verificationResult.rowCount} tables created.`);

  } catch (error) {
    // If any part of the migration fails, roll back the entire transaction
    await client.query('ROLLBACK');
    console.error('❌ Migration failed, transaction rolled back:', error);
    throw error; // Re-throw the error to indicate failure
  } finally {
    // Always release the client back to the pool
    client.release();
  }
}

// This allows running the script directly from the command line, e.g., `node database_migration.js`
// It checks if the script is the main module being run.
const isDirectRun = import.meta.url.endsWith(process.argv[1]);

if (isDirectRun) {
  (async () => {
    try {
      await runMigration();
    } catch (e) {
      console.error("💥 Standalone migration run failed.");
    } finally {
      await closeDatabase();
    }
  })();
}
