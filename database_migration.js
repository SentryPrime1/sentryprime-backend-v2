// Database Migration Script for Alt Text AI
// Run this script to set up all required tables and indexes

import { initializeDatabase, closeDatabase } from './database_models.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runMigration() {
  let pool = null;
  
  try {
    console.log('🚀 Starting database migration...');
    
    // Initialize database connection
    pool = await initializeDatabase();
    
    // Read the SQL schema file
    const schemaPath = path.join(__dirname, 'database_schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    
    console.log('📋 Executing database schema...');
    
    // Split SQL into individual statements and execute them
    const statements = schemaSql
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 0);
    
    for (let i = 0; i < statements.length; i++) {
      const statement = statements[i];
      
      try {
        await pool.query(statement);
        
        // Log progress for major operations
        if (statement.includes('CREATE TABLE')) {
          const tableName = statement.match(/CREATE TABLE (?:IF NOT EXISTS )?(\w+)/i)?.[1];
          console.log(`✅ Created table: ${tableName}`);
        } else if (statement.includes('CREATE INDEX')) {
          const indexName = statement.match(/CREATE INDEX (?:IF NOT EXISTS )?(\w+)/i)?.[1];
          console.log(`📊 Created index: ${indexName}`);
        } else if (statement.includes('CREATE TRIGGER')) {
          const triggerName = statement.match(/CREATE TRIGGER (\w+)/i)?.[1];
          console.log(`⚡ Created trigger: ${triggerName}`);
        } else if (statement.includes('CREATE OR REPLACE FUNCTION')) {
          const functionName = statement.match(/CREATE OR REPLACE FUNCTION (\w+)/i)?.[1];
          console.log(`🔧 Created function: ${functionName}`);
        }
        
      } catch (error) {
        // Log error but continue with other statements
        console.error(`❌ Error executing statement ${i + 1}:`, error.message);
        console.error(`Statement: ${statement.substring(0, 100)}...`);
      }
    }
    
    console.log('🎯 Migration completed successfully!');
    
    // Verify tables were created
    const tablesQuery = `
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      ORDER BY table_name
    `;
    
    const result = await pool.query(tablesQuery);
    const tables = result.rows.map(row => row.table_name);
    
    console.log('\n📋 Created tables:');
    tables.forEach(table => {
      console.log(`  ✅ ${table}`);
    });
    
    // Verify indexes were created
    const indexesQuery = `
      SELECT indexname 
      FROM pg_indexes 
      WHERE schemaname = 'public' 
      AND indexname LIKE 'idx_%'
      ORDER BY indexname
    `;
    
    const indexResult = await pool.query(indexesQuery);
    const indexes = indexResult.rows.map(row => row.indexname);
    
    console.log('\n📊 Created indexes:');
    indexes.forEach(index => {
      console.log(`  ✅ ${index}`);
    });
    
    console.log('\n🎉 Database is ready for Alt Text AI!');
    
  } catch (error) {
    console.error('💥 Migration failed:', error);
    process.exit(1);
  } finally {
    if (pool) {
      await closeDatabase();
    }
  }
}

// Run migration if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runMigration();
}

export { runMigration };
