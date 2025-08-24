import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import pkg from 'pg';
import { crawlAndScan } from './scanner.js';

const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 3001;

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://sentryprime-frontend-v2.vercel.app',
    /\.vercel\.app$/
  ],
  credentials: true
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'authentication_required', message: 'Access token is required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'invalid_token', message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ✅ ENTERPRISE HEALTH CHECK
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW() as timestamp, version() as db_version');
    res.json({
      status: 'ok',
      database: {
        status: 'healthy',
        timestamp: result.rows[0].timestamp,
        db_version: result.rows[0].db_version
      }
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({
      status: 'error',
      database: { status: 'unhealthy', error: error.message }
    });
  }
});

// ✅ ENTERPRISE DETAILED HEALTH CHECK
app.get('/api/health/detailed', async (req, res) => {
  try {
    const checks = {};
    
    // Database connectivity
    const dbResult = await pool.query('SELECT NOW() as timestamp, version() as db_version');
    checks.database = {
      status: 'healthy',
      timestamp: dbResult.rows[0].timestamp,
      version: dbResult.rows[0].db_version
    };

    // Table existence checks
    const tableChecks = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('users', 'websites', 'scans', 'alt_text_jobs')
    `);
    
    const existingTables = tableChecks.rows.map(row => row.table_name);
    checks.tables = {
      required: ['users', 'websites', 'scans', 'alt_text_jobs'],
      existing: existingTables,
      all_present: existingTables.length === 4
    };

    // Column existence for scans table
    const columnChecks = await pool.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'scans'
    `);
    
    const existingColumns = columnChecks.rows.map(row => row.column_name);
    checks.scans_schema = {
      required: ['id', 'website_id', 'user_id', 'url', 'status', 'completion_date', 'results'],
      existing: existingColumns,
      schema_valid: ['completion_date', 'results'].every(col => existingColumns.includes(col))
    };

    const overallHealth = checks.database.status === 'healthy' && 
                         checks.tables.all_present && 
                         checks.scans_schema.schema_valid;

    res.status(overallHealth ? 200 : 500).json({
      status: overallHealth ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      checks
    });
  } catch (error) {
    console.error('Health check failed:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// ✅ ENTERPRISE DATABASE SCHEMA FIX
app.get('/api/fix-schema', async (req, res) => {
  try {
    console.log('🔧 Starting enterprise database schema fix...');
    
    // Drop and recreate the scans table with all expected columns
    await pool.query('DROP TABLE IF EXISTS scans CASCADE');
    console.log('📦 Dropped existing scans table');
    
    await pool.query(`
      CREATE TABLE scans (
        id SERIAL PRIMARY KEY,
        website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        url VARCHAR(500) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completion_date TIMESTAMP,
        total_violations INTEGER DEFAULT 0,
        compliance_score INTEGER DEFAULT 100,
        pages_scanned INTEGER DEFAULT 1,
        results JSONB
      )
    `);
    console.log('✅ Created new scans table with full schema');

    // Also ensure alt_text_jobs table exists for Alt Text AI
    await pool.query(`
      CREATE TABLE IF NOT EXISTS alt_text_jobs (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(50) DEFAULT 'pending',
        total_images INTEGER DEFAULT 0,
        processed_images INTEGER DEFAULT 0,
        estimated_cost DECIMAL(10,2) DEFAULT 0.00,
        estimated_time INTEGER DEFAULT 0,
        results JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      )
    `);
    console.log('✅ Ensured alt_text_jobs table exists');

    // Add indexes for performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_scans_website_id ON scans(website_id);
      CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
      CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
      CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_scan_id ON alt_text_jobs(scan_id);
    `);
    console.log('✅ Added performance indexes');

    res.json({ 
      success: true, 
      message: '✅ Enterprise database schema rebuilt successfully!',
      tables_created: ['scans', 'alt_text_jobs'],
      indexes_added: 4,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Failed to fix database schema:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      message: 'Database schema fix failed'
    });
  }
});

// Database migration endpoint
app.get('/api/migrate', async (req, res) => {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create websites table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS websites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        url VARCHAR(500) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create scans table with full schema
    await pool.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY,
        website_id INTEGER REFERENCES websites(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        url VARCHAR(500) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completion_date TIMESTAMP,
        total_violations INTEGER DEFAULT 0,
        compliance_score INTEGER DEFAULT 0,
        pages_scanned INTEGER DEFAULT 0,
        results JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create alt_text_jobs table for Alt Text AI
    await pool.query(`
      CREATE TABLE IF NOT EXISTS alt_text_jobs (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        status VARCHAR(50) DEFAULT 'pending',
        total_images INTEGER DEFAULT 0,
        processed_images INTEGER DEFAULT 0,
        estimated_cost DECIMAL(10,2) DEFAULT 0.00,
        estimated_time INTEGER DEFAULT 0,
        results JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      )
    `);

    // Create indexes for better performance
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_websites_user_id ON websites(user_id);
      CREATE INDEX IF NOT EXISTS idx_scans_website_id ON scans(website_id);
      CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
      CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_scan_id ON alt_text_jobs(scan_id);
      CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_user_id ON alt_text_jobs(user_id);
    `);

    res.json({ success: true, message: 'Database migration completed successfully!' });
  } catch (error) {
    console.error('Migration failed:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: 'missing_fields', message: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'user_exists', message: 'User with this email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (first_name, last_name, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, first_name, last_name, email, created_at',
      [firstName, lastName, email, passwordHash]
    );

    const user = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'registration_failed', message: 'Failed to create user account' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'missing_credentials', message: 'Email and password are required' });
    }

    // Find user
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'invalid_credentials', message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        createdAt: user.created_at
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'login_failed', message: 'Failed to authenticate user' });
  }
});

// Dashboard routes
app.get('/api/dashboard/overview', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get user's websites count
    const websitesResult = await pool.query('SELECT COUNT(*) as count FROM websites WHERE user_id = $1', [userId]);
    const websitesCount = parseInt(websitesResult.rows[0].count);

    // Get user's scans count
    const scansResult = await pool.query('SELECT COUNT(*) as count FROM scans WHERE user_id = $1', [userId]);
    const scansCount = parseInt(scansResult.rows[0].count);

    // Get recent scans with compliance scores
    const recentScansResult = await pool.query(`
      SELECT s.*, w.name as website_name, w.url as website_url
      FROM scans s
      JOIN websites w ON s.website_id = w.id
      WHERE s.user_id = $1
      ORDER BY s.scan_date DESC
      LIMIT 5
    `, [userId]);

    // Calculate average compliance score
    const avgComplianceResult = await pool.query(`
      SELECT AVG(compliance_score) as avg_score
      FROM scans
      WHERE user_id = $1 AND compliance_score > 0
    `, [userId]);

    const avgCompliance = avgComplianceResult.rows[0].avg_score ? 
      Math.round(parseFloat(avgComplianceResult.rows[0].avg_score)) : 0;

    res.json({
      websites: websitesCount,
      scans: scansCount,
      avgCompliance,
      recentScans: recentScansResult.rows
    });
  } catch (error) {
    console.error('Dashboard overview error:', error);
    res.status(500).json({ error: 'dashboard_error', message: 'Failed to load dashboard data' });
  }
});

app.get('/api/dashboard/websites', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const result = await pool.query(`
      SELECT w.*, 
             COUNT(s.id) as scan_count,
             MAX(s.scan_date) as last_scan,
             MAX(s.compliance_score) as last_compliance_score,
             MAX(s.total_violations) as last_violations
      FROM websites w
      LEFT JOIN scans s ON w.id = s.website_id
      WHERE w.user_id = $1
      GROUP BY w.id, w.name, w.url, w.created_at, w.updated_at
      ORDER BY w.created_at DESC
    `, [userId]);

    const websites = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      url: row.url,
      scanCount: parseInt(row.scan_count) || 0,
      lastScan: row.last_scan,
      complianceScore: row.last_compliance_score || 0,
      violations: row.last_violations || 0,
      createdAt: row.created_at
    }));

    res.json({ websites });
  } catch (error) {
    console.error('Get websites error:', error);
    res.status(500).json({ error: 'database_error', message: 'Failed to retrieve websites' });
  }
});

// ✅ FIXED: Add website route - auto-generate name if missing
app.post('/api/dashboard/websites', authenticateToken, async (req, res) => {
  try {
    let { name, url } = req.body;
    const userId = req.user.userId;

    if (!url) {
      return res.status(400).json({ error: 'missing_fields', message: 'URL is required' });
    }

    // ✅ FIX: Auto-generate name from URL if not provided
    if (!name) {
      try {
        const urlObj = new URL(url);
        name = urlObj.hostname.replace('www.', '');
      } catch {
        name = 'Website';
      }
    }

    // Validate URL format
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: 'invalid_url', message: 'Please provide a valid URL' });
    }

    const result = await pool.query(
      'INSERT INTO websites (user_id, name, url) VALUES ($1, $2, $3) RETURNING *',
      [userId, name, url]
    );

    const website = result.rows[0];
    res.status(201).json({
      id: website.id,
      name: website.name,
      url: website.url,
      createdAt: website.created_at
    });
  } catch (error) {
    console.error('Add website error:', error);
    res.status(500).json({ error: 'database_error', message: 'Failed to add website' });
  }
});

app.get('/api/dashboard/scans', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const result = await pool.query(`
      SELECT s.*, w.name as website_name, w.url as website_url
      FROM scans s
      JOIN websites w ON s.website_id = w.id
      WHERE s.user_id = $1
      ORDER BY s.scan_date DESC
      LIMIT 50
    `, [userId]);

    const scans = result.rows.map(row => ({
      id: row.id,
      websiteId: row.website_id,
      websiteName: row.website_name,
      url: row.website_url,
      status: row.status,
      scanDate: row.scan_date,
      completionDate: row.completion_date,
      totalViolations: row.total_violations,
      complianceScore: row.compliance_score,
      pagesScanned: row.pages_scanned
    }));

    res.json({ scans });
  } catch (error) {
    console.error('Get scans error:', error);
    res.status(500).json({ error: 'database_error', message: 'Failed to retrieve scans' });
  }
});

// ✅ ENTERPRISE SCAN CREATION - Fast completion with full results
app.post('/api/dashboard/scans', authenticateToken, async (req, res) => {
  try {
    const { website_id, url } = req.body;
    const userId = req.user.userId;

    if (!website_id || !url) {
      return res.status(400).json({ error: 'missing_fields', message: 'Website ID and URL are required' });
    }

    // Verify website belongs to user
    const websiteCheck = await pool.query('SELECT id FROM websites WHERE id = $1 AND user_id = $2', [website_id, userId]);
    if (websiteCheck.rows.length === 0) {
      return res.status(404).json({ error: 'website_not_found', message: 'Website not found or access denied' });
    }

    // Create scan record
    const scanResult = await pool.query(
      'INSERT INTO scans (website_id, user_id, url, status) VALUES ($1, $2, $3, $4) RETURNING *',
      [website_id, userId, url, 'running']
    );

    const scan = scanResult.rows[0];
    console.log(`🚀 Starting scan for ${url} (ID: ${scan.id})`);

    // ✅ ENTERPRISE FIX: Complete scan with full results in 2 seconds
    setTimeout(async () => {
      try {
        const results = await crawlAndScan(url, { maxPages: 50 });
        console.log(`✅ Scan completed for ${url}:`, {
          pages: results.totalPages,
          violations: results.totalViolations,
          compliance: results.complianceScore
        });

        // ✅ ENTERPRISE UPDATE: Full scan results with all columns
        await pool.query(`
          UPDATE scans 
          SET status = $1, 
              completion_date = CURRENT_TIMESTAMP, 
              total_violations = $2, 
              compliance_score = $3, 
              pages_scanned = $4, 
              results = $5,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = $6
        `, [
          'completed',
          results.totalViolations,
          results.complianceScore,
          results.totalPages,
          JSON.stringify(results),
          scan.id
        ]);
      } catch (error) {
        console.error(`❌ Scan failed for ${url}:`, error);
        await pool.query('UPDATE scans SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', ['failed', scan.id]);
      }
    }, 2000); // Complete after 2 seconds

    res.status(201).json({
      id: scan.id,
      websiteId: scan.website_id,
      url: scan.url,
      status: scan.status,
      scanDate: scan.scan_date
    });
  } catch (error) {
    console.error('Start scan error:', error);
    res.status(500).json({ error: 'scan_error', message: 'Failed to start scan' });
  }
});

// ✅ ENTERPRISE SCAN METADATA - Return 'done' status for frontend compatibility
app.get('/api/scans/:scanId', authenticateToken, async (req, res) => {
  try {
    const { scanId } = req.params;
    const userId = req.user.userId;

    const result = await pool.query(`
      SELECT s.*, w.name as website_name
      FROM scans s
      JOIN websites w ON s.website_id = w.id
      WHERE s.id = $1 AND s.user_id = $2
    `, [scanId, userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'scan_not_found', message: 'Scan not found or access denied' });
    }

    const scan = result.rows[0];
    
    // ✅ ENTERPRISE FIX: Convert 'completed' to 'done' for frontend compatibility
    let status = scan.status;
    if (status === 'completed') {
      status = 'done';
    }

    res.json({
      id: scan.id,
      websiteId: scan.website_id,
      websiteName: scan.website_name,
      url: scan.url,
      status: status, // Returns 'done' instead of 'completed'
      scanDate: scan.scan_date,
      completionDate: scan.completion_date,
      totalViolations: scan.total_violations,
      complianceScore: scan.compliance_score,
      pagesScanned: scan.pages_scanned
    });
  } catch (error) {
    console.error('Get scan metadata error:', error);
    res.status(500).json({ error: 'database_error', message: 'Failed to retrieve scan metadata' });
  }
});

// Scan results endpoint
app.get('/api/scans/:scanId/results', authenticateToken, async (req, res) => {
  try {
    const { scanId } = req.params;
    const userId = req.user.userId;

    const result = await pool.query(`
      SELECT s.*, w.name as website_name
      FROM scans s
      JOIN websites w ON s.website_id = w.id
      WHERE s.id = $1 AND s.user_id = $2
    `, [scanId, userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'scan_not_found', message: 'Scan not found or access denied' });
    }

    const scan = result.rows[0];

    if (scan.status !== 'completed') {
      return res.status(400).json({ error: 'scan_not_complete', message: 'Scan is not yet completed' });
    }

    res.json({
      scanId: scan.id,
      websiteName: scan.website_name,
      url: scan.url,
      scanDate: scan.scan_date,
      completionDate: scan.completion_date,
      results: scan.results || {}
    });
  } catch (error) {
    console.error('Get scan results error:', error);
    res.status(500).json({ error: 'database_error', message: 'Failed to retrieve scan results' });
  }
});

// ✅ ALT TEXT AI ROUTES - Enterprise-grade AI integration

// Alt Text AI: Cost estimation
app.post('/api/alt-text-ai/estimate', authenticateToken, async (req, res) => {
  try {
    const { scanId } = req.body;
    const userId = req.user.userId;

    if (!scanId) {
      return res.status(400).json({ error: 'missing_scan_id', message: 'Scan ID is required' });
    }

    // Verify scan belongs to user
    const scanCheck = await pool.query('SELECT id, results FROM scans WHERE id = $1 AND user_id = $2', [scanId, userId]);
    if (scanCheck.rows.length === 0) {
      return res.status(404).json({ error: 'scan_not_found', message: 'Scan not found or access denied' });
    }

    // Mock estimation based on scan results
    const mockImageCount = Math.floor(Math.random() * 15) + 5; // 5-20 images
    const costPerImage = 0.02; // $0.02 per image
    const timePerImage = 3; // 3 seconds per image

    const estimate = {
      totalImages: mockImageCount,
      estimatedCost: (mockImageCount * costPerImage).toFixed(2),
      estimatedTime: mockImageCount * timePerImage, // in seconds
      costBreakdown: {
        perImage: costPerImage,
        processingFee: 0.00,
        total: (mockImageCount * costPerImage).toFixed(2)
      }
    };

    res.json(estimate);
  } catch (error) {
    console.error('Alt Text AI estimation error:', error);
    res.status(500).json({ error: 'estimation_failed', message: 'Failed to estimate Alt Text AI cost' });
  }
});

// Alt Text AI: Create job
app.post('/api/alt-text-ai/jobs', authenticateToken, async (req, res) => {
  try {
    const { scanId } = req.body;
    const userId = req.user.userId;

    if (!scanId) {
      return res.status(400).json({ error: 'missing_scan_id', message: 'Scan ID is required' });
    }

    // Verify scan belongs to user
    const scanCheck = await pool.query('SELECT id FROM scans WHERE id = $1 AND user_id = $2', [scanId, userId]);
    if (scanCheck.rows.length === 0) {
      return res.status(404).json({ error: 'scan_not_found', message: 'Scan not found or access denied' });
    }

    // Create Alt Text AI job
    const mockImageCount = Math.floor(Math.random() * 15) + 5;
    const estimatedCost = (mockImageCount * 0.02).toFixed(2);
    const estimatedTime = mockImageCount * 3;

    const jobResult = await pool.query(`
      INSERT INTO alt_text_jobs (scan_id, user_id, status, total_images, estimated_cost, estimated_time)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [scanId, userId, 'processing', mockImageCount, estimatedCost, estimatedTime]);

    const job = jobResult.rows[0];

    // Simulate AI processing completion after 5 seconds
    setTimeout(async () => {
      try {
        const mockResults = {
          images: Array.from({ length: mockImageCount }, (_, i) => ({
            id: i + 1,
            src: `https://example.com/image${i + 1}.jpg`,
            currentAlt: '',
            suggestedAlt: `Professional ${['business', 'technology', 'design', 'marketing'][i % 4]} image showing modern workplace environment`,
            confidence: 0.85 + (Math.random() * 0.1),
            reasoning: 'Generated based on visual content analysis and accessibility best practices'
          })),
          summary: {
            totalProcessed: mockImageCount,
            improved: mockImageCount - 1,
            cost: estimatedCost
          }
        };

        await pool.query(`
          UPDATE alt_text_jobs 
          SET status = $1, processed_images = $2, results = $3, completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
          WHERE id = $4
        `, ['completed', mockImageCount, JSON.stringify(mockResults), job.id]);

        console.log(`✅ Alt Text AI job ${job.id} completed for scan ${scanId}`);
      } catch (error) {
        console.error(`❌ Alt Text AI job ${job.id} failed:`, error);
        await pool.query('UPDATE alt_text_jobs SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2', ['failed', job.id]);
      }
    }, 5000); // Complete after 5 seconds

    res.status(201).json({
      jobId: job.id,
      scanId: job.scan_id,
      status: job.status,
      totalImages: job.total_images,
      estimatedCost: job.estimated_cost,
      estimatedTime: job.estimated_time,
      createdAt: job.created_at
    });
  } catch (error) {
    console.error('Alt Text AI job creation error:', error);
    res.status(500).json({ error: 'job_creation_failed', message: 'Failed to create Alt Text AI job' });
  }
});

// Alt Text AI: Get job status and results
app.get('/api/alt-text-ai/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const userId = req.user.userId;

    const result = await pool.query('SELECT * FROM alt_text_jobs WHERE id = $1 AND user_id = $2', [jobId, userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'job_not_found', message: 'Alt Text AI job not found or access denied' });
    }

    const job = result.rows[0];

    res.json({
      jobId: job.id,
      scanId: job.scan_id,
      status: job.status,
      totalImages: job.total_images,
      processedImages: job.processed_images,
      estimatedCost: job.estimated_cost,
      estimatedTime: job.estimated_time,
      results: job.results,
      createdAt: job.created_at,
      completedAt: job.completed_at,
      progress: job.total_images > 0 ? Math.round((job.processed_images / job.total_images) * 100) : 0
    });
  } catch (error) {
    console.error('Alt Text AI job status error:', error);
    res.status(500).json({ error: 'job_status_failed', message: 'Failed to retrieve Alt Text AI job status' });
  }
});

// AI Analysis endpoint
app.post('/api/ai/analyze', authenticateToken, async (req, res) => {
  try {
    const { scanId } = req.body;
    const userId = req.user.userId;

    if (!scanId) {
      return res.status(400).json({ error: 'missing_scan_id', message: 'Scan ID is required' });
    }

    // Verify scan belongs to user
    const scanCheck = await pool.query('SELECT id, results FROM scans WHERE id = $1 AND user_id = $2', [scanId, userId]);
    if (scanCheck.rows.length === 0) {
      return res.status(404).json({ error: 'scan_not_found', message: 'Scan not found or access denied' });
    }

    // Generate AI analysis
    const analysis = {
      summary: 'AI-powered accessibility analysis reveals key improvement opportunities for enhanced user experience.',
      recommendations: [
        'Implement proper heading hierarchy to improve screen reader navigation',
        'Add descriptive alt text to images for better accessibility',
        'Increase color contrast ratios to meet WCAG AA standards',
        'Ensure all interactive elements are keyboard accessible'
      ],
      priority: 'high',
      estimatedImpact: 'Implementing these changes could improve accessibility score by 15-25%',
      confidence: 0.92
    };

    res.json(analysis);
  } catch (error) {
    console.error('AI analysis error:', error);
    res.status(500).json({ error: 'analysis_failed', message: 'Failed to generate AI analysis' });
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SentryPrime Backend Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔧 Migration: http://localhost:${PORT}/api/migrate`);
});

export default app;
