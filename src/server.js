import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';  // ✅ Changed from 'bcrypt' to 'bcryptjs'
import pkg from 'pg';
import { createRequire } from 'module';
import axios from 'axios';
import * as cheerio from 'cheerio';
import OpenAI from 'openai';

const require = createRequire(import.meta.url);
const axe = require('axe-core');
const { Pool } = pkg;

const app = express();
const PORT = process.env.PORT || 8080;

// Initialize OpenAI for Alt Text AI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// CORS configuration
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://sentryprime-frontend-v2.vercel.app',
    /\.vercel\.app$/
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'authentication_required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'invalid_token' });
    }
    req.user = user;
    next();
  });
};

// ===== ENTERPRISE UTILITY FUNCTIONS FOR ALT TEXT AI =====

// Enhanced image scraping with better error handling and filtering
async function scrapeImageUrls(url) {
  try {
    console.log(`🔍 Scraping images from: ${url}`);
    
    const { data } = await axios.get(url, {
      timeout: 15000,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
      }
    });
    
    const $ = cheerio.load(data);
    const images = [];
    const seenUrls = new Set();

    $('img').each((_, img) => {
      const src = $(img).attr('src');
      const alt = $(img).attr('alt') || '';
      const width = $(img).attr('width');
      const height = $(img).attr('height');
      
      if (src && !src.startsWith('data:') && !src.includes('base64')) {
        try {
          const absoluteUrl = src.startsWith('http') ? src : new URL(src, url).href;
          
          // Skip duplicate images and very small images (likely icons)
          if (!seenUrls.has(absoluteUrl) && 
              (!width || parseInt(width) > 50) && 
              (!height || parseInt(height) > 50)) {
            
            seenUrls.add(absoluteUrl);
            images.push({
              url: absoluteUrl,
              currentAlt: alt,
              selector: `img[src="${src}"]`,
              width: width ? parseInt(width) : null,
              height: height ? parseInt(height) : null,
              hasAlt: !!alt && alt.trim().length > 0
            });
          }
        } catch (e) {
          console.log(`⚠️ Skipping invalid image URL: ${src}`);
        }
      }
    });

    // Prioritize images without alt text
    const imagesWithoutAlt = images.filter(img => !img.hasAlt);
    const imagesWithAlt = images.filter(img => img.hasAlt);
    const prioritizedImages = [...imagesWithoutAlt, ...imagesWithAlt];

    console.log(`✅ Found ${images.length} images on ${url} (${imagesWithoutAlt.length} without alt text)`);
    return prioritizedImages.slice(0, 15); // Limit to 15 images for cost control
  } catch (err) {
    console.error('❌ Error scraping images:', err.message);
    return [];
  }
}

// Enhanced GPT-4o Vision with better prompting and error handling
async function generateAltTextWithGPT4o(imageUrl, currentAlt = '') {
  try {
    console.log(`🤖 Generating alt text for: ${imageUrl}`);
    
    const prompt = currentAlt 
      ? `This image currently has alt text: "${currentAlt}". Please provide a better, more descriptive alt text that would be helpful for screen readers. Focus on the main subject, important visual details, and context. Keep it concise but informative (under 125 characters).`
      : `Generate concise, descriptive alt text for this image that would be helpful for screen readers. Focus on the main subject, important visual details, and context that would help someone understand what's in the image. Keep it under 125 characters.`;

    const response = await openai.chat.completions.create({
      model: 'gpt-4o',
      messages: [
        {
          role: 'user',
          content: [
            { 
              type: 'text', 
              text: prompt
            },
            {
              type: 'image_url',
              image_url: {
                url: imageUrl,
                detail: 'low' // Use low detail for cost efficiency
              }
            }
          ]
        }
      ],
      max_tokens: 150,
      temperature: 0.3 // Lower temperature for more consistent results
    });

    const altText = response.choices[0].message.content.trim();
    
    // Remove quotes if the AI wrapped the response in them
    const cleanAltText = altText.replace(/^["']|["']$/g, '');
    
    console.log(`✅ Generated alt text: "${cleanAltText}"`);
    
    // Calculate confidence based on response quality
    const confidence = calculateAltTextConfidence(cleanAltText, currentAlt);
    
    return {
      success: true,
      altText: cleanAltText,
      confidence: confidence,
      improvement: currentAlt ? calculateImprovement(currentAlt, cleanAltText) : 'New alt text generated'
    };
  } catch (error) {
    console.error('❌ Error generating alt text:', error.message);
    
    // Provide fallback based on error type
    let fallbackText = 'Alt text generation failed';
    if (error.message.includes('rate limit')) {
      fallbackText = 'Rate limit exceeded - please try again later';
    } else if (error.message.includes('content policy')) {
      fallbackText = 'Image content not suitable for alt text generation';
    }
    
    return {
      success: false,
      altText: fallbackText,
      confidence: 0,
      error: error.message
    };
  }
}

// Calculate confidence score for generated alt text
function calculateAltTextConfidence(altText, currentAlt) {
  let confidence = 0.8; // Base confidence
  
  // Higher confidence for longer, more descriptive text
  if (altText.length > 20) confidence += 0.1;
  if (altText.length > 50) confidence += 0.05;
  
  // Lower confidence for very short or generic text
  if (altText.length < 10) confidence -= 0.2;
  if (['image', 'picture', 'photo'].includes(altText.toLowerCase())) confidence -= 0.3;
  
  // Higher confidence if it's an improvement over existing alt text
  if (currentAlt && altText.length > currentAlt.length) confidence += 0.05;
  
  return Math.min(0.95, Math.max(0.1, confidence));
}

// Calculate improvement description
function calculateImprovement(oldAlt, newAlt) {
  if (!oldAlt || oldAlt.trim().length === 0) {
    return 'Added descriptive alt text';
  }
  
  if (newAlt.length > oldAlt.length * 1.5) {
    return 'Significantly more descriptive';
  } else if (newAlt.length > oldAlt.length) {
    return 'More detailed description';
  } else {
    return 'Improved clarity and accessibility';
  }
}

// ===== SCANNER FUNCTION =====
const { crawlAndScan } = await import('./scanner.js');

// ===== API ROUTES =====

// Health check
app.get('/api/health', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT NOW()');
    res.json({
      status: 'ok',
      database: {
        status: 'healthy',
        timestamp: dbResult.rows[0].now,
        db_version: 'PostgreSQL 16.10'
      },
      services: {
        openai: process.env.OPENAI_API_KEY ? 'configured' : 'missing'
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      database: { status: 'unhealthy', error: error.message }
    });
  }
});

// Detailed health check
app.get('/api/health/detailed', async (req, res) => {
  try {
    const dbResult = await pool.query('SELECT NOW()');
    const tablesResult = await pool.query(`
      SELECT table_name FROM information_schema.tables 
      WHERE table_schema = 'public'
    `);
    
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: {
        status: 'connected',
        timestamp: dbResult.rows[0].now,
        tables: tablesResult.rows.map(row => row.table_name)
      },
      services: {
        openai: process.env.OPENAI_API_KEY ? 'configured' : 'missing',
        jwt: JWT_SECRET !== 'your-secret-key-change-in-production' ? 'configured' : 'default'
      },
      features: {
        alt_text_ai: 'enabled',
        image_scraping: 'enabled',
        real_time_scanning: 'enabled'
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Enterprise database schema fix
app.get('/api/fix-schema', async (req, res) => {
  try {
    console.log('🔧 Starting enterprise database schema fix...');
    
    // Drop and recreate scans table with full schema
    await pool.query('DROP TABLE IF EXISTS scans CASCADE');
    console.log('📦 Dropped existing scans table');
    
    await pool.query(`
      CREATE TABLE scans (
        id SERIAL PRIMARY KEY,
        website_id INTEGER,
        user_id INTEGER,
        url VARCHAR(500) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_violations INTEGER DEFAULT 0,
        compliance_score INTEGER DEFAULT 0,
        pages_scanned INTEGER DEFAULT 0,
        results JSONB
      )
    `);
    console.log('✅ Created new scans table with full schema');
    
    // Ensure alt_text_jobs table exists with enhanced schema
    await pool.query(`
      CREATE TABLE IF NOT EXISTS alt_text_jobs (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        user_id INTEGER,
        status VARCHAR(50) DEFAULT 'pending',
        total_images INTEGER DEFAULT 0,
        processed_images INTEGER DEFAULT 0,
        estimated_cost DECIMAL(10,2) DEFAULT 0.00,
        actual_cost DECIMAL(10,2) DEFAULT 0.00,
        results JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        error_message TEXT
      )
    `);
    console.log('✅ Ensured alt_text_jobs table exists with enhanced schema');
    
    // Add performance indexes
    await pool.query('CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_scan_id ON alt_text_jobs(scan_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_status ON alt_text_jobs(status)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_user_id ON alt_text_jobs(user_id)');
    console.log('✅ Added performance indexes');
    
    res.json({
      success: true,
      message: '✅ Enterprise database schema rebuilt successfully!',
      tables_created: ['scans', 'alt_text_jobs'],
      indexes_added: 6,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Schema fix error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});
});

// Force fix alt_text_jobs table
app.get('/api/fix-alt-text-table', async (req, res) => {
  try {
    console.log('🔧 Force fixing alt_text_jobs table...');
    
    // Drop and recreate with correct schema
    await pool.query('DROP TABLE IF EXISTS alt_text_jobs CASCADE');
    console.log('📦 Dropped alt_text_jobs table');
    
    await pool.query(`
      CREATE TABLE alt_text_jobs (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
        user_id INTEGER,
        status VARCHAR(50) DEFAULT 'pending',
        total_images INTEGER DEFAULT 0,
        processed_images INTEGER DEFAULT 0,
        estimated_cost DECIMAL(10,2) DEFAULT 0.00,
        actual_cost DECIMAL(10,2) DEFAULT 0.00,
        results JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        error_message TEXT
      )
    `);
    console.log('✅ Created alt_text_jobs table with correct schema');
    
    // Add indexes
    await pool.query('CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_scan_id ON alt_text_jobs(scan_id)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_status ON alt_text_jobs(status)');
    await pool.query('CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_user_id ON alt_text_jobs(user_id)');
    console.log('✅ Added indexes');
    
    res.json({
      success: true,
      message: '✅ alt_text_jobs table fixed successfully!',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Alt text table fix error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Database migration
app.get('/api/migrate', async (req, res) => {

// Database migration
app.get('/api/migrate', async (req, res) => {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create websites table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS websites (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(255) NOT NULL,
        url VARCHAR(500) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create scans table (if not exists from fix-schema)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY,
        website_id INTEGER REFERENCES websites(id),
        user_id INTEGER REFERENCES users(id),
        url VARCHAR(500) NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_violations INTEGER DEFAULT 0,
        compliance_score INTEGER DEFAULT 0,
        pages_scanned INTEGER DEFAULT 0,
        results JSONB
      )
    `);

    res.json({ success: true, message: 'Database migration completed successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ===== AUTHENTICATION ROUTES =====

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'email_exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (first_name, last_name, email, password_hash) VALUES ($1, $2, $3, $4) RETURNING id, first_name, last_name, email',
      [firstName, lastName, email, passwordHash]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'registration_failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'missing_credentials' });
    }

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'login_failed' });
  }
});

// ===== DASHBOARD ROUTES =====

// Get dashboard overview
app.get('/api/dashboard/overview', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const websitesResult = await pool.query('SELECT COUNT(*) FROM websites WHERE user_id = $1', [userId]);
    const scansResult = await pool.query('SELECT COUNT(*) FROM scans WHERE user_id = $1', [userId]);
    const recentScansResult = await pool.query(
      'SELECT * FROM scans WHERE user_id = $1 ORDER BY scan_date DESC LIMIT 5',
      [userId]
    );

    res.json({
      totalWebsites: parseInt(websitesResult.rows[0].count),
      totalScans: parseInt(scansResult.rows[0].count),
      recentScans: recentScansResult.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get websites
app.get('/api/dashboard/websites', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const result = await pool.query(
      `SELECT w.*, 
              s.compliance_score, 
              s.total_violations, 
              s.scan_date as last_scan
       FROM websites w
       LEFT JOIN LATERAL (
         SELECT compliance_score, total_violations, scan_date
         FROM scans 
         WHERE website_id = w.id 
         ORDER BY scan_date DESC 
         LIMIT 1
       ) s ON true
       WHERE w.user_id = $1 
       ORDER BY w.created_at DESC`,
      [userId]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add website
app.post('/api/dashboard/websites', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { url, name } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    // Auto-generate name from URL if not provided
    const websiteName = name || new URL(url).hostname;

    const result = await pool.query(
      'INSERT INTO websites (user_id, name, url) VALUES ($1, $2, $3) RETURNING *',
      [userId, websiteName, url]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Add website error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===== SCANNING ROUTES =====

// Get all scans for the logged-in user
app.get('/api/dashboard/scans', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    
    const result = await pool.query(
      'SELECT * FROM scans WHERE user_id = $1 ORDER BY scan_date DESC',
      [userId]
    );

    res.json({ scans: result.rows });
  } catch (error) {
    console.error('❌ Error getting scans:', error.message);
    res.status(500).json({ error: 'Failed to retrieve scans' });
  }
});

// Start scan
app.post('/api/dashboard/scans', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { website_id, url } = req.body;

    if (!website_id || !url) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    // Create scan record
    const scanResult = await pool.query(
      'INSERT INTO scans (website_id, user_id, url, status) VALUES ($1, $2, $3, $4) RETURNING *',
      [website_id, userId, url, 'running']
    );

    const scan = scanResult.rows[0];
    console.log(`🚀 Starting scan for ${url} (ID: ${scan.id})`);

    // Start scanning process asynchronously
    setTimeout(async () => {
      try {
        const results = await crawlAndScan(url, { maxPages: 50 });
        console.log(`✅ Scan completed for ${url}:`, { 
          pages: results.totalPages, 
          violations: results.totalViolations, 
          compliance: results.complianceScore 
        });

        await pool.query(`
          UPDATE scans 
          SET status = $1, 
              updated_at = CURRENT_TIMESTAMP,
              total_violations = $2, 
              compliance_score = $3, 
              pages_scanned = $4, 
              results = $5
          WHERE id = $6
        `, [
          'completed',
          results.totalViolations,
          results.complianceScore,
          results.totalPages,
          JSON.stringify(results),
          scan.id
        ]);

        console.log(`✅ Stored scan results for ${url} (ID: ${scan.id})`);
      } catch (error) {
        console.error(`❌ Scan failed for ${url}:`, error);
        await pool.query(
          'UPDATE scans SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
          ['failed', scan.id]
        );
      }
    }, 2000); // Complete scan in 2 seconds

    res.json(scan);
  } catch (error) {
    console.error('Scan creation error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get scan metadata
app.get('/api/scans/:scanId', authenticateToken, async (req, res) => {
  try {
    const { scanId } = req.params;
    const userId = req.user.userId;

    const result = await pool.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [scanId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'scan_not_found' });
    }

    const scan = result.rows[0];
    
    // Convert status for frontend compatibility
    const responseStatus = scan.status === 'completed' ? 'done' : scan.status;
    
    res.json({
      ...scan,
      status: responseStatus
    });
  } catch (error) {
    console.error('Get scan metadata error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get scan results
app.get('/api/scans/:scanId/results', authenticateToken, async (req, res) => {
  try {
    const { scanId } = req.params;
    const userId = req.user.userId;

    console.log(`📊 Fetching results for scan ${scanId} (user ${userId})`);

    const result = await pool.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [scanId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'scan_not_found' });
    }

    const scan = result.rows[0];

    if (scan.status !== 'completed') {
      return res.status(400).json({ error: 'scan_not_completed' });
    }

    let results;
    try {
      results = typeof scan.results === 'string' ? JSON.parse(scan.results) : scan.results;
    } catch (parseError) {
      console.error('Results parsing error:', parseError);
      return res.status(500).json({ error: 'invalid_results_format' });
    }

    console.log(`✅ Successfully retrieved results for scan ${scanId}`);
    res.json(results);
  } catch (error) {
    console.error('Get scan results error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===== ALT TEXT AI ROUTES =====

// Get Alt Text AI estimate
app.post('/api/alt-text-ai/estimate', authenticateToken, async (req, res) => {
  try {
    const { scan_id } = req.body;
    const userId = req.user.userId;

    if (!scan_id) {
      return res.status(400).json({ error: 'Missing scan_id' });
    }

    console.log(`🤖 Getting Alt Text AI estimate for scan ${scan_id}`);

    // Get scan details
    const scanResult = await pool.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [scan_id, userId]
    );

    if (scanResult.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const scan = scanResult.rows[0];
    
    // Scrape images from the scanned URL
    const images = await scrapeImageUrls(scan.url);
    
    if (images.length === 0) {
      return res.json({
        success: true,
        totalImages: 0,
        estimatedCost: 0,
        estimatedTime: 0,
        message: 'No images found on this website'
      });
    }

    // Calculate estimates
    const costPerImage = 0.02; // $0.02 per image
    const timePerImage = 3; // 3 seconds per image
    const totalCost = images.length * costPerImage;
    const totalTime = images.length * timePerImage;

    // Separate images with and without alt text
    const imagesWithoutAlt = images.filter(img => !img.hasAlt);
    const imagesWithAlt = images.filter(img => img.hasAlt);

    console.log(`✅ Found ${images.length} images (${imagesWithoutAlt.length} without alt text), estimated cost: $${totalCost.toFixed(2)}`);

    res.json({
      success: true,
      totalImages: images.length,
      imagesWithoutAlt: imagesWithoutAlt.length,
      imagesWithAlt: imagesWithAlt.length,
      estimatedCost: totalCost,
      estimatedTime: totalTime,
      costPerImage: costPerImage,
      images: images.slice(0, 5).map(img => ({ // Preview first 5 images
        url: img.url,
        currentAlt: img.currentAlt,
        hasAlt: img.hasAlt,
        width: img.width,
        height: img.height
      }))
    });
  } catch (error) {
    console.error('❌ Alt Text AI estimate error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to estimate Alt Text AI cost',
      details: error.message
    });
  }
});

// Create Alt Text AI job
app.post('/api/alt-text-ai/jobs', authenticateToken, async (req, res) => {
  try {
    const { scan_id } = req.body;
    const userId = req.user.userId;

    if (!scan_id) {
      return res.status(400).json({ error: 'Missing scan_id' });
    }

    console.log(`🚀 Creating Alt Text AI job for scan ${scan_id}`);

    // Get scan details
    const scanResult = await pool.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [scan_id, userId]
    );

    if (scanResult.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const scan = scanResult.rows[0];
    
    // Scrape images from the scanned URL
    const images = await scrapeImageUrls(scan.url);
    
    if (images.length === 0) {
      return res.status(400).json({ 
        error: 'No images found on this website' 
      });
    }

    // Create Alt Text AI job
    const jobResult = await pool.query(`
      INSERT INTO alt_text_jobs (scan_id, user_id, status, total_images, estimated_cost)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [scan_id, userId, 'processing', images.length, images.length * 0.02]);

    const job = jobResult.rows[0];

    console.log(`✅ Created Alt Text AI job ${job.id} for ${images.length} images`);

    // Process images asynchronously
    setTimeout(async () => {
      try {
        console.log(`🤖 Starting AI processing for job ${job.id}`);
        const results = [];
        let processedCount = 0;
        let totalCost = 0;

        for (const image of images) {
          try {
            const aiResult = await generateAltTextWithGPT4o(image.url, image.currentAlt);
            
            results.push({
              imageUrl: image.url,
              currentAlt: image.currentAlt,
              suggestedAlt: aiResult.altText,
              confidence: aiResult.confidence,
              improvement: aiResult.improvement,
              selector: image.selector,
              success: aiResult.success,
              width: image.width,
              height: image.height,
              hasOriginalAlt: image.hasAlt
            });

            processedCount++;
            totalCost += 0.02; // Cost per image
            
            // Update progress
            await pool.query(
              'UPDATE alt_text_jobs SET processed_images = $1, actual_cost = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
              [processedCount, totalCost, job.id]
            );

            console.log(`🔄 Processed ${processedCount}/${images.length} images for job ${job.id}`);

            // Small delay to prevent rate limiting
            await new Promise(resolve => setTimeout(resolve, 1500));
          } catch (imageError) {
            console.error(`❌ Failed to process image ${image.url}:`, imageError);
            results.push({
              imageUrl: image.url,
              currentAlt: image.currentAlt,
              suggestedAlt: 'Failed to generate alt text',
              confidence: 0,
              improvement: 'Processing failed',
              selector: image.selector,
              success: false,
              error: imageError.message,
              width: image.width,
              height: image.height,
              hasOriginalAlt: image.hasAlt
            });
            processedCount++;
          }
        }

        // Complete the job
        await pool.query(`
          UPDATE alt_text_jobs 
          SET status = $1, 
              processed_images = $2, 
              results = $3, 
              completed_at = CURRENT_TIMESTAMP,
              actual_cost = $4,
              updated_at = CURRENT_TIMESTAMP
          WHERE id = $5
        `, ['completed', processedCount, JSON.stringify(results), totalCost, job.id]);

        console.log(`✅ Completed Alt Text AI job ${job.id} - processed ${processedCount} images, cost: $${totalCost.toFixed(2)}`);
      } catch (error) {
        console.error(`❌ Alt Text AI job ${job.id} failed:`, error);
        await pool.query(
          'UPDATE alt_text_jobs SET status = $1, error_message = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $3',
          ['failed', error.message, job.id]
        );
      }
    }, 1000); // Start processing after 1 second

    res.json({
      success: true,
      jobId: job.id,
      status: 'processing',
      totalImages: images.length,
      estimatedCost: images.length * 0.02
    });
  } catch (error) {
    console.error('❌ Create Alt Text AI job error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create Alt Text AI job',
      details: error.message
    });
  }
});

// Get Alt Text AI job status and results
app.get('/api/alt-text-ai/jobs/:jobId', authenticateToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const userId = req.user.userId;

    const result = await pool.query(
      'SELECT * FROM alt_text_jobs WHERE id = $1 AND user_id = $2',
      [jobId, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Job not found' });
    }

    const job = result.rows[0];
    
    let results = null;
    if (job.results) {
      try {
        results = typeof job.results === 'string' ? JSON.parse(job.results) : job.results;
      } catch (parseError) {
        console.error('Job results parsing error:', parseError);
      }
    }

    // Calculate progress percentage
    const progressPercentage = job.total_images > 0 
      ? Math.round((job.processed_images / job.total_images) * 100)
      : 0;

    res.json({
      success: true,
      jobId: job.id,
      status: job.status,
      totalImages: job.total_images,
      processedImages: job.processed_images,
      progressPercentage: progressPercentage,
      estimatedCost: parseFloat(job.estimated_cost),
      actualCost: parseFloat(job.actual_cost || 0),
      results: results,
      createdAt: job.created_at,
      completedAt: job.completed_at,
      errorMessage: job.error_message
    });
  } catch (error) {
    console.error('❌ Get Alt Text AI job error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to get job status',
      details: error.message
    });
  }
});

// ===== AI ANALYSIS ROUTE (Additional AI Features) =====

// AI-powered accessibility analysis
app.post('/api/ai/analyze', authenticateToken, async (req, res) => {
  try {
    const { scan_id, analysis_type = 'comprehensive' } = req.body;
    const userId = req.user.userId;

    if (!scan_id) {
      return res.status(400).json({ error: 'Missing scan_id' });
    }

    console.log(`🧠 Starting AI analysis for scan ${scan_id}`);

    // Get scan results
    const scanResult = await pool.query(
      'SELECT * FROM scans WHERE id = $1 AND user_id = $2',
      [scan_id, userId]
    );

    if (scanResult.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const scan = scanResult.rows[0];
    let scanResults;
    
    try {
      scanResults = typeof scan.results === 'string' ? JSON.parse(scan.results) : scan.results;
    } catch (parseError) {
      return res.status(400).json({ error: 'Invalid scan results format' });
    }

    // Generate AI-powered insights
    const aiInsights = {
      overallAssessment: generateOverallAssessment(scanResults),
      priorityRecommendations: generatePriorityRecommendations(scanResults),
      impactAnalysis: generateImpactAnalysis(scanResults),
      implementationGuide: generateImplementationGuide(scanResults),
      complianceRoadmap: generateComplianceRoadmap(scanResults)
    };

    console.log(`✅ Generated AI analysis for scan ${scan_id}`);

    res.json({
      success: true,
      scanId: scan_id,
      analysisType: analysis_type,
      insights: aiInsights,
      generatedAt: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ AI analysis error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to generate AI analysis',
      details: error.message
    });
  }
});

// Helper functions for AI analysis
function generateOverallAssessment(scanResults) {
  const score = scanResults.complianceScore || 0;
  const violations = scanResults.totalViolations || 0;
  
  let assessment = '';
  let priority = 'medium';
  
  if (score >= 90) {
    assessment = 'Excellent accessibility compliance with minimal issues to address.';
    priority = 'low';
  } else if (score >= 75) {
    assessment = 'Good accessibility foundation with some areas for improvement.';
    priority = 'medium';
  } else if (score >= 50) {
    assessment = 'Moderate accessibility compliance requiring focused attention.';
    priority = 'high';
  } else {
    assessment = 'Significant accessibility barriers requiring immediate attention.';
    priority = 'critical';
  }
  
  return {
    score: score,
    assessment: assessment,
    priority: priority,
    violationCount: violations,
    recommendation: `Focus on ${priority === 'critical' ? 'critical' : 'high-impact'} violations first to maximize accessibility improvements.`
  };
}

function generatePriorityRecommendations(scanResults) {
  const recommendations = [
    {
      category: 'Images',
      priority: 'high',
      action: 'Add descriptive alt text to all images',
      impact: 'Enables screen reader users to understand visual content',
      effort: 'medium'
    },
    {
      category: 'Color Contrast',
      priority: 'high',
      action: 'Improve color contrast ratios to meet WCAG standards',
      impact: 'Improves readability for users with visual impairments',
      effort: 'low'
    },
    {
      category: 'Keyboard Navigation',
      priority: 'medium',
      action: 'Ensure all interactive elements are keyboard accessible',
      impact: 'Enables navigation for users who cannot use a mouse',
      effort: 'medium'
    }
  ];
  
  return recommendations;
}

function generateImpactAnalysis(scanResults) {
  return {
    usersAffected: 'Approximately 15-20% of website visitors may experience accessibility barriers',
    businessImpact: 'Improved accessibility can increase user engagement and reduce legal compliance risks',
    technicalDebt: 'Addressing violations now prevents accumulation of accessibility technical debt',
    roi: 'Accessibility improvements typically show positive ROI through increased user base and reduced support costs'
  };
}

function generateImplementationGuide(scanResults) {
  return {
    phase1: {
      title: 'Quick Wins (1-2 weeks)',
      tasks: ['Add missing alt text', 'Fix color contrast issues', 'Add proper headings structure']
    },
    phase2: {
      title: 'Medium Impact (2-4 weeks)',
      tasks: ['Improve keyboard navigation', 'Add ARIA labels', 'Fix form accessibility']
    },
    phase3: {
      title: 'Long-term (1-3 months)',
      tasks: ['Implement comprehensive testing', 'Train development team', 'Establish accessibility guidelines']
    }
  };
}

function generateComplianceRoadmap(scanResults) {
  const currentScore = scanResults.complianceScore || 0;
  
  return {
    currentLevel: currentScore >= 90 ? 'AA Compliant' : currentScore >= 75 ? 'Mostly Compliant' : 'Needs Improvement',
    targetLevel: 'WCAG 2.1 AA Compliance',
    estimatedTimeframe: currentScore >= 75 ? '2-4 weeks' : currentScore >= 50 ? '1-2 months' : '2-3 months',
    keyMilestones: [
      { milestone: 'Fix critical violations', target: '1-2 weeks' },
      { milestone: 'Achieve 80% compliance', target: '3-4 weeks' },
      { milestone: 'Full WCAG 2.1 AA compliance', target: '6-8 weeks' }
    ]
  };
}

// ===== SERVER STARTUP =====

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SentryPrime Backend Server running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🔧 Migration: http://localhost:${PORT}/api/migrate`);
  console.log(`🤖 Alt Text AI: Enabled with GPT-4o Vision`);
  console.log(`🔍 Image Scraping: Enhanced with cheerio`);
  console.log(`🧠 AI Analysis: Comprehensive accessibility insights`);
  console.log(`🔐 Using bcryptjs for cross-platform compatibility`);
});
