import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import OpenAI from 'openai';
import { crawlAndScan } from './scanner.js';
// ✅ Database and security imports
import { initializeDatabase, closeDatabase, createDatabaseModels } from '../database_models.js';
import { runMigration } from '../database_migration.js';
import { 
  authenticateToken, 
  createRateLimit, 
  authRateLimit, 
  scanRateLimit,
  securityHeaders,
  errorHandler,
  corsConfig
} from '../auth_middleware.js';
// ✅ Alt Text AI routes import
import altTextAIRoutes, { initializeAltTextAIRoutes } from '../routes/altTextAIRoutes.js';

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';

// ✅ OpenAI client initialization
const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// ✅ Database initialization with proper error handling
let dbInitialized = false;
let db = null;

const initDB = async () => {
  try {
    console.log('🔄 Initializing database connection...');
    await initializeDatabase();
    db = createDatabaseModels();
    dbInitialized = true;
    console.log('✅ Database initialized successfully');
    
    // Initialize Alt Text AI routes with database
    initializeAltTextAIRoutes(db, {
      openai: {
        apiKey: OPENAI_API_KEY,
        model: OPENAI_MODEL
      },
      imageProcessing: {
        maxImageSize: 10 * 1024 * 1024, // 10MB
        maxDimensions: { width: 2048, height: 2048 }
      },
      notifications: {
        enableInApp: true,
        enableEmail: false, // Disable for now
        enableWebhooks: false // Disable for now
      }
    });
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    console.log('⚠️  Falling back to in-memory storage');
    dbInitialized = false;
    db = null;
  }
};

// Initialize database
initDB();

// --- Security Middleware ---
app.use(securityHeaders);
app.use(express.json({ limit: '2mb' }));
app.use(cors(corsConfig));

// General rate limiting
app.use(createRateLimit());

// --- In-memory Data Stores (fallback) ---
const users = new Map();
const websites = new Map();
const scans = new Map();

// --- Helper Functions ---
function signToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
}

// ✅ Migration endpoint with proper error handling
app.get('/api/migrate', async (req, res) => {
  try {
    console.log('🚀 Starting database migration via HTTP endpoint...');
    
    if (!dbInitialized) {
      await initDB();
    }
    
    if (!dbInitialized) {
      throw new Error('Database connection could not be established');
    }
    
    await runMigration();
    
    res.json({
      success: true,
      message: 'Database migration completed successfully!',
      timestamp: new Date().toISOString(),
      tables_created: [
        'users', 'websites', 'scans', 'alt_text_jobs',
        'alt_text_suggestions', 'image_cache', 'api_usage', 'user_settings'
      ]
    });
    
  } catch (error) {
    console.error('❌ Migration failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// ✅ Database health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    if (!dbInitialized || !db) {
      return res.json({
        status: 'ok',
        database: 'in-memory',
        timestamp: new Date().toISOString()
      });
    }

    const healthCheck = await db.healthCheck();
    
    res.json({
      status: 'ok',
      database: healthCheck,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// --- Authentication Routes ---
app.post('/api/auth/register', authRateLimit, async (req, res) => {
  const { firstName, lastName, email, password } = req.body || {};
  
  if (!firstName || !lastName || !email || !password) {
    return res.status(400).json({ error: 'missing_fields' });
  }
  
  try {
    // Check if user exists in database first
    if (dbInitialized && db) {
      const existingUser = await db.getUserByEmail(email);
      if (existingUser) {
        return res.status(409).json({ error: 'email_exists' });
      }
      
      // Create user in database
      const passwordHash = await bcrypt.hash(password, 12);
      const user = await db.createUser(email, passwordHash);
      
      const token = signToken(user.id);
      return res.status(201).json({ 
        token, 
        user: { 
          id: user.id, 
          firstName, 
          lastName, 
          email: user.email 
        } 
      });
    }
    
    // Fallback to in-memory storage
    const existingUser = [...users.values()].find(u => u.email === email);
    if (existingUser) {
      return res.status(409).json({ error: 'email_exists' });
    }
    
    const userId = uuid();
    const passwordHash = await bcrypt.hash(password, 10);
    
    const user = { id: userId, firstName, lastName, email, passwordHash };
    users.set(userId, user);
    
    const token = signToken(userId);
    return res.status(201).json({ token, user: { id: userId, firstName, lastName, email } });
    
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'registration_failed' });
  }
});

app.post('/api/auth/login', authRateLimit, async (req, res) => {
  const { email, password } = req.body || {};
  
  if (!email || !password) {
    return res.status(400).json({ error: 'missing_credentials' });
  }
  
  try {
    // Check database first
    if (dbInitialized && db) {
      const user = await db.getUserByEmail(email);
      if (!user) {
        return res.status(401).json({ error: 'invalid_credentials' });
      }
      
      const isValid = await bcrypt.compare(password, user.password_hash);
      if (!isValid) {
        return res.status(401).json({ error: 'invalid_credentials' });
      }
      
      const token = signToken(user.id);
      return res.status(200).json({ 
        token, 
        user: { 
          id: user.id, 
          firstName: user.firstName || 'User', 
          lastName: user.lastName || '', 
          email: user.email 
        } 
      });
    }
    
    // Fallback to in-memory storage
    const user = [...users.values()].find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    
    const token = signToken(user.id);
    return res.status(200).json({ token, user: { id: user.id, firstName: user.firstName, lastName: user.lastName, email: user.email } });
    
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'login_failed' });
  }
});

// --- Dashboard Routes ---
app.get('/api/dashboard/overview', authenticateToken, (req, res) => {
  const userWebsites = [...websites.values()].filter(w => w.userId === req.userId);
  const userScans = [...scans.values()].filter(s => s.userId === req.userId);
  
  const totalWebsites = userWebsites.length;
  const totalScans = userScans.length;
  const totalViolations = userScans.reduce((sum, scan) => sum + (scan.total_violations || 0), 0);
  const avgCompliance = userScans.length > 0 
    ? Math.round(userScans.reduce((sum, scan) => sum + (scan.compliance_score || 0), 0) / userScans.length)
    : 0;
  
  return res.json({
    totalWebsites,
    totalScans,
    totalViolations,
    avgCompliance
  });
});

app.get('/api/dashboard/websites', authenticateToken, (req, res) => {
  const userWebsites = [...websites.values()].filter(w => w.userId === req.userId);
  
  const websiteList = userWebsites.map(website => ({
    id: website.id,
    name: website.name,
    url: website.url,
    last_scan_id: website.last_scan_id || null,
    last_scan_date: website.last_scan_date || null,
    compliance_score: website.compliance_score || 0,
    total_violations: website.total_violations || 0
  }));
  
  return res.json({ websites: websiteList });
});

app.get('/api/dashboard/websites/:websiteId', authenticateToken, (req, res) => {
  const { websiteId } = req.params;
  const website = websites.get(websiteId);
  
  if (!website || website.userId !== req.userId) {
    return res.status(404).json({ error: 'website_not_found' });
  }
  
  return res.json(website);
});

app.post('/api/dashboard/websites', authenticateToken, (req, res) => {
  const { url, name } = req.body || {};
  
  if (!url) {
    return res.status(400).json({ error: 'url_required' });
  }
  
  const websiteId = uuid();
  const website = {
    id: websiteId,
    userId: req.userId,
    name: name || url,
    url,
    last_scan_date: null,
    compliance_score: 0,
    total_violations: 0,
    last_scan_id: null
  };
  
  websites.set(websiteId, website);
  return res.status(201).json(website);
});

// --- Scan Routes ---
app.route('/api/dashboard/scans')
  .get(authenticateToken, (req, res) => {
    const userScans = [...scans.values()]
      .filter(s => s.userId === req.userId)
      .filter(s => s.status === 'done')
      .sort((a, b) => new Date(b.scan_date) - new Date(a.scan_date));
    
    const scanSummaries = userScans.map(scan => ({
      id: scan.id,
      website_id: scan.website_id,
      website_name: scan.website_name,
      url: scan.url,
      scan_date: scan.scan_date,
      total_violations: scan.total_violations,
      compliance_score: scan.compliance_score,
      risk_level: scan.risk_level,
      pages_scanned: scan.pages_scanned,
      status: scan.status
    }));
    
    console.log(`Returning ${scanSummaries.length} completed scans for user ${req.userId}`);
    return res.json({ scans: scanSummaries });
  })
  .post(authenticateToken, scanRateLimit, async (req, res) => {
    const { website_id, url } = req.body || {};
    
    if (!website_id || !url) {
      return res.status(400).json({ error: 'website_id_and_url_required' });
    }
    
    const website = websites.get(website_id);
    if (!website || website.userId !== req.userId) {
      return res.status(404).json({ error: 'website_not_found' });
    }
    
    try {
      console.log(`Starting scan for user ${req.userId}, website ${website_id}: ${url}`);
      
      const scanId = uuid();
      const scan = {
        id: scanId,
        userId: req.userId,
        website_id,
        website_name: website.name,
        url,
        status: 'running',
        scan_date: new Date().toISOString(),
        total_violations: 0,
        compliance_score: 0,
        risk_level: 'Unknown',
        pages_scanned: 0,
        details: { pages: [] }
      };
      
      scans.set(scanId, scan);
      
      // Run scan asynchronously
      (async () => {
        try {
          const scanResult = await crawlAndScan(url, { maxPages: 50 });
          
          const processedPages = (scanResult.pages || []).map(page => ({
            url: page.url,
            violations: (page.violations || []).map(violation => ({
              id: violation.id,
              impact: violation.impact,
              description: violation.description,
              help: violation.help,
              helpUrl: violation.helpUrl,
              nodes: (violation.nodes || []).slice(0, 5).map(node => ({
                target: Array.isArray(node.target) ? node.target.join(' ') : node.target,
                failureSummary: node.failureSummary,
                html: typeof node.html === 'string' ? node.html.slice(0, 500) : ''
              }))
            }))
          }));
          
          const totalViolationCount = processedPages.reduce((total, page) => {
            return total + (page.violations ? page.violations.length : 0);
          }, 0);
          
          scan.status = 'done';
          scan.scan_date = scanResult.scannedAt || scan.scan_date;
          scan.total_violations = totalViolationCount;
          scan.compliance_score = scanResult.complianceScore || 0;
          scan.risk_level = scan.compliance_score < 70 ? 'High' : 
                           scan.compliance_score < 90 ? 'Moderate' : 'Low';
          scan.pages_scanned = scanResult.totalPages || processedPages.length;
          scan.details = { pages: processedPages };
          
          scans.set(scanId, scan);
          
          const websiteToUpdate = websites.get(website_id);
          if (websiteToUpdate) {
            websiteToUpdate.last_scan_id = scanId;
            websiteToUpdate.last_scan_date = scan.scan_date;
            websiteToUpdate.total_violations = totalViolationCount;
            websiteToUpdate.compliance_score = scan.compliance_score;
            websites.set(website_id, websiteToUpdate);
          }
          
          console.log(`Scan completed: ${totalViolationCount} violations, ${scan.compliance_score}% compliance, scan ID: ${scanId}`);
          
        } catch (error) {
          console.error('Scan failed:', error);
          scan.status = 'error';
          scans.set(scanId, scan);
        }
      })();
      
      return res.status(201).json(scan);
      
    } catch (error) {
      console.error('Scan creation failed:', error);
      return res.status(500).json({ 
        error: 'scan_failed', 
        details: error.message 
      });
    }
  });

app.get('/api/scans/:scanId', authenticateToken, (req, res) => {
  const { scanId } = req.params;
  const scan = scans.get(scanId);
  
  if (!scan || scan.userId !== req.userId) {
    return res.status(404).json({ error: 'scan_not_found' });
  }
  
  const scanMeta = {
    id: scan.id,
    website_id: scan.website_id,
    url: scan.url,
    scan_date: scan.scan_date || null,
    total_violations: scan.total_violations ?? 0,
    compliance_score: scan.compliance_score ?? 0,
    status: scan.status || 'running'
  };
  
  return res.json(scanMeta);
});

app.get('/api/scans/:scanId/results', authenticateToken, (req, res) => {
  const { scanId } = req.params;
  const scan = scans.get(scanId);

  if (!scan || scan.userId !== req.userId) {
    return res.status(404).json({ error: 'scan_not_found' });
  }

  if (scan.status !== 'done') {
    return res.status(202).json({ 
      status: scan.status, 
      message: 'scan_not_ready',
      details: 'Scan is still processing. Please wait and try again.'
    });
  }

  const result = {
    id: scan.id,
    url: scan.url,
    scan_date: scan.scan_date,
    total_violations: scan.total_violations,
    compliance_score: scan.compliance_score,
    violations: [],
  };

  if (scan.details && Array.isArray(scan.details.pages)) {
    for (const page of scan.details.pages) {
      const pageUrl = page.url;
      const vios = Array.isArray(page.violations) ? page.violations : [];
      
      for (const v of vios) {
        result.violations.push({
          ruleId: v.id,
          impact: v.impact,
          description: v.description,
          help: v.help,
          helpUrl: v.helpUrl,
          pageUrl,
          nodes: (v.nodes || []).map(n => ({
            target: Array.isArray(n.target) ? n.target.join(' ') : n.target,
            failureSummary: n.failureSummary,
            html: typeof n.html === 'string' ? n.html.slice(0, 500) : ''
          })),
        });
      }
    }
  }

  console.log(`Scan ${scanId}: stored ${scan.total_violations} violations, returning ${result.violations.length} detailed violations`);
  
  return res.json(result);
});

// --- AI Analysis Route ---
app.post('/api/ai/analyze', authenticateToken, async (req, res) => {
  if (!process.env.OPENAI_API_KEY) {
    return res.status(501).json({ 
      error: 'ai_disabled', 
      message: 'OpenAI API key not configured. Set OPENAI_API_KEY environment variable.' 
    });
  }

  try {
    const { scan_id } = req.body || {};
    if (!scan_id) {
      return res.status(400).json({ error: 'scan_id_required' });
    }

    const scan = scans.get(scan_id);
    if (!scan || scan.userId !== req.userId) {
      return res.status(404).json({ error: 'scan_not_found' });
    }

    if (scan.status !== 'done') {
      return res.status(202).json({ 
        status: scan.status, 
        message: 'scan_not_ready',
        details: 'Please wait for the scan to complete before requesting analysis.'
      });
    }

    const pages = scan.details?.pages || [];
    if (!pages.length) {
      return res.status(400).json({ error: 'no_scan_data_available' });
    }

    const prompt = `Analyze this accessibility scan for ${scan.url}:

SUMMARY:
- Total violations: ${scan.total_violations}
- Compliance score: ${scan.compliance_score}%
- Pages scanned: ${pages.length}

Provide a structured analysis with:
1. Executive summary (2-3 sentences)
2. Top 3 priority fixes with specific steps
3. Overall accessibility maturity assessment
4. Recommended next steps

Keep it concise and actionable for business stakeholders.`;

    const completion = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      messages: [{ role: 'user', content: prompt }],
      max_tokens: 1000,
      temperature: 0.3
    });

    const analysis = completion.choices[0]?.message?.content || 'Analysis could not be generated.';

    return res.json({
      status: 'ok',
      summary: {
        url: scan.url,
        total_violations: scan.total_violations,
        compliance_score: scan.compliance_score,
        pages_scanned: pages.length
      },
      analysis
    });

  } catch (e) {
    console.error('AI analyze error:', e);
    return res.status(500).json({ 
      error: 'ai_analysis_failed',
      details: e.message 
    });
  }
});

// ✅ Alt Text AI Routes
app.use('/api/alt-text-ai', altTextAIRoutes);

// --- Debug Routes ---
app.get('/api/debug/scans', authenticateToken, (req, res) => {
  const userScans = [...scans.values()]
    .filter(s => s.userId === req.userId)
    .map(s => ({
      id: s.id,
      status: s.status,
      url: s.url,
      violations: s.total_violations,
      pages: s.details?.pages?.length || 0
    }));
  
  return res.json({ scans: userScans });
});

app.get('/api/debug/websites', authenticateToken, (req, res) => {
  const userWebsites = [...websites.values()]
    .filter(w => w.userId === req.userId)
    .map(w => ({
      id: w.id,
      url: w.url,
      last_scan_id: w.last_scan_id,
      violations: w.total_violations
    }));
  
  return res.json({ websites: userWebsites });
});

// ✅ Error handling middleware
app.use(errorHandler);

// ✅ Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  if (dbInitialized) {
    await closeDatabase();
  }
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  if (dbInitialized) {
    await closeDatabase();
  }
  process.exit(0);
});

// --- Start Server ---
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`OpenAI integration: ${OPENAI_API_KEY ? 'enabled' : 'disabled'}`);
  console.log(`Database: ${dbInitialized ? 'PostgreSQL' : 'in-memory fallback'}`);
});
