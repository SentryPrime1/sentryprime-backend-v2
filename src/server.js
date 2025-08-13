import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { v4 as uuid } from 'uuid';
import OpenAI from 'openai';
import { crawlAndScan } from './scanner.js';

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';

// Initialize OpenAI if API key is provided
const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// --- Middleware ---
app.use(express.json({ limit: '2mb' }));
app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  credentials: false,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// --- In-memory Data Stores (replace with database later) ---
const users = new Map();      // id -> { id, firstName, lastName, email, passwordHash }
const websites = new Map();   // id -> { id, userId, name, url, last_scan_date, compliance_score, total_violations }
const scans = new Map();      // id -> { ...scan data, details: { pages } }

// --- Helper Functions ---
function signToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  
  if (!token) {
    return res.status(401).json({ error: 'no_token' });
  }
  
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// === Helpers ===
const getFromStore = (collection, key) => {
  // Supports Map or plain object
  if (!collection) return undefined;
  return collection instanceof Map ? collection.get(key) : collection[key];
};

const toArray = (collection) => {
  if (!collection) return [];
  return collection instanceof Map ? Array.from(collection.values()) : Object.values(collection);
};

const flattenViolationsFromScan = (scan) => {
  // Normalize to a single array of violations
  if (!scan) return [];

  if (Array.isArray(scan.violations)) return scan.violations;

  if (scan?.results?.violations && Array.isArray(scan.results.violations)) {
    return scan.results.violations;
  }

  if (scan?.details?.pages && Array.isArray(scan.details.pages)) {
    const all = [];
    for (const p of scan.details.pages) {
      if (Array.isArray(p.violations)) all.push(...p.violations);
    }
    return all;
  }

  return [];
};

// --- Authentication Endpoints ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body || {};
    
    if (!firstName || !lastName || !email || !password) {
      return res.status(400).json({ error: 'missing_fields' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'password_too_short' });
    }
    
    // Check if user already exists
    const existingUser = [...users.values()].find(
      u => u.email.toLowerCase() === String(email).toLowerCase()
    );
    
    if (existingUser) {
      return res.status(409).json({ error: 'email_exists' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);
    
    // Create user
    const id = uuid();
    const user = {
      id,
      firstName: String(firstName).trim(),
      lastName: String(lastName).trim(),
      email: String(email).toLowerCase().trim(),
      passwordHash,
      createdAt: new Date().toISOString()
    };
    
    users.set(id, user);
    
    const token = signToken(id);
    
    return res.status(201).json({
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'registration_failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    
    if (!email || !password) {
      return res.status(400).json({ error: 'missing_fields' });
    }
    
    // Find user
    const user = [...users.values()].find(
      u => u.email.toLowerCase() === String(email).toLowerCase()
    );
    
    if (!user) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.passwordHash);
    
    if (!isValidPassword) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    
    const token = signToken(user.id);
    
    return res.json({
      token,
      user: {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'login_failed' });
  }
});

// --- Dashboard Endpoints ---
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  const userWebsites = [...websites.values()].filter(w => w.userId === req.userId);
  const userScans = [...scans.values()].filter(s => s.userId === req.userId);
  
  const stats = {
    total_websites: userWebsites.length,
    total_scans: userScans.length,
    total_violations: userScans.reduce((sum, scan) => sum + (scan.total_violations || 0), 0),
    avg_compliance_score: userScans.length === 0 ? 0 : 
      Math.round(userScans.reduce((sum, scan) => sum + (scan.compliance_score || 0), 0) / userScans.length)
  };
  
  return res.json({ overview: stats });
});

// --- Website Management ---
app.route('/api/dashboard/websites')
  .get(authenticateToken, (req, res) => {
    const userWebsites = [...websites.values()].filter(w => w.userId === req.userId);
    return res.json({ websites: userWebsites });
  })
  .post(authenticateToken, (req, res) => {
    const { url, name } = req.body || {};
    
    if (!url) {
      return res.status(400).json({ error: 'url_required' });
    }
    
    // Validate URL format
    try {
      new URL(url);
    } catch {
      return res.status(400).json({ error: 'invalid_url' });
    }
    
    const id = uuid();
    const website = {
      id,
      userId: req.userId,
      url: String(url).trim(),
      name: name ? String(name).trim() : String(url).trim(),
      compliance_score: 0,
      total_violations: 0,
      last_scan_date: null,
      createdAt: new Date().toISOString()
    };
    
    websites.set(id, website);
    return res.status(201).json(website);
  });

// --- Scan Management ---
app.route('/api/dashboard/scans')
  .get(authenticateToken, (req, res) => {
    const userScans = [...scans.values()].filter(s => s.userId === req.userId);
    
    // Return summary data (without full page details)
    const scanSummaries = userScans.map(scan => ({
      id: scan.id,
      website_id: scan.website_id,
      website_name: scan.website_name,
      url: scan.url,
      scan_date: scan.scan_date,
      total_violations: scan.total_violations,
      compliance_score: scan.compliance_score,
      risk_level: scan.risk_level,
      pages_scanned: scan.pages_scanned
    }));
    
    return res.json({ scans: scanSummaries });
  })
  .post(authenticateToken, async (req, res) => {
    const { website_id, url } = req.body || {};
    
    if (!website_id || !url) {
      return res.status(400).json({ error: 'website_id_and_url_required' });
    }
    
    // Verify website belongs to user
    const website = websites.get(website_id);
    if (!website || website.userId !== req.userId) {
      return res.status(404).json({ error: 'website_not_found' });
    }
    
    try {
      // Create scan record FIRST with running status
      const scanId = uuid();
      console.log('[scan:start]', scanId, url, 'user=', req.userId); // ✅ LOGGING ADDED
      
      const scan = {
        id: scanId,
        userId: req.userId,
        website_id,
        website_name: website.name,
        url,
        scan_date: new Date().toISOString(),
        status: 'running',
        total_violations: 0,
        compliance_score: null,
        risk_level: 'Unknown',
        pages_scanned: 0,
        details: null
      };
      
      // Store scan immediately
      scans.set(scanId, scan);
      
      console.log(`Starting scan for user ${req.userId}, website ${website_id}: ${url}`);
      
      // Run the actual accessibility scan
      const scanResult = await crawlAndScan(url, { maxPages: 50 });
      
      // Process scan results for storage
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
      
      // Update the SAME scan object
      scan.scan_date = scanResult.scannedAt;
      scan.total_violations = scanResult.totalViolations;
      scan.compliance_score = scanResult.complianceScore;
      scan.risk_level = scanResult.complianceScore < 70 ? 'High' : 
                       scanResult.complianceScore < 90 ? 'Moderate' : 'Low';
      scan.pages_scanned = scanResult.totalPages;
      scan.details = { pages: processedPages };
      scan.status = 'done';
      
      // Update scan in storage (same ID)
      scans.set(scanId, scan);
      
      // Update website summary
      website.compliance_score = scan.compliance_score;
      website.total_violations = scan.total_violations;
      website.last_scan_date = scan.scan_date;
      
      console.log('[scan:finish]', scan.id, 'violations=', scan.total_violations, 'status=', scan.status); // ✅ LOGGING ADDED
      console.log(`Scan completed: ${scan.total_violations} violations, ${scan.compliance_score}% compliance`);
      
      return res.status(201).json(scan);
      
    } catch (error) {
      console.error('Scan failed:', error);
      return res.status(500).json({ 
        error: 'scan_failed', 
        details: error.message 
      });
    }
  });

// Individual scan summary (no heavy payload), auth required
app.get('/api/scans/:scanId', authenticateToken, (req, res) => {
  const { scanId } = req.params;
  const scan = getFromStore(scans, scanId);

  if (!scan || (scan.userId && scan.userId !== req.userId)) {
    return res.status(404).json({ error: 'scan_not_found' });
  }

  return res.json({
    id: scan.id || scanId,
    url: scan.url || scan.targetUrl || scan.pageUrl,
    userId: scan.userId,
    scan_date: scan.scan_date || scan.createdAt || scan.timestamp,
    totals: {
      violations: flattenViolationsFromScan(scan).length,
    },
  });
});

// Full results for a scan (normalized), auth required
app.get('/api/scans/:scanId/results', authenticateToken, (req, res) => {
  const { scanId } = req.params;
  const scan = getFromStore(scans, scanId);

  if (!scan || (scan.userId && scan.userId !== req.userId)) {
    return res.status(404).json({ error: 'scan_not_found' });
  }

  const violations = flattenViolationsFromScan(scan);

  return res.json({
    id: scan.id || scanId,
    url: scan.url || scan.targetUrl || scan.pageUrl,
    scan_date: scan.scan_date || scan.createdAt || scan.timestamp,
    violations,
  });
});

// --- Enhanced AI Analysis Endpoint ---
app.post('/api/ai/analyze', authenticateToken, async (req, res) => {
  try {
    const { scan_id, scanId, url } = req.body || {};
    const id = scan_id || scanId;

    let scan = id ? getFromStore(scans, id) : null;

    // Optional fallback: if no scanId provided or not found, try the most recent scan for this user (and same URL if provided)
    if (!scan) {
      let userScans = toArray(scans).filter(s => !s.userId || s.userId === req.userId);
      if (url) userScans = userScans.filter(s => (s.url || s.targetUrl || s.pageUrl) === url);
      userScans.sort((a, b) => new Date(b.scan_date || b.createdAt || b.timestamp || 0) - new Date(a.scan_date || a.createdAt || a.timestamp || 0));
      scan = userScans[0] || null;
    }

    if (!scan) {
      return res.status(404).json({ error: 'scan_not_found' });
    }

    if (!openai) {
      return res.status(501).json({ 
        error: 'ai_disabled', 
        message: 'OpenAI API key not configured. Set OPENAI_API_KEY environment variable.' 
      });
    }

    const violations = flattenViolationsFromScan(scan);

    // Build a compact prompt with a capped sample if huge
    const maxExamples = 50;
    const sample = violations.slice(0, maxExamples).map(v => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      description: v.description,
      helpUrl: v.helpUrl,
      nodes: (v.nodes || []).slice(0, 3).map(n => ({
        target: n.target,
        failureSummary: n.failureSummary
      }))
    }));

    const sys = `
You are an accessibility expert. Based on axe-core violations, produce:
1) A concise summary for non-technical stakeholders.
2) A prioritized list of fixes (group by issue type, highest impact first).
3) For each group, give step-by-step, code-aware remediation guidance (HTML/ARIA/CSS/JS), with short examples.
4) Keep it actionable and concrete.
`;

    const userMsg = {
      url: scan.url || scan.targetUrl || scan.pageUrl,
      total_violations: violations.length,
      sample_violations: sample
    };

    const completion = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      temperature: 0.2,
      messages: [
        { role: 'system', content: sys },
        { role: 'user', content: `Here are axe-core results:\n${JSON.stringify(userMsg, null, 2)}` }
      ]
    });

    const text = completion.choices?.[0]?.message?.content?.trim() || 'No analysis generated.';

    // Lightweight structured response with a plain-text summary
    return res.json({
      scan_id: scan.id || id,
      url: userMsg.url,
      total_violations: violations.length,
      summary: text,
      prioritized_fixes: [], // (optional) keep as array if you later add structured parsing
    });
  } catch (err) {
    console.error('AI analyze error:', err);
    return res.status(500).json({ error: 'ai_error', detail: String(err?.message || err) });
  }
});

// TEMP DEBUG — list scans in memory for the current user
app.get('/debug/scans', authenticateToken, (req, res) => {
  const list = [...scans.values()].filter(s => s.userId === req.userId);
  res.json({
    count: list.length,
    scanIds: list.map(s => ({ id: s.id, url: s.url, status: s.status, date: s.scan_date })),
  });
});

// --- Health Check ---
app.get('/', (req, res) => {
  res.json({ 
    ok: true, 
    service: 'SentryPrime Backend v2',
    features: {
      scanning: true,
      ai_analysis: !!openai
    }
  });
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`🚀 SentryPrime Backend v2 running on port ${PORT}`);
  console.log(`🤖 AI Analysis: ${openai ? 'Enabled' : 'Disabled (set OPENAI_API_KEY)'}`);
});
