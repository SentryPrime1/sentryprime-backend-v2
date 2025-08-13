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
      
      // Create scan record
      const scanId = uuid();
      const scan = {
        id: scanId,
        userId: req.userId,
        website_id,
        website_name: website.name,
        url,
        scan_date: scanResult.scannedAt,
        total_violations: scanResult.totalViolations,
        compliance_score: scanResult.complianceScore,
        risk_level: scanResult.complianceScore < 70 ? 'High' : 
                   scanResult.complianceScore < 90 ? 'Moderate' : 'Low',
        pages_scanned: scanResult.totalPages,
        details: { pages: processedPages }
      };
      
      scans.set(scanId, scan);
      
      // Update website summary
      website.compliance_score = scan.compliance_score;
      website.total_violations = scan.total_violations;
      website.last_scan_date = scan.scan_date;
      
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

// --- AI Analysis Endpoint ---
app.post('/api/ai/analyze', authenticateToken, async (req, res) => {
  if (!openai) {
    return res.status(501).json({ 
      error: 'ai_disabled', 
      message: 'OpenAI API key not configured. Set OPENAI_API_KEY environment variable.' 
    });
  }
  
  const { scan_id } = req.body || {};
  
  if (!scan_id) {
    return res.status(400).json({ error: 'scan_id_required' });
  }
  
  // Verify scan belongs to user
  const scan = scans.get(scan_id);
  if (!scan || scan.userId !== req.userId) {
    return res.status(404).json({ error: 'scan_not_found' });
  }
  
  const pages = scan.details?.pages || [];
  if (!pages.length) {
    return res.status(400).json({ error: 'no_scan_data_available' });
  }
  
  try {
    // Aggregate violations by rule
    const ruleMap = new Map();
    
    for (const page of pages) {
      for (const violation of page.violations || []) {
        const ruleId = violation.id;
        const existing = ruleMap.get(ruleId) || {
          id: violation.id,
          help: violation.help,
          helpUrl: violation.helpUrl,
          description: violation.description,
          impactCounts: { critical: 0, serious: 0, moderate: 0, minor: 0, unknown: 0 },
          totalCount: 0,
          examples: []
        };
        
        const nodeCount = violation.nodes?.length || 1;
        existing.totalCount += nodeCount;
        
        const impact = (violation.impact || 'unknown').toLowerCase();
        existing.impactCounts[impact] = (existing.impactCounts[impact] || 0) + nodeCount;
        
        // Add examples (limit to 3 per rule)
        for (const node of violation.nodes || []) {
          if (existing.examples.length >= 3) break;
          existing.examples.push({
            target: node.target,
            failureSummary: node.failureSummary,
            htmlSnippet: node.html
          });
        }
        
        ruleMap.set(ruleId, existing);
      }
    }
    
    // Get top 10 most frequent violations
    const topViolations = [...ruleMap.values()]
      .sort((a, b) => b.totalCount - a.totalCount)
      .slice(0, 10);
    
    const analysisData = {
      siteUrl: scan.url,
      totalViolations: scan.total_violations,
      complianceScore: scan.compliance_score,
      riskLevel: scan.risk_level,
      pagesScanned: scan.pages_scanned,
      topViolations
    };
    
    // Enhanced AI prompt for better recommendations
    const systemPrompt = `You are an expert web accessibility consultant. Analyze the provided axe-core scan results and create a comprehensive, actionable fix guide.

For each violation rule:
1. Explain what the issue means in plain English
2. Explain why it matters for users with disabilities
3. Provide specific, step-by-step instructions to fix it
4. Include before/after code examples when relevant
5. Reference WCAG guidelines when applicable

Keep explanations clear and actionable for developers of all skill levels.`;

    const userPrompt = `Please analyze these accessibility scan results and provide detailed fix recommendations:

${JSON.stringify(analysisData, null, 2)}

Format your response in clear Markdown with sections for each violation type.`;

    console.log(`Generating AI analysis for scan ${scan_id}`);
    
    const completion = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      temperature: 0.3,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ]
    });
    
    const analysis = completion.choices?.[0]?.message?.content || 'No analysis generated.';
    
    console.log(`AI analysis completed for scan ${scan_id}`);
    
    return res.json({ analysis });
    
  } catch (error) {
    console.error('AI analysis failed:', error);
    return res.status(500).json({ 
      error: 'ai_analysis_failed', 
      details: error.message 
    });
  }
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
