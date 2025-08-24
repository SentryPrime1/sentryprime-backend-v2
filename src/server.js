import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import OpenAI from 'openai';
import { crawlAndScan } from './scanner.js';
import { initializeDatabase, closeDatabase } from '../database_connector.js';
import { createDatabaseModels } from '../database_models.js';
import { runMigration } from '../database_migration.js';
import {
  authenticateToken,
  createRateLimit,
  authRateLimit,
  scanRateLimit,
  securityHeaders,
  errorHandler
} from '../auth_middleware.js';
import altTextAIRoutes, { initializeAltTextAIRoutes } from '../routes/altTextAIRoutes.js';

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-4o-mini';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://sentryprime-frontend-v2.vercel.app';

// --- CORS Configuration ---
const allowedOrigins = [FRONTEND_URL, 'https://sentryprime-frontend-v2.vercel.app'];
const corsOptions = {
  origin: (origin, callback ) => {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) callback(null, true);
    else callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

const openai = OPENAI_API_KEY ? new OpenAI({ apiKey: OPENAI_API_KEY }) : null;

// --- Database Initialization ---
let db = null;

const initDB = async () => {
  if (db) return;
  try {
    console.log('🔄 Initializing database connection...');
    initializeDatabase();
    db = createDatabaseModels();
    console.log('✅ Database initialized successfully');
    initializeAltTextAIRoutes(db, {
      openai: { apiKey: OPENAI_API_KEY, model: OPENAI_MODEL },
      imageProcessing: { maxImageSize: 10 * 1024 * 1024, maxDimensions: { width: 2048, height: 2048 } },
      notifications: { enableInApp: true }
    });
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    db = null;
  }
};

initDB();

// --- Middleware ---
app.use(securityHeaders);
app.use(express.json({ limit: '2mb' }));
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(createRateLimit());

// --- Helper Functions ---
const signToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
const ensureDbInitialized = async (errorMessage) => {
  if (!db) {
    await initDB();
    if (!db) throw new Error(errorMessage);
  }
};

// --- Core Routes ---
app.get('/api/migrate', async (req, res, next) => {
  try {
    await ensureDbInitialized('Database connection could not be established for migration');
    await runMigration();
    res.json({ success: true, message: 'Database migration completed successfully!' });
  } catch (error) { next(error); }
});

app.get('/api/health', async (req, res, next) => {
  try {
    const dbHealth = db ? await db.healthCheck() : 'disconnected';
    res.json({ status: 'ok', database: dbHealth, timestamp: new Date().toISOString() });
  } catch (error) { next(error); }
});

// --- Auth Routes ---
app.post('/api/auth/register', authRateLimit, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for registration");
    const { firstName, lastName, email, password } = req.body;
    if (!firstName || !lastName || !email || !password) return res.status(400).json({ error: 'missing_fields' });
    const existingUser = await db.getUserByEmail(email);
    if (existingUser) return res.status(409).json({ error: 'email_exists' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = await db.createUser(email, passwordHash, firstName, lastName);
    const token = signToken(user.id);
    res.status(201).json({ token, user: { id: user.id, firstName: user.first_name, lastName: user.last_name, email: user.email } });
  } catch (error) { next(error); }
});

app.post('/api/auth/login', authRateLimit, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for login");
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'missing_credentials' });
    const user = await db.getUserByEmail(email);
    if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) return res.status(401).json({ error: 'invalid_credentials' });
    const token = signToken(user.id);
    res.status(200).json({ token, user: { id: user.id, firstName: user.first_name, lastName: user.last_name, email: user.email } });
  } catch (error) { next(error); }
});

// --- Dashboard & Website Routes ---
app.get('/api/dashboard/overview', authenticateToken, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for overview");
    const overview = await db.getUserDashboardOverview(req.userId);
    res.json(overview);
  } catch (error) { next(error); }
});

app.get('/api/dashboard/websites', authenticateToken, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for websites");
    const websites = await db.getWebsitesByUserId(req.userId);
    res.json({ websites });
  } catch (error) { next(error); }
});

app.post('/api/dashboard/websites', authenticateToken, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for creating website");
    const { url, name } = req.body;
    if (!url) return res.status(400).json({ error: 'url_required' });
    const existing = await db.getWebsiteByUrlAndUserId(req.userId, url);
    if (existing) return res.status(409).json({ error: 'website_exists' });
    const website = await db.createWebsite(req.userId, url, name || url);
    res.status(201).json(website);
  } catch (error) { next(error); }
});

// --- Scan Routes ---
app.get('/api/dashboard/scans', authenticateToken, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for scans");
    const scans = await db.getScansByUserId(req.userId);
    res.json({ scans });
  } catch (error) { next(error); }
});

// ✅ FIXED: Changed to match frontend expectations
app.post('/api/dashboard/scans', authenticateToken, scanRateLimit, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for starting scan");
    const { website_id, url } = req.body;
    if (!website_id || !url) return res.status(400).json({ error: 'website_id_and_url_required' });
    
    const website = await db.getWebsiteById(website_id);
    if (!website || website.user_id !== req.userId) return res.status(404).json({ error: 'website_not_found' });
    
    const scan = await db.createScan(req.userId, website_id, url, 'running');
    
    // Run scan asynchronously
    (async () => {
      try {
        const scanResult = await crawlAndScan(url, { maxPages: 50 });
        const updatePayload = { 
          status: 'done', 
          scanned_at: scanResult.scannedAt, 
          total_violations: scanResult.totalViolations, 
          compliance_score: scanResult.complianceScore, 
          pages_scanned: scanResult.totalPages, 
          scan_results: { pages: scanResult.pages } 
        };
        await db.updateScan(scan.id, updatePayload);
        console.log(`✅ Scan completed for website ${website_id}: ${scanResult.totalViolations} violations found`);
      } catch (error) {
        console.error('❌ Async scan processing failed:', error);
        await db.updateScan(scan.id, { status: 'error', scan_results: { error: error.message } });
      }
    })();
    
    res.status(201).json(scan);
  } catch (error) { next(error); }
});

app.get('/api/scans/:scanId/results', authenticateToken, async (req, res, next) => {
  try {
    await ensureDbInitialized("Database not available for scan results");
    const { scanId } = req.params;
    const scan = await db.getScanById(scanId);
    if (!scan || scan.user_id !== req.userId) return res.status(404).json({ error: 'scan_not_found' });
    if (scan.status !== 'done') return res.status(202).json({ status: scan.status, message: 'Scan not ready' });
    
    const scanResults = scan.scan_results || { pages: [] };
    const violations = (scanResults.pages || []).flatMap(page => 
      (page.violations || []).map(v => ({ ...v, pageUrl: page.url }))
    );
    
    res.json({ 
      id: scan.id, 
      url: scan.url, 
      scan_date: scan.scanned_at, 
      total_violations: scan.total_violations, 
      compliance_score: scan.compliance_score, 
      violations: violations 
    });
  } catch (error) { next(error); }
});

// --- AI Routes ---
app.use('/api/alt-text-ai', altTextAIRoutes);

// --- Error Handling ---
app.use(errorHandler);

// --- Server Lifecycle ---
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`OpenAI integration: ${OPENAI_API_KEY ? 'enabled' : 'disabled'}`);
  console.log(`Database: ${db ? 'connected' : 'checking...'}`);
});

const gracefulShutdown = async (signal) => {
  console.log(`${signal} received, shutting down gracefully`);
  server.close(async () => {
    if (db) await closeDatabase();
    process.exit(0);
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
