// Enterprise Authentication Middleware for Alt Text AI
// Provides JWT validation, rate limiting, and security features

import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { body, validationResult, param, query } from 'express-validator';

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 100; // requests per window

// JWT Authentication Middleware
export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    
    if (!token) {
      return res.status(401).json({ 
        error: 'authentication_required',
        message: 'Access token is required'
      });
    }
    
    // Verify JWT token
    const payload = jwt.verify(token, JWT_SECRET);
    
    // Add user info to request
    req.userId = payload.userId;
    req.userEmail = payload.email;
    req.tokenIat = payload.iat;
    req.tokenExp = payload.exp;
    
    // Optional: Check if user exists in database
    if (req.app.locals.db) {
      try {
        const user = await req.app.locals.db.getUserById(req.userId);
        if (!user) {
          return res.status(401).json({ 
            error: 'user_not_found',
            message: 'User account no longer exists'
          });
        }
        req.user = user;
      } catch (dbError) {
        console.warn('Database user lookup failed:', dbError.message);
        // Continue without database validation if DB is unavailable
      }
    }
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'invalid_token',
        message: 'Invalid access token'
      });
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'token_expired',
        message: 'Access token has expired'
      });
    } else {
      console.error('Authentication error:', error);
      return res.status(500).json({ 
        error: 'authentication_error',
        message: 'Authentication service unavailable'
      });
    }
  }
};

// API Key Authentication (for Alt Text AI service-to-service calls)
export const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  const validApiKey = process.env.ALT_TEXT_API_KEY;
  
  if (!validApiKey) {
    return res.status(501).json({ 
      error: 'api_key_not_configured',
      message: 'API key authentication not configured'
    });
  }
  
  if (!apiKey || apiKey !== validApiKey) {
    return res.status(401).json({ 
      error: 'invalid_api_key',
      message: 'Valid API key is required'
    });
  }
  
  next();
};

// Rate Limiting Middleware
export const createRateLimit = (options = {}) => {
  return rateLimit({
    windowMs: options.windowMs || RATE_LIMIT_WINDOW,
    max: options.max || RATE_LIMIT_MAX,
    message: {
      error: 'rate_limit_exceeded',
      message: `Too many requests. Try again in ${Math.ceil((options.windowMs || RATE_LIMIT_WINDOW) / 60000)} minutes.`,
      retryAfter: Math.ceil((options.windowMs || RATE_LIMIT_WINDOW) / 1000)
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    keyGenerator: (req) => {
      // Use user ID if authenticated, otherwise IP address
      return req.userId || req.ip;
    },
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === '/api/health';
    }
  });
};

// Specific rate limits for different endpoints
export const authRateLimit = createRateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 login attempts per 15 minutes
});

export const altTextRateLimit = createRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // 50 Alt Text AI requests per hour
});

export const scanRateLimit = createRateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // 5 scans per 10 minutes
});

// Input Validation Middleware
export const validateScanRequest = [
  body('website_id')
    .isUUID()
    .withMessage('website_id must be a valid UUID'),
  body('url')
    .isURL({ protocols: ['http', 'https'] } )
    .withMessage('url must be a valid HTTP/HTTPS URL')
    .isLength({ max: 2048 })
    .withMessage('url must be less than 2048 characters'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Invalid request data',
        details: errors.array()
      });
    }
    next();
  }
];

export const validateAltTextRequest = [
  body('scan_id')
    .isUUID()
    .withMessage('scan_id must be a valid UUID'),
  body('website_url')
    .isURL({ protocols: ['http', 'https'] } )
    .withMessage('website_url must be a valid HTTP/HTTPS URL'),
  body('total_images')
    .optional()
    .isInt({ min: 0, max: 1000 })
    .withMessage('total_images must be between 0 and 1000'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Invalid Alt Text AI request',
        details: errors.array()
      });
    }
    next();
  }
];

export const validateJobId = [
  param('jobId')
    .isUUID()
    .withMessage('jobId must be a valid UUID'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Invalid job ID',
        details: errors.array()
      });
    }
    next();
  }
];

export const validateScanId = [
  param('scanId')
    .isUUID()
    .withMessage('scanId must be a valid UUID'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'validation_error',
        message: 'Invalid scan ID',
        details: errors.array()
      });
    }
    next();
  }
];

// Request Sanitization Middleware
export const sanitizeInput = (req, res, next) => {
  // Recursively sanitize all string inputs
  const sanitizeObject = (obj) => {
    if (typeof obj === 'string') {
      // Remove potentially dangerous characters
      return obj.replace(/[<>\"']/g, '').trim();
    } else if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    } else if (obj && typeof obj === 'object') {
      const sanitized = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[key] = sanitizeObject(value);
      }
      return sanitized;
    }
    return obj;
  };
  
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }
  
  next();
};

// Error Handling Middleware
export const errorHandler = (err, req, res, next) => {
  console.error('API Error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    userId: req.userId,
    timestamp: new Date().toISOString()
  });
  
  // Don't leak internal errors in production
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({
      error: 'internal_server_error',
      message: 'An unexpected error occurred'
    });
  }
  
  // In development, provide more details
  res.status(500).json({
    error: 'internal_server_error',
    message: err.message,
    stack: err.stack
  });
};

// Security Headers Middleware
export const securityHeaders = (req, res, next) => {
  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Remove server information
  res.removeHeader('X-Powered-By');
  
  next();
};

// Audit Logging Middleware for Alt Text AI operations
export const auditLogger = (operation) => {
  return (req, res, next) => {
    const startTime = Date.now();
    
    // Log request
    const logData = {
      operation,
      userId: req.userId,
      userEmail: req.userEmail,
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
      requestId: req.headers['x-request-id'] || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
    };
    
    // Add request ID to response headers
    res.setHeader('X-Request-ID', logData.requestId);
    
    // Override res.json to capture response
    const originalJson = res.json;
    res.json = function(data) {
      const duration = Date.now() - startTime;
      
      // Log response (without sensitive data)
      console.log('Alt Text AI Audit:', {
        ...logData,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        success: res.statusCode < 400,
        responseSize: JSON.stringify(data).length
      });
      
      // Store in database if available
      if (req.app.locals.db && req.userId) {
        try {
          // You could add an audit_logs table and store this data
          // req.app.locals.db.logAuditEvent(logData, res.statusCode, duration);
        } catch (dbError) {
          console.warn('Failed to store audit log:', dbError.message);
        }
      }
      
      return originalJson.call(this, data);
    };
    
    next();
  };
};

// CORS Configuration for Production
export const corsConfig = {
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = process.env.CORS_ORIGINS 
      ? process.env.CORS_ORIGINS.split(',').map(s => s.trim())
      : ['http://localhost:3000', 'http://localhost:5173']; // Default for development
    
    if (allowedOrigins.includes('*' ) || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Request-ID'],
  exposedHeaders: ['X-Request-ID', 'X-RateLimit-Limit', 'X-RateLimit-Remaining']
};

// Health Check Middleware (bypasses authentication)
export const healthCheck = (req, res, next) => {
  if (req.path === '/api/health' || req.path === '/health') {
    return res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: process.env.npm_package_version || '1.0.0'
    });
  }
  next();
};
