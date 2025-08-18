// Security Configuration and Utilities for Alt Text AI
// Enterprise-grade security features and configurations

import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import helmet from 'helmet';

// Security Configuration
export const securityConfig = {
  // JWT Configuration
  jwt: {
    secret: process.env.JWT_SECRET || 'dev-secret-change-me',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    issuer: process.env.JWT_ISSUER || 'sentryprime-api',
    audience: process.env.JWT_AUDIENCE || 'sentryprime-frontend'
  },
  
  // Password Security
  password: {
    minLength: 8,
    maxLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: false,
    saltRounds: 12
  },
  
  // API Key Configuration
  apiKey: {
    length: 32,
    prefix: 'sp_',
    algorithm: 'sha256'
  },
  
  // Rate Limiting
  rateLimit: {
    // General API rate limit
    general: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100 // requests per window
    },
    
    // Authentication endpoints
    auth: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 10 // login attempts per window
    },
    
    // Alt Text AI endpoints
    altText: {
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 50 // AI requests per hour
    },
    
    // Scan endpoints
    scan: {
      windowMs: 10 * 60 * 1000, // 10 minutes
      max: 5 // scans per window
    }
  },
  
  // File Upload Security
  upload: {
    maxFileSize: 10 * 1024 * 1024, // 10MB
    allowedMimeTypes: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
    allowedExtensions: ['.jpg', '.jpeg', '.png', '.gif', '.webp']
  },
  
  // CORS Configuration
  cors: {
    development: ['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000'],
    production: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',' ) : []
  }
};

// Password Validation
export const validatePassword = (password) => {
  const errors = [];
  const config = securityConfig.password;
  
  if (!password || typeof password !== 'string') {
    errors.push('Password is required');
    return { isValid: false, errors };
  }
  
  if (password.length < config.minLength) {
    errors.push(`Password must be at least ${config.minLength} characters long`);
  }
  
  if (password.length > config.maxLength) {
    errors.push(`Password must be no more than ${config.maxLength} characters long`);
  }
  
  if (config.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (config.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (config.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (config.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Password Hashing
export const hashPassword = async (password) => {
  const validation = validatePassword(password);
  if (!validation.isValid) {
    throw new Error(`Password validation failed: ${validation.errors.join(', ')}`);
  }
  
  return await bcrypt.hash(password, securityConfig.password.saltRounds);
};

export const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// API Key Generation and Validation
export const generateApiKey = () => {
  const randomBytes = crypto.randomBytes(securityConfig.apiKey.length);
  const key = randomBytes.toString('hex');
  return `${securityConfig.apiKey.prefix}${key}`;
};

export const hashApiKey = (apiKey) => {
  return crypto
    .createHash(securityConfig.apiKey.algorithm)
    .update(apiKey)
    .digest('hex');
};

export const validateApiKey = (apiKey) => {
  if (!apiKey || typeof apiKey !== 'string') {
    return false;
  }
  
  if (!apiKey.startsWith(securityConfig.apiKey.prefix)) {
    return false;
  }
  
  const keyPart = apiKey.slice(securityConfig.apiKey.prefix.length);
  return keyPart.length === securityConfig.apiKey.length * 2; // hex encoding doubles length
};

// Secure Random Token Generation
export const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

// Data Encryption/Decryption (for sensitive data storage)
export const encrypt = (text, key = null) => {
  const encryptionKey = key || process.env.ENCRYPTION_KEY || 'default-key-change-me';
  const algorithm = 'aes-256-gcm';
  const iv = crypto.randomBytes(16);
  
  const cipher = crypto.createCipher(algorithm, encryptionKey);
  cipher.setAAD(Buffer.from('sentryprime-alt-text-ai'));
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
};

export const decrypt = (encryptedData, key = null) => {
  const encryptionKey = key || process.env.ENCRYPTION_KEY || 'default-key-change-me';
  const algorithm = 'aes-256-gcm';
  
  const decipher = crypto.createDecipher(algorithm, encryptionKey);
  decipher.setAAD(Buffer.from('sentryprime-alt-text-ai'));
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};

// Input Sanitization
export const sanitizeInput = (input) => {
  if (typeof input !== 'string') {
    return input;
  }
  
  // Remove potentially dangerous characters
  return input
    .replace(/[<>\"']/g, '') // Remove HTML/script injection chars
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .trim();
};

export const sanitizeUrl = (url) => {
  if (typeof url !== 'string') {
    return null;
  }
  
  try {
    const parsed = new URL(url);
    
    // Only allow HTTP and HTTPS protocols
    if (!['http:', 'https:'].includes(parsed.protocol )) {
      return null;
    }
    
    // Remove potentially dangerous query parameters
    const dangerousParams = ['javascript', 'script', 'eval', 'onload'];
    for (const param of dangerousParams) {
      parsed.searchParams.delete(param);
    }
    
    return parsed.toString();
  } catch (error) {
    return null;
  }
};

// File Upload Security
export const validateFileUpload = (file) => {
  const errors = [];
  const config = securityConfig.upload;
  
  if (!file) {
    errors.push('No file provided');
    return { isValid: false, errors };
  }
  
  // Check file size
  if (file.size > config.maxFileSize) {
    errors.push(`File size exceeds maximum allowed size of ${config.maxFileSize / (1024 * 1024)}MB`);
  }
  
  // Check MIME type
  if (!config.allowedMimeTypes.includes(file.mimetype)) {
    errors.push(`File type ${file.mimetype} is not allowed`);
  }
  
  // Check file extension
  const ext = file.originalname.toLowerCase().match(/\.[^.]+$/)?.[0];
  if (!ext || !config.allowedExtensions.includes(ext)) {
    errors.push(`File extension ${ext} is not allowed`);
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

// Helmet Security Configuration
export const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Disable for API compatibility
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
} );

// Security Audit Logging
export const logSecurityEvent = (event, details = {}) => {
  const logEntry = {
    timestamp: new Date().toISOString(),
    event,
    details,
    severity: getSeverityLevel(event),
    source: 'alt-text-ai-security'
  };
  
  console.log('Security Event:', JSON.stringify(logEntry));
  
  // In production, you might want to send this to a security monitoring service
  if (process.env.NODE_ENV === 'production' && logEntry.severity === 'high') {
    // Send alert to security team
    console.error('HIGH SEVERITY SECURITY EVENT:', logEntry);
  }
};

const getSeverityLevel = (event) => {
  const highSeverityEvents = [
    'authentication_failure',
    'authorization_failure',
    'rate_limit_exceeded',
    'invalid_api_key',
    'suspicious_activity'
  ];
  
  const mediumSeverityEvents = [
    'validation_error',
    'file_upload_rejected',
    'cors_violation'
  ];
  
  if (highSeverityEvents.includes(event)) return 'high';
  if (mediumSeverityEvents.includes(event)) return 'medium';
  return 'low';
};

// Request Fingerprinting (for security monitoring)
export const generateRequestFingerprint = (req) => {
  const fingerprint = {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    acceptLanguage: req.get('Accept-Language'),
    acceptEncoding: req.get('Accept-Encoding'),
    timestamp: Date.now()
  };
  
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(fingerprint))
    .digest('hex');
};

// Environment-specific security settings
export const getSecuritySettings = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  return {
    isProduction,
    corsOrigins: isProduction 
      ? securityConfig.cors.production 
      : securityConfig.cors.development,
    jwtSecret: isProduction 
      ? process.env.JWT_SECRET 
      : securityConfig.jwt.secret,
    enableDetailedErrors: !isProduction,
    enableSecurityHeaders: isProduction,
    enableAuditLogging: true,
    enableRateLimiting: true
  };
};
