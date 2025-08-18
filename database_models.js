// Database Models and Connection for Alt Text AI
// Enterprise-grade PostgreSQL integration with connection pooling

import pkg from 'pg';
const { Pool } = pkg;
import crypto from 'crypto';

// Database connection pool
let pool = null;

// Initialize database connection
export const initializeDatabase = async () => {
  try {
    // Create connection pool with Railway environment variables
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      max: 20, // Maximum number of connections
      idleTimeoutMillis: 30000, // Close idle connections after 30 seconds
      connectionTimeoutMillis: 2000, // Return error after 2 seconds if connection cannot be established
    });

    // Test the connection
    const client = await pool.connect();
    console.log('✅ Database connected successfully');
    client.release();

    return pool;
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    throw error;
  }
};

// Get database pool
export const getPool = () => {
  if (!pool) {
    throw new Error('Database not initialized. Call initializeDatabase() first.');
  }
  return pool;
};

// Close database connection
export const closeDatabase = async () => {
  if (pool) {
    await pool.end();
    pool = null;
    console.log('✅ Database connection closed');
  }
};

// Database Models
export class DatabaseModels {
  constructor() {
    this.pool = getPool();
  }

  // User Management
  async createUser(email, passwordHash) {
    const query = `
      INSERT INTO users (email, password_hash)
      VALUES ($1, $2)
      RETURNING id, email, created_at
    `;
    const result = await this.pool.query(query, [email, passwordHash]);
    return result.rows[0];
  }

  async getUserById(userId) {
    const query = 'SELECT id, email, created_at FROM users WHERE id = $1';
    const result = await this.pool.query(query, [userId]);
    return result.rows[0];
  }

  async getUserByEmail(email) {
    const query = 'SELECT id, email, password_hash, created_at FROM users WHERE email = $1';
    const result = await this.pool.query(query, [email]);
    return result.rows[0];
  }

  // Website Management
  async createOrUpdateWebsite(userId, url, title = null) {
    const query = `
      INSERT INTO websites (user_id, url, title, last_scanned_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id, url)
      DO UPDATE SET 
        title = COALESCE($3, websites.title),
        last_scanned_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      RETURNING id, url, title, last_scanned_at
    `;
    const result = await this.pool.query(query, [userId, url, title]);
    return result.rows[0];
  }

  async getUserWebsites(userId, limit = 50) {
    const query = `
      SELECT id, url, title, last_scanned_at, created_at
      FROM websites
      WHERE user_id = $1
      ORDER BY last_scanned_at DESC NULLS LAST, created_at DESC
      LIMIT $2
    `;
    const result = await this.pool.query(query, [userId, limit]);
    return result.rows;
  }

  // Scan Management
  async createScan(userId, websiteId, scanId, scanData = null) {
    const query = `
      INSERT INTO scans (user_id, website_id, scan_id, scan_data, status)
      VALUES ($1, $2, $3, $4, 'pending')
      RETURNING id, scan_id, status, created_at
    `;
    const result = await this.pool.query(query, [userId, websiteId, scanId, JSON.stringify(scanData)]);
    return result.rows[0];
  }

  async updateScanResults(scanId, violationCounts, scanData = null) {
    const query = `
      UPDATE scans SET
        status = 'completed',
        total_violations = $2,
        critical_count = $3,
        serious_count = $4,
        moderate_count = $5,
        minor_count = $6,
        pages_scanned = $7,
        scan_data = $8,
        completed_at = CURRENT_TIMESTAMP
      WHERE scan_id = $1
      RETURNING id, scan_id, status, total_violations, completed_at
    `;
    const result = await this.pool.query(query, [
      scanId,
      violationCounts.total || 0,
      violationCounts.critical || 0,
      violationCounts.serious || 0,
      violationCounts.moderate || 0,
      violationCounts.minor || 0,
      violationCounts.pages || 1,
      JSON.stringify(scanData)
    ]);
    return result.rows[0];
  }

  async getScanById(scanId) {
    const query = `
      SELECT s.*, w.url as website_url, w.title as website_title
      FROM scans s
      JOIN websites w ON s.website_id = w.id
      WHERE s.scan_id = $1
    `;
    const result = await this.pool.query(query, [scanId]);
    return result.rows[0];
  }

  async getUserScans(userId, limit = 50) {
    const query = `
      SELECT s.*, w.url as website_url, w.title as website_title
      FROM scans s
      JOIN websites w ON s.website_id = w.id
      WHERE s.user_id = $1
      ORDER BY s.created_at DESC
      LIMIT $2
    `;
    const result = await this.pool.query(query, [userId, limit]);
    return result.rows;
  }

  // Alt Text AI Job Management
  async createAltTextJob(userId, scanId, websiteUrl, totalImages = 0) {
    const jobId = crypto.randomUUID();
    const query = `
      INSERT INTO alt_text_jobs (job_id, user_id, scan_id, website_url, total_images, status)
      VALUES ($1, $2, $3, $4, $5, 'pending')
      RETURNING id, job_id, status, created_at
    `;
    const result = await this.pool.query(query, [jobId, userId, scanId, websiteUrl, totalImages]);
    return result.rows[0];
  }

  async updateAltTextJobStatus(jobId, status, processedImages = null, failedImages = null, errorMessage = null) {
    const updates = ['status = $2'];
    const params = [jobId, status];
    let paramIndex = 3;

    if (processedImages !== null) {
      updates.push(`processed_images = $${paramIndex}`);
      params.push(processedImages);
      paramIndex++;
    }

    if (failedImages !== null) {
      updates.push(`failed_images = $${paramIndex}`);
      params.push(failedImages);
      paramIndex++;
    }

    if (errorMessage !== null) {
      updates.push(`error_message = $${paramIndex}`);
      params.push(errorMessage);
      paramIndex++;
    }

    if (status === 'completed' || status === 'failed') {
      updates.push('completed_at = CURRENT_TIMESTAMP');
    }

    const query = `
      UPDATE alt_text_jobs SET
        ${updates.join(', ')},
        updated_at = CURRENT_TIMESTAMP
      WHERE job_id = $1
      RETURNING id, job_id, status, processed_images, failed_images, updated_at
    `;

    const result = await this.pool.query(query, params);
    return result.rows[0];
  }

  async getAltTextJob(jobId) {
    const query = `
      SELECT atj.*, s.scan_id, w.url as website_url, w.title as website_title
      FROM alt_text_jobs atj
      LEFT JOIN scans s ON atj.scan_id = s.id
      LEFT JOIN websites w ON s.website_id = w.id
      WHERE atj.job_id = $1
    `;
    const result = await this.pool.query(query, [jobId]);
    return result.rows[0];
  }

  async getUserAltTextJobs(userId, limit = 50) {
    const query = `
      SELECT atj.*, s.scan_id, w.url as website_url, w.title as website_title
      FROM alt_text_jobs atj
      LEFT JOIN scans s ON atj.scan_id = s.id
      LEFT JOIN websites w ON s.website_id = w.id
      WHERE atj.user_id = $1
      ORDER BY atj.created_at DESC
      LIMIT $2
    `;
    const result = await this.pool.query(query, [userId, limit]);
    return result.rows;
  }

  // Alt Text Suggestions Management
  async createAltTextSuggestion(jobId, imageData) {
    const query = `
      INSERT INTO alt_text_suggestions (
        job_id, image_url, image_selector, page_url, page_title, page_context,
        suggestion_1, suggestion_2, suggestion_3,
        confidence_1, confidence_2, confidence_3,
        is_decorative
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING id, image_url, suggestion_1, suggestion_2, suggestion_3
    `;
    
    const result = await this.pool.query(query, [
      jobId,
      imageData.imageUrl,
      imageData.selector,
      imageData.pageUrl,
      imageData.pageTitle,
      imageData.pageContext,
      imageData.suggestions[0]?.text,
      imageData.suggestions[1]?.text,
      imageData.suggestions[2]?.text,
      imageData.suggestions[0]?.confidence,
      imageData.suggestions[1]?.confidence,
      imageData.suggestions[2]?.confidence,
      imageData.isDecorative || false
    ]);
    
    return result.rows[0];
  }

  async getJobSuggestions(jobId) {
    const query = `
      SELECT *
      FROM alt_text_suggestions
      WHERE job_id = (SELECT id FROM alt_text_jobs WHERE job_id = $1)
      ORDER BY created_at ASC
    `;
    const result = await this.pool.query(query, [jobId]);
    return result.rows;
  }

  async updateSuggestionSelection(suggestionId, selectedSuggestion, userFeedback = null) {
    const query = `
      UPDATE alt_text_suggestions SET
        selected_suggestion = $2,
        user_feedback = $3,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING id, selected_suggestion, user_feedback
    `;
    const result = await this.pool.query(query, [suggestionId, selectedSuggestion, userFeedback]);
    return result.rows[0];
  }

  // Image Cache Management
  async getCachedImage(imageUrl) {
    const urlHash = crypto.createHash('sha256').update(imageUrl).digest('hex');
    const query = `
      UPDATE image_cache SET accessed_at = CURRENT_TIMESTAMP
      WHERE url_hash = $1
      RETURNING *
    `;
    const result = await this.pool.query(query, [urlHash]);
    return result.rows[0];
  }

  async cacheImage(imageUrl, imageData, contentType, width, height, altSuggestions = null) {
    const urlHash = crypto.createHash('sha256').update(imageUrl).digest('hex');
    const query = `
      INSERT INTO image_cache (
        image_url, url_hash, image_data, content_type, file_size, width, height, alt_suggestions
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (url_hash) DO UPDATE SET
        accessed_at = CURRENT_TIMESTAMP,
        alt_suggestions = COALESCE($8, image_cache.alt_suggestions)
      RETURNING id, url_hash
    `;
    
    const result = await this.pool.query(query, [
      imageUrl,
      urlHash,
      imageData,
      contentType,
      imageData ? imageData.length : 0,
      width,
      height,
      JSON.stringify(altSuggestions)
    ]);
    
    return result.rows[0];
  }

  async cleanupImageCache(olderThanDays = 30) {
    const query = `
      DELETE FROM image_cache
      WHERE accessed_at < CURRENT_TIMESTAMP - INTERVAL '${olderThanDays} days'
      RETURNING COUNT(*) as deleted_count
    `;
    const result = await this.pool.query(query);
    return result.rows[0].deleted_count;
  }

  // API Usage Tracking
  async logApiUsage(userId, jobId, apiType, tokensUsed, costUsd, requestData = null, responseData = null) {
    const query = `
      INSERT INTO api_usage (user_id, job_id, api_type, tokens_used, cost_usd, request_data, response_data)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, created_at
    `;
    
    const result = await this.pool.query(query, [
      userId,
      jobId,
      apiType,
      tokensUsed,
      costUsd,
      JSON.stringify(requestData),
      JSON.stringify(responseData)
    ]);
    
    return result.rows[0];
  }

  async getUserApiUsage(userId, fromDate = null, toDate = null) {
    let query = `
      SELECT 
        api_type,
        COUNT(*) as request_count,
        SUM(tokens_used) as total_tokens,
        SUM(cost_usd) as total_cost,
        DATE(created_at) as usage_date
      FROM api_usage
      WHERE user_id = $1
    `;
    
    const params = [userId];
    let paramIndex = 2;

    if (fromDate) {
      query += ` AND created_at >= $${paramIndex}`;
      params.push(fromDate);
      paramIndex++;
    }

    if (toDate) {
      query += ` AND created_at <= $${paramIndex}`;
      params.push(toDate);
      paramIndex++;
    }

    query += `
      GROUP BY api_type, DATE(created_at)
      ORDER BY usage_date DESC, api_type
    `;

    const result = await this.pool.query(query, params);
    return result.rows;
  }

  // User Settings Management
  async getUserSettings(userId) {
    const query = `
      SELECT *
      FROM user_settings
      WHERE user_id = $1
    `;
    const result = await this.pool.query(query, [userId]);
    return result.rows[0];
  }

  async updateUserSettings(userId, settings) {
    const updates = [];
    const params = [userId];
    let paramIndex = 2;

    const allowedSettings = [
      'alt_text_style', 'include_decorative', 'max_alt_length',
      'preferred_language', 'email_notifications'
    ];

    for (const [key, value] of Object.entries(settings)) {
      if (allowedSettings.includes(key)) {
        updates.push(`${key} = $${paramIndex}`);
        params.push(value);
        paramIndex++;
      }
    }

    if (updates.length === 0) {
      return await this.getUserSettings(userId);
    }

    const query = `
      INSERT INTO user_settings (user_id, ${Object.keys(settings).filter(k => allowedSettings.includes(k)).join(', ')})
      VALUES ($1, ${Object.keys(settings).filter(k => allowedSettings.includes(k)).map((_, i) => `$${i + 2}`).join(', ')})
      ON CONFLICT (user_id) DO UPDATE SET
        ${updates.join(', ')},
        updated_at = CURRENT_TIMESTAMP
      RETURNING *
    `;

    const result = await this.pool.query(query, params);
    return result.rows[0];
  }

  // Health Check
  async healthCheck() {
    try {
      const result = await this.pool.query('SELECT NOW() as current_time, version() as postgres_version');
      return {
        status: 'healthy',
        timestamp: result.rows[0].current_time,
        database: 'PostgreSQL',
        version: result.rows[0].postgres_version.split(' ')[1]
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
}

// Export singleton instance
export const db = new DatabaseModels();
