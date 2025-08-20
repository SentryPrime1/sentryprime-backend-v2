import { getPool } from './database_connector.js';

// --- DatabaseModels Class ---
// Encapsulates all database interactions for the application.
class DatabaseModels {
  constructor() {
    this.pool = getPool();
    if (!this.pool) {
      // This check is a safeguard, as getPool() now initializes if needed.
      throw new Error('Database pool could not be initialized.');
    }
  }

  // --- Health & Utility ---
  async healthCheck() {
    try {
      const { rows } = await this.pool.query('SELECT version()');
      return { status: 'healthy', db_version: rows[0].version };
    } catch (error) {
      console.error('Database health check failed:', error);
      return { status: 'unhealthy', error: error.message };
    }
  }

  // --- User Methods ---
  async createUser(email, passwordHash, firstName, lastName) {
    const query = `
      INSERT INTO users (email, password_hash, first_name, last_name)
      VALUES ($1, $2, $3, $4)
      RETURNING id, email, first_name, last_name, created_at;
    `;
    const { rows } = await this.pool.query(query, [email, passwordHash, firstName, lastName]);
    return rows[0];
  }

  async getUserByEmail(email) {
    const { rows } = await this.pool.query('SELECT * FROM users WHERE email = $1', [email]);
    return rows[0];
  }

  // --- Website Methods ---
  async createWebsite(userId, url, name) {
    const query = `
      INSERT INTO websites (user_id, url, name)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;
    const { rows } = await this.pool.query(query, [userId, url, name]);
    return rows[0];
  }

  async getWebsitesByUserId(userId) {
    const { rows } = await this.pool.query('SELECT * FROM websites WHERE user_id = $1 ORDER BY created_at DESC', [userId]);
    return rows;
  }

  async getWebsiteById(websiteId) {
    const { rows } = await this.pool.query('SELECT * FROM websites WHERE id = $1', [websiteId]);
    return rows[0];
  }

  async getWebsiteByUrlAndUserId(userId, url) {
    const { rows } = await this.pool.query('SELECT * FROM websites WHERE user_id = $1 AND url = $2', [userId, url]);
    return rows[0];
  }

  // --- Scan Methods ---
  async createScan(userId, websiteId, url, status) {
    const query = `
      INSERT INTO scans (user_id, website_id, url, status, scan_date)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING *;
    `;
    const { rows } = await this.pool.query(query, [userId, websiteId, url, status]);
    return rows[0];
  }

  async updateScan(scanId, payload) {
    const { status, scanned_at, total_violations, compliance_score, pages_scanned, scan_results } = payload;
    const query = `
      UPDATE scans
      SET
        status = COALESCE($2, status),
        scanned_at = COALESCE($3, scanned_at),
        total_violations = COALESCE($4, total_violations),
        compliance_score = COALESCE($5, compliance_score),
        pages_scanned = COALESCE($6, pages_scanned),
        scan_results = COALESCE($7, scan_results)
      WHERE id = $1
      RETURNING *;
    `;
    const { rows } = await this.pool.query(query, [scanId, status, scanned_at, total_violations, compliance_score, pages_scanned, scan_results]);
    return rows[0];
  }

  async getScanById(scanId) {
    const { rows } = await this.pool.query('SELECT * FROM scans WHERE id = $1', [scanId]);
    return rows[0];
  }

  async getScansByUserId(userId) {
    const query = `
      SELECT s.id, s.website_id, w.name as website_name, s.url, s.scan_date, s.status, s.total_violations, s.compliance_score
      FROM scans s
      JOIN websites w ON s.website_id = w.id
      WHERE s.user_id = $1
      ORDER BY s.scan_date DESC;
    `;
    const { rows } = await this.pool.query(query, [userId]);
    return rows;
  }

  async getUserDashboardOverview(userId) {
    const query = `
      SELECT
        (SELECT COUNT(*) FROM websites WHERE user_id = $1) AS total_websites,
        (SELECT COUNT(*) FROM scans WHERE user_id = $1) AS total_scans,
        (SELECT COALESCE(SUM(total_violations), 0) FROM scans WHERE user_id = $1 AND status = 'done') AS total_violations,
        (SELECT COALESCE(AVG(compliance_score), 0) FROM scans WHERE user_id = $1 AND status = 'done') AS avg_compliance;
    `;
    try {
      const { rows } = await this.pool.query(query, [userId]);
      const result = rows[0];
      return {
        totalWebsites: parseInt(result.total_websites, 10),
        totalScans: parseInt(result.total_scans, 10),
        totalViolations: parseInt(result.total_violations, 10),
        avgCompliance: parseFloat(result.avg_compliance).toFixed(0)
      };
    } catch (error) {
      console.error(`Error getting dashboard overview for user ${userId}:`, error);
      throw new Error('Failed to retrieve dashboard overview');
    }
  }
}

// Factory function to create an instance of DatabaseModels
export function createDatabaseModels() {
  return new DatabaseModels();
}
