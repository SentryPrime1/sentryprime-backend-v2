-- Alt Text AI Database Schema for PostgreSQL
-- Enterprise-grade schema with proper indexing, relationships, and constraints

-- Users table (if not exists)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Websites table for tracking scanned sites
CREATE TABLE IF NOT EXISTS websites (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url VARCHAR(2048) NOT NULL,
    title VARCHAR(500),
    last_scanned_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, url)
);

-- Scans table for tracking accessibility scans
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    scan_id VARCHAR(255) UNIQUE NOT NULL, -- External scan ID from frontend
    status VARCHAR(50) DEFAULT 'pending',
    total_violations INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    serious_count INTEGER DEFAULT 0,
    moderate_count INTEGER DEFAULT 0,
    minor_count INTEGER DEFAULT 0,
    pages_scanned INTEGER DEFAULT 0,
    scan_data JSONB, -- Store full scan results
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Alt Text AI Jobs table for tracking generation jobs
CREATE TABLE IF NOT EXISTS alt_text_jobs (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    website_url VARCHAR(2048) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending', -- pending, processing, completed, failed
    total_images INTEGER DEFAULT 0,
    processed_images INTEGER DEFAULT 0,
    failed_images INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Alt Text Suggestions table for storing AI-generated suggestions
CREATE TABLE IF NOT EXISTS alt_text_suggestions (
    id SERIAL PRIMARY KEY,
    job_id INTEGER NOT NULL REFERENCES alt_text_jobs(id) ON DELETE CASCADE,
    image_url VARCHAR(2048) NOT NULL,
    image_selector VARCHAR(1000), -- CSS selector for the image
    page_url VARCHAR(2048) NOT NULL,
    page_title VARCHAR(500),
    page_context TEXT, -- Surrounding text context
    suggestion_1 TEXT,
    suggestion_2 TEXT,
    suggestion_3 TEXT,
    confidence_1 DECIMAL(3,2), -- 0.00 to 1.00
    confidence_2 DECIMAL(3,2),
    confidence_3 DECIMAL(3,2),
    is_decorative BOOLEAN DEFAULT FALSE,
    selected_suggestion INTEGER, -- 1, 2, 3, or null
    user_feedback TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Image Cache table for avoiding duplicate processing
CREATE TABLE IF NOT EXISTS image_cache (
    id SERIAL PRIMARY KEY,
    image_url VARCHAR(2048) NOT NULL,
    url_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA-256 hash of URL
    image_data BYTEA, -- Cached image data
    content_type VARCHAR(100),
    file_size INTEGER,
    width INTEGER,
    height INTEGER,
    alt_suggestions JSONB, -- Cached AI suggestions
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- API Usage Analytics table for monitoring and billing
CREATE TABLE IF NOT EXISTS api_usage (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    job_id INTEGER REFERENCES alt_text_jobs(id) ON DELETE SET NULL,
    api_type VARCHAR(50) NOT NULL, -- 'openai_vision', 'openai_chat', etc.
    tokens_used INTEGER,
    cost_usd DECIMAL(10,6), -- Cost in USD
    request_data JSONB,
    response_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- User Settings table for preferences
CREATE TABLE IF NOT EXISTS user_settings (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alt_text_style VARCHAR(50) DEFAULT 'descriptive', -- descriptive, concise, technical
    include_decorative BOOLEAN DEFAULT TRUE,
    max_alt_length INTEGER DEFAULT 125,
    preferred_language VARCHAR(10) DEFAULT 'en',
    email_notifications BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_websites_user_id ON websites(user_id);
CREATE INDEX IF NOT EXISTS idx_websites_url ON websites(url);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_user_id ON alt_text_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_job_id ON alt_text_jobs(job_id);
CREATE INDEX IF NOT EXISTS idx_alt_text_jobs_status ON alt_text_jobs(status);
CREATE INDEX IF NOT EXISTS idx_alt_text_suggestions_job_id ON alt_text_suggestions(job_id);
CREATE INDEX IF NOT EXISTS idx_alt_text_suggestions_image_url ON alt_text_suggestions(image_url);
CREATE INDEX IF NOT EXISTS idx_image_cache_url_hash ON image_cache(url_hash);
CREATE INDEX IF NOT EXISTS idx_image_cache_accessed_at ON image_cache(accessed_at);
CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_created_at ON api_usage(created_at);

-- Create triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_websites_updated_at BEFORE UPDATE ON websites FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_alt_text_jobs_updated_at BEFORE UPDATE ON alt_text_jobs FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_alt_text_suggestions_updated_at BEFORE UPDATE ON alt_text_suggestions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_user_settings_updated_at BEFORE UPDATE ON user_settings FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default user settings for existing users
INSERT INTO user_settings (user_id)
SELECT id FROM users
WHERE id NOT IN (SELECT user_id FROM user_settings)
ON CONFLICT (user_id) DO NOTHING;
