-- SentryPrime Database Schema V2
-- Includes tables for users, websites, scans, and the full Alt Text AI feature set.

-- Drop existing tables in reverse order of dependency to ensure clean migration
DROP TABLE IF EXISTS alt_text_suggestions CASCADE;
DROP TABLE IF EXISTS alt_text_jobs CASCADE;
DROP TABLE IF EXISTS image_cache CASCADE;
DROP TABLE IF EXISTS api_usage CASCADE;
DROP TABLE IF EXISTS user_settings CASCADE;
DROP TABLE IF EXISTS scans CASCADE;
DROP TABLE IF EXISTS websites CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Drop existing functions and triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_websites_updated_at ON websites;
DROP TRIGGER IF EXISTS update_scans_updated_at ON scans;
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Create a function to automatically update the 'updated_at' timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ language 'plpgsql';

-- 1. Users Table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE INDEX idx_users_email ON users(email);

-- 2. Websites Table
CREATE TABLE websites (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url VARCHAR(2048) NOT NULL,
    name VARCHAR(255), -- ✅ FIXED: Added the missing 'name' column
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TRIGGER update_websites_updated_at BEFORE UPDATE ON websites FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE INDEX idx_websites_user_id ON websites(user_id);

-- 3. Scans Table
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    url VARCHAR(2048) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- e.g., pending, running, done, error
    scan_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_violations INTEGER DEFAULT 0,
    pages_scanned INTEGER DEFAULT 0,
    compliance_score NUMERIC(5, 2) DEFAULT 0.00, -- ✅ FIXED: Added the missing 'compliance_score' column
    scan_results JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scanned_at TIMESTAMPTZ
);
CREATE TRIGGER update_scans_updated_at BEFORE UPDATE ON scans FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();
CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_website_id ON scans(website_id);
CREATE INDEX idx_scans_status ON scans(status);

-- 4. Alt Text AI Jobs Table
CREATE TABLE alt_text_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    website_id INTEGER NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- pending, processing, completed, failed, cancelled
    progress INTEGER NOT NULL DEFAULT 0,
    total_images INTEGER NOT NULL DEFAULT 0,
    processed_images INTEGER NOT NULL DEFAULT 0,
    cost_estimate NUMERIC(10, 6),
    actual_cost NUMERIC(10, 6),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_alt_text_jobs_user_id ON alt_text_jobs(user_id);
CREATE INDEX idx_alt_text_jobs_status ON alt_text_jobs(status);

-- 5. Alt Text Suggestions Table
CREATE TABLE alt_text_suggestions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES alt_text_jobs(id) ON DELETE CASCADE,
    image_url TEXT NOT NULL,
    text TEXT NOT NULL,
    confidence NUMERIC(5, 4),
    type VARCHAR(50), -- e.g., concise, detailed, decorative
    is_selected BOOLEAN DEFAULT FALSE,
    feedback TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_alt_text_suggestions_job_id ON alt_text_suggestions(job_id);
CREATE INDEX idx_alt_text_suggestions_image_url ON alt_text_suggestions(image_url);

-- 6. Image Cache Table
CREATE TABLE image_cache (
    image_hash VARCHAR(64) PRIMARY KEY,
    image_url TEXT NOT NULL,
    alt_text_suggestions JSONB,
    last_accessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_image_cache_last_accessed ON image_cache(last_accessed_at);

-- 7. API Usage Table
CREATE TABLE api_usage (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    feature VARCHAR(100) NOT NULL, -- e.g., 'alt_text_ai', 'scan'
    tokens_used INTEGER,
    images_processed INTEGER,
    cost NUMERIC(10, 6),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX idx_api_usage_feature ON api_usage(feature);

-- 8. User Settings Table
CREATE TABLE user_settings (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
