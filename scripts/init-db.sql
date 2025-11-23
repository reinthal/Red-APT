-- Kill Chain Database Initialization
-- This script runs automatically when the PostgreSQL container starts

-- Create the assets table
CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    phase TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    search_vector TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('english', coalesce(value, '') || ' ' || coalesce(context, ''))
    ) STORED
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_assets_session ON assets(session_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
CREATE INDEX IF NOT EXISTS idx_assets_phase ON assets(phase);
CREATE INDEX IF NOT EXISTS idx_assets_created ON assets(created_at DESC);

-- GIN index for full-text search
CREATE INDEX IF NOT EXISTS idx_assets_search ON assets USING GIN(search_vector);

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO redapt;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO redapt;
