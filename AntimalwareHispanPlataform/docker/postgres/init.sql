-- Initialization script for PostgreSQL
-- Crea extensiones necesarias y configura database

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";        -- UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";         -- Cryptographic functions
CREATE EXTENSION IF NOT EXISTS "pg_trgm";          -- Trigram similarity (full-text search)
CREATE EXTENSION IF NOT EXISTS "vector";           -- pgvector for RAG (AI embeddings)
-- Note: pgvector requires manual installation, see https://github.com/pgvector/pgvector

-- Create schema for multi-tenant isolation (opcional, usar public por ahora)
-- CREATE SCHEMA IF NOT EXISTS tenant_data;

-- Set timezone
SET timezone = 'UTC';

-- Enable Row Level Security globally (will be set per table)
-- Las policies se crean en Alembic migrations

COMMENT ON DATABASE antimalware_db IS 'AntimalwareHispan Platform - Multi-tenant malware analysis SaaS';
