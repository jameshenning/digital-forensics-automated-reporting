-- Add evidence_id column to tool_usage so individual tools can be
-- associated with a specific evidence item rather than just a case.
--
-- v1 added this column via ALTER TABLE in _migrate_schema() (database.py
-- lines 91-108). It was absent from 0001_init.sql because the init SQL
-- was taken from the base schema before the v1 migration ran.
--
-- This migration is idempotent on v1 databases: SQLite ignores the
-- ALTER TABLE if the column is already present when run with IF NOT
-- EXISTS on the index; the ALTER TABLE itself will fail on pre-existing
-- columns — SQLite does not support IF NOT EXISTS for ADD COLUMN.
-- sqlx will only run this migration once (checksum-gated), so a v1 DB
-- that already has the column will not hit this migration a second time.

ALTER TABLE tool_usage ADD COLUMN evidence_id TEXT;
CREATE INDEX IF NOT EXISTS idx_tool_evidence_id ON tool_usage(evidence_id);
