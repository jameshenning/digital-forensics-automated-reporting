-- migration 0009: validation levels (0-4) on analysis_notes
--
-- Adds a mandatory INTEGER column `validation_level` with CHECK constraint.
-- Existing rows are backfilled to 0 (Unvalidated) because every prior finding
-- was created before this framework existed — honest provenance requires
-- admitting they were not independently validated.
--
-- Levels per the DFIR Forensic Validation methodology:
--   0 = Unvalidated        — not independently validated; AI/tool output only
--   1 = Tool-Validated     — validated against known-good dataset or hash
--   2 = Cross-Validated    — corroborated by a secondary method or tool
--   3 = Examiner-Validated — manual verification by the primary examiner
--   4 = Peer-Reviewed      — independently validated by a second examiner
--
-- The UI enforces that a finding at level 0 cannot be added to a final
-- report without an explicit override + justification (master prompt §2a
-- hard rule). This column makes that check possible.

ALTER TABLE analysis_notes ADD COLUMN validation_level INTEGER NOT NULL DEFAULT 0 CHECK (validation_level BETWEEN 0 AND 4);

-- Existing v1/v2 rows were created before validation levels existed.
-- They remain at the DEFAULT 0 (Unvalidated) — honest provenance.
-- No UPDATE needed because DEFAULT handles the backfill.
