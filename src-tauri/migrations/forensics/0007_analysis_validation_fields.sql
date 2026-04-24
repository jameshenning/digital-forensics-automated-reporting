-- migration 0007: validation principles on analysis_notes
--
-- Adds four nullable columns to `analysis_notes` so each finding carries
-- the methodology context that stands up to cross-examination:
--   created_by             — who authored the finding (peer review is
--                            meaningless without author attribution)
--   method_reference       — SOP or standard cited (NIST SP 800-86 §X,
--                            internal SOP-FRA-007, etc.)
--   alternatives_considered — other explanations examined and ruled out
--   tool_version           — tool + version that produced the finding
--                            (mirrors identifiers.discovered_via_tool
--                            for parallel provenance across tables)
--
-- All four are nullable; existing v1 rows keep NULLs. The UI renders
-- a "not recorded" placeholder for missing created_by so v1 data is
-- handled honestly rather than silently backfilled.
--
-- Also creates an APPEND-ONLY `analysis_reviews` table for peer-review
-- stamping. A bounded UPDATE on analysis_notes would overwrite prior
-- reviewers and break the "this app never mutates analytical records"
-- invariant — a separate table preserves that narrative and naturally
-- supports multi-reviewer workflows.

ALTER TABLE analysis_notes ADD COLUMN created_by TEXT;
ALTER TABLE analysis_notes ADD COLUMN method_reference TEXT;
ALTER TABLE analysis_notes ADD COLUMN alternatives_considered TEXT;
ALTER TABLE analysis_notes ADD COLUMN tool_version TEXT;

CREATE TABLE IF NOT EXISTS analysis_reviews (
    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL REFERENCES analysis_notes(note_id),
    reviewed_by TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,      -- ISO 'YYYY-MM-DD HH:MM:SS' or 'YYYY-MM-DDTHH:MM:SS', v1-compat String
    review_notes TEXT,              -- what the reviewer observed / concurred with / flagged
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_analysis_reviews_note
    ON analysis_reviews(note_id);
