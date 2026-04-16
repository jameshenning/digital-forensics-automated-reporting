-- migration 0006: discovered_via_tool on identifier tables
--
-- Adds a dedicated column to person_identifiers + business_identifiers that
-- records which OSINT tool surfaced each auto-discovered row. Prior to this
-- migration the tool name was only visible embedded in the `notes` string
-- via the "Auto-discovered via OSINT <tool> on <date>" stamp. Storing it as
-- its own column lets the UI render a per-row source badge with a popover
-- that pulls the tool description from the forensic-tools KB, and makes the
-- provenance queryable for future per-tool reporting without string parsing.
--
-- Manual identifiers keep `discovered_via_tool = NULL` so the UI can show
-- the badge only for auto-discovered rows.

ALTER TABLE person_identifiers ADD COLUMN discovered_via_tool TEXT;
ALTER TABLE business_identifiers ADD COLUMN discovered_via_tool TEXT;

-- Backfill existing auto-discovered rows by parsing the tool name out of
-- the standard notes stamp.  Format: "Auto-discovered via OSINT <tool> on <date>".
-- The 26-character literal prefix "Auto-discovered via OSINT " (including the
-- trailing space) is stripped, and the tool name runs up to the next " on ".
-- No tool name contains " on ", so the first occurrence of that delimiter is
-- always the end marker.
UPDATE person_identifiers
SET discovered_via_tool = TRIM(SUBSTR(
    notes,
    INSTR(notes, 'Auto-discovered via OSINT ') + 26,
    INSTR(notes, ' on ') - (INSTR(notes, 'Auto-discovered via OSINT ') + 26)
))
WHERE notes LIKE 'Auto-discovered via OSINT % on %'
  AND discovered_via_tool IS NULL;

UPDATE business_identifiers
SET discovered_via_tool = TRIM(SUBSTR(
    notes,
    INSTR(notes, 'Auto-discovered via OSINT ') + 26,
    INSTR(notes, ' on ') - (INSTR(notes, 'Auto-discovered via OSINT ') + 26)
))
WHERE notes LIKE 'Auto-discovered via OSINT % on %'
  AND discovered_via_tool IS NULL;

CREATE INDEX IF NOT EXISTS idx_person_identifiers_discovered_via_tool
    ON person_identifiers(discovered_via_tool);
CREATE INDEX IF NOT EXISTS idx_business_identifiers_discovered_via_tool
    ON business_identifiers(discovered_via_tool);
