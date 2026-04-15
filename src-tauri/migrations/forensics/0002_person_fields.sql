-- Add Person-specific columns to the entities table.
--
-- These columns are only meaningful when entity_type = 'person', but we add
-- them at the table level (not a separate persons table) because:
--   1. The existing entities CRUD, link analysis, and soft-delete cascade all
--      work for every entity type — no need to duplicate.
--   2. The frontend already conditions subtype + organizational_rank on
--      entity_type === 'person'. These new columns follow the same pattern.
--
-- All columns are nullable — non-person entity rows simply leave them NULL.
--
-- Storage: photo_path holds an absolute filesystem path to a file under
-- %APPDATA%\DFARS\person_photos\<case_id>\. Photos are NOT evidence; they're
-- identifying metadata and live outside the chain-of-custody audit tree.

ALTER TABLE entities ADD COLUMN photo_path TEXT;
ALTER TABLE entities ADD COLUMN email TEXT;
ALTER TABLE entities ADD COLUMN phone TEXT;
ALTER TABLE entities ADD COLUMN username TEXT;
ALTER TABLE entities ADD COLUMN employer TEXT;
ALTER TABLE entities ADD COLUMN dob TEXT;
