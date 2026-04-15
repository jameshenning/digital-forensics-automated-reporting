-- Add reproduction-tracking columns to tool_usage.
--
-- Forensic reproducibility: a second examiner should be able to read the
-- report, run the same tool against the same input, and arrive at the same
-- result. These columns capture the four pieces of operator-supplied data
-- that make that possible alongside the curated KB steps in
-- src-tauri/src/forensic_tools.rs.
--
--   input_sha256        — SHA-256 of the input file at run time. Lets the
--                         reproducing examiner verify they have the same
--                         bytes the original examiner used. Hex string,
--                         no leading 0x.
--   output_sha256       — SHA-256 of the output file (or transcript).
--                         Lets the reproducing examiner verify their result
--                         matches the original.
--   environment_notes   — Free-text. Operator records OS, Kali version,
--                         binary path, library versions, anything that
--                         affects determinism.
--   reproduction_notes  — Free-text. Operator's case-specific tips,
--                         pitfalls, and deviations from the curated KB
--                         steps. Renders BELOW the KB steps in the UI
--                         and in the forensic report.
--
-- All four columns are nullable — fields are optional so case-wide tool
-- runs (where there is no single input file, like an OSINT scan against a
-- person's known fields) can omit them.

ALTER TABLE tool_usage ADD COLUMN input_sha256 TEXT;
ALTER TABLE tool_usage ADD COLUMN output_sha256 TEXT;
ALTER TABLE tool_usage ADD COLUMN environment_notes TEXT;
ALTER TABLE tool_usage ADD COLUMN reproduction_notes TEXT;
