-- migration 0008: attribution principles on entity_links + identifiers
--
-- Phase B of the cross-examination methodology rollout. Phase A (migration
-- 0007) baked validation/peer-review structure into analysis_notes. Phase B
-- extends the same accountability primitives to the *attribution* surface:
-- every assertion that "X is connected to Y" or "this email belongs to this
-- person" must now carry the basis of the attribution, who made the call,
-- and what level of confidence/verification supports it.
--
-- All columns are nullable. Existing v1 rows keep NULLs; the UI/report layer
-- renders a "not recorded" placeholder so v1 data is presented honestly
-- rather than silently backfilled.
--
-- entity_links (why is this connection asserted?):
--   attributed_by           — investigator who asserted the link
--   basis                   — short narrative ("shared email in evidence
--                             E-001", "subject named target as employer")
--   confidence_level        — low | medium | high (enforced at app layer)
--   method_reference        — SOP / standard cited (NIST SP 800-86 §X,
--                             internal SOP-FRA-007, etc.)
--   alternatives_considered — competing explanations examined and ruled out
--   evidence_refs           — freeform reference list ("E-001, E-007").
--                             Kept text rather than a join table until real-
--                             case use forces structure.
--
-- person_identifiers + business_identifiers (why does this identifier belong
-- to this entity?):
--   attributed_by      — investigator who asserted the link
--   attribution_basis  — narrative for HOW the identifier was attributed
--                        ("self-reported in intake", "OSINT via whois")
--   confidence_level   — low | medium | high
--   verification_status — unverified | tentative | confirmed.
--                         Distinct from confidence: did anyone independently
--                         corroborate? An identifier can be high-confidence
--                         (came from a strong source) but unverified (no
--                         second independent corroboration yet).
--
-- No new review tables — peer-review is overkill for factual links and
-- identifiers; verification status is the right primitive. Compare with
-- migration 0007 which created an append-only analysis_reviews table because
-- analytical *findings* carry interpretive weight that benefits from a
-- multi-reviewer history.

ALTER TABLE entity_links ADD COLUMN attributed_by TEXT;
ALTER TABLE entity_links ADD COLUMN basis TEXT;
ALTER TABLE entity_links ADD COLUMN confidence_level TEXT;
ALTER TABLE entity_links ADD COLUMN method_reference TEXT;
ALTER TABLE entity_links ADD COLUMN alternatives_considered TEXT;
ALTER TABLE entity_links ADD COLUMN evidence_refs TEXT;

ALTER TABLE person_identifiers ADD COLUMN attributed_by TEXT;
ALTER TABLE person_identifiers ADD COLUMN attribution_basis TEXT;
ALTER TABLE person_identifiers ADD COLUMN confidence_level TEXT;
ALTER TABLE person_identifiers ADD COLUMN verification_status TEXT;

ALTER TABLE business_identifiers ADD COLUMN attributed_by TEXT;
ALTER TABLE business_identifiers ADD COLUMN attribution_basis TEXT;
ALTER TABLE business_identifiers ADD COLUMN confidence_level TEXT;
ALTER TABLE business_identifiers ADD COLUMN verification_status TEXT;
