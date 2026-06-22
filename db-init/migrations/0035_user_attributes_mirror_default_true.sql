-- migration-safety: ignore (default flip on column added in 0033; feature branch unmerged)
-- Flip the default on tenant_attribute_config.mirror_from_idp from FALSE to TRUE.
--
-- Rationale: tenants overwhelmingly want IdP-sourced standard attributes to
-- persist into the canonical user profile. The conservative info-only default
-- introduced in 0034 (and then subsequently folded into 0033, in 119d1eb
-- explaining the absence of 0034 in the code-base) made enabling an attribute
-- a two-step operation. The new default is "mirror IdP values into the user
-- profile" so that enabling an attribute does the obvious thing.
--
-- Backfill UPDATE is safe because the feature branch is unmerged and 0034
-- only ran on dev databases. Any tenant that has explicitly turned mirror
-- back off after seeing this migration land is responsible for re-toggling
-- in tenant settings; that is acceptable for an unreleased feature.

SET LOCAL ROLE appowner;

ALTER TABLE tenant_attribute_config
    ALTER COLUMN mirror_from_idp SET DEFAULT TRUE;

UPDATE tenant_attribute_config
SET mirror_from_idp = TRUE
WHERE mirror_from_idp = FALSE;
