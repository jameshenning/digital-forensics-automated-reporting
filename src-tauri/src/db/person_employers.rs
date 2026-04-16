/// person_employers — atomic "set employer list" for a person entity.
///
/// Replaces any prior `employs` entity_links with exactly the requested set,
/// auto-creates stub business entities for free-text names, and rebuilds the
/// `entities.employer` rollup column on the person row.
///
/// All work runs inside a single SQLite transaction so the graph and the
/// person row are always consistent.
use sqlx::SqlitePool;

use crate::error::AppError;

// ── Validation constants ───────────────────────────────────────────────────────

/// Mirrors `DISPLAY_NAME_MAX_LEN` in `db::entities`.
const DISPLAY_NAME_MAX_LEN: usize = 200;

// ── Public entry point ─────────────────────────────────────────────────────────

/// Atomically set the complete list of employers for a person.  Replaces any
/// prior `employs` entity_links and auto-creates stub business entities for
/// free-text names that don't yet exist.
///
/// Steps (all inside one transaction):
///   1. Verify the person entity exists, is active, and is `entity_type='person'`.
///   2. Validate + dedup `existing_business_ids`; verify each is an active
///      business in the same case.
///   3. Validate `new_business_names`; create a stub business entity for each.
///   4. Soft-delete all current `employs` links targeting this person.
///   5. INSERT fresh links for the merged set of business entity ids.
///   6. UPDATE `entities.employer` to a comma-separated rollup (ASC).
///
/// Returns the final `(business_entity_id, display_name)` list.
pub async fn set_person_employers(
    pool: &SqlitePool,
    person_entity_id: i64,
    existing_business_ids: &[i64],
    new_business_names: &[String],
) -> Result<Vec<(i64, String)>, AppError> {
    // ── Step 1: verify person ─────────────────────────────────────────────────
    let person_row: Option<(String, String)> = sqlx::query_as(
        "SELECT case_id, entity_type FROM entities WHERE entity_id = ? AND is_deleted = 0",
    )
    .bind(person_entity_id)
    .fetch_optional(pool)
    .await?;

    let (case_id, entity_type) = person_row.ok_or(AppError::EntityNotFound {
        entity_id: person_entity_id,
    })?;

    if entity_type != "person" {
        return Err(AppError::EntityNotAPerson {
            entity_id: person_entity_id,
            entity_type,
        });
    }

    // ── Step 2: validate + dedup existing_business_ids ────────────────────────
    let mut seen_ids: Vec<i64> = Vec::new();
    for &biz_id in existing_business_ids {
        if seen_ids.contains(&biz_id) {
            continue; // dedup: first-seen wins
        }
        seen_ids.push(biz_id);

        let biz_row: Option<(String, String)> = sqlx::query_as(
            "SELECT case_id, entity_type FROM entities WHERE entity_id = ? AND is_deleted = 0",
        )
        .bind(biz_id)
        .fetch_optional(pool)
        .await?;

        match biz_row {
            None => {
                return Err(AppError::ValidationError {
                    field: "existing_business_ids".into(),
                    message: format!(
                        "business entity_id={biz_id} does not exist or has been deleted"
                    ),
                });
            }
            Some((biz_case_id, biz_type)) => {
                if biz_case_id != case_id {
                    return Err(AppError::ValidationError {
                        field: "existing_business_ids".into(),
                        message: format!(
                            "business entity_id={biz_id} belongs to case '{biz_case_id}', \
                             not to the person's case '{case_id}'"
                        ),
                    });
                }
                if biz_type != "business" {
                    return Err(AppError::ValidationError {
                        field: "existing_business_ids".into(),
                        message: format!(
                            "entity_id={biz_id} is not a business (entity_type='{biz_type}')"
                        ),
                    });
                }
            }
        }
    }

    // ── Step 3: validate free-text names ──────────────────────────────────────
    let mut validated_names: Vec<String> = Vec::new();
    for raw in new_business_names {
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            continue; // skip blanks
        }
        if trimmed.starts_with('-') {
            return Err(AppError::ValidationError {
                field: "new_business_names".into(),
                message: format!(
                    "Business name '{trimmed}' starts with '-', which is \
                     rejected for argv-injection safety (CWE-88)"
                ),
            });
        }
        if trimmed.chars().count() > DISPLAY_NAME_MAX_LEN {
            return Err(AppError::ValidationError {
                field: "new_business_names".into(),
                message: format!(
                    "Business name exceeds {DISPLAY_NAME_MAX_LEN} character limit"
                ),
            });
        }
        validated_names.push(trimmed);
    }

    // ── Begin transaction ──────────────────────────────────────────────────────
    let mut tx = pool.begin().await?;

    // ── Step 3 (cont): insert stub business entities ───────────────────────────
    let mut new_biz_ids: Vec<(i64, String)> = Vec::new();
    for name in &validated_names {
        let new_biz: (i64,) = sqlx::query_as(
            r#"
            INSERT INTO entities (
                case_id, entity_type, display_name, notes
            ) VALUES (?, 'business', ?, 'Auto-created from person employer input')
            RETURNING entity_id
            "#,
        )
        .bind(&case_id)
        .bind(name)
        .fetch_one(&mut *tx)
        .await?;
        new_biz_ids.push((new_biz.0, name.clone()));
    }

    // ── Step 4: soft-delete all existing employs links targeting this person ───
    let person_id_str = person_entity_id.to_string();
    sqlx::query(
        r#"
        UPDATE entity_links
        SET is_deleted = 1
        WHERE link_label = 'employs'
          AND is_deleted = 0
          AND target_type = 'entity'
          AND target_id = ?
        "#,
    )
    .bind(&person_id_str)
    .execute(&mut *tx)
    .await?;

    // ── Step 5: insert fresh links ─────────────────────────────────────────────
    // Merge: validated existing ids + newly created ids.
    let all_biz: Vec<(i64, String)> = {
        // Fetch display_names for existing ids in one go.
        let mut v: Vec<(i64, String)> = Vec::new();
        for &biz_id in &seen_ids {
            let name: (String,) = sqlx::query_as(
                "SELECT display_name FROM entities WHERE entity_id = ?",
            )
            .bind(biz_id)
            .fetch_one(&mut *tx)
            .await?;
            v.push((biz_id, name.0));
        }
        v.extend(new_biz_ids);
        v
    };

    for (biz_id, _) in &all_biz {
        sqlx::query(
            r#"
            INSERT INTO entity_links (
                case_id, source_type, source_id,
                target_type, target_id,
                link_label, directional, weight
            ) VALUES (?, 'entity', CAST(? AS TEXT),
                      'entity', CAST(? AS TEXT),
                      'employs', 1, 1.0)
            "#,
        )
        .bind(&case_id)
        .bind(biz_id)
        .bind(person_entity_id)
        .execute(&mut *tx)
        .await?;
    }

    // ── Step 6: rebuild employer rollup on the person row ─────────────────────
    let rollup: Option<String> = if all_biz.is_empty() {
        None
    } else {
        // Sort names alphabetically for a stable rollup string.
        let mut names: Vec<&str> = all_biz.iter().map(|(_, n)| n.as_str()).collect();
        names.sort_unstable();
        Some(names.join(", "))
    };

    sqlx::query(
        "UPDATE entities SET employer = ?, updated_at = CURRENT_TIMESTAMP WHERE entity_id = ?",
    )
    .bind(&rollup)
    .bind(person_entity_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    // Return the final list sorted by display_name for stable output.
    let mut result = all_biz;
    result.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(result)
}

// ── Unit tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::test_forensics_db_with_schema as make_forensics_pool;
    use sqlx::SqlitePool;

    // ── Seed helpers ──────────────────────────────────────────────────────────

    async fn seed_case(pool: &SqlitePool, case_id: &str) {
        sqlx::query(
            "INSERT INTO cases (case_id, case_name, investigator, start_date) \
             VALUES (?, ?, 'Tester', '2025-01-01')",
        )
        .bind(case_id)
        .bind(format!("Case {case_id}"))
        .execute(pool)
        .await
        .expect("seed_case failed");
    }

    async fn seed_entity(pool: &SqlitePool, case_id: &str, name: &str, etype: &str) -> i64 {
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO entities (case_id, entity_type, display_name) \
             VALUES (?, ?, ?) RETURNING entity_id",
        )
        .bind(case_id)
        .bind(etype)
        .bind(name)
        .fetch_one(pool)
        .await
        .expect("seed_entity failed");
        row.0
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Happy path: two businesses linked to a person; assert links + rollup.
    #[tokio::test]
    async fn set_employers_creates_links_and_rollup() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-01").await;
        let person_id = seed_entity(&pool, "EMP-01", "John Doe", "person").await;
        let biz1 = seed_entity(&pool, "EMP-01", "Acme Corp", "business").await;
        let biz2 = seed_entity(&pool, "EMP-01", "Beta LLC", "business").await;

        let result = set_person_employers(&pool, person_id, &[biz1, biz2], &[])
            .await
            .expect("should succeed");

        assert_eq!(result.len(), 2);

        // Assert entity_links rows
        let link_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM entity_links \
             WHERE link_label='employs' AND is_deleted=0 \
               AND target_type='entity' AND target_id=CAST(? AS TEXT)",
        )
        .bind(person_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(link_count.0, 2);

        // Assert employer rollup
        let employer: (Option<String>,) =
            sqlx::query_as("SELECT employer FROM entities WHERE entity_id=?")
                .bind(person_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(employer.0.as_deref(), Some("Acme Corp, Beta LLC"));
    }

    /// Replace: start with 2 links, replace with 1 existing + 1 new.
    #[tokio::test]
    async fn set_employers_replaces_existing_links() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-02").await;
        let person_id = seed_entity(&pool, "EMP-02", "Jane Doe", "person").await;
        let biz1 = seed_entity(&pool, "EMP-02", "Alpha Inc", "business").await;
        let biz2 = seed_entity(&pool, "EMP-02", "Beta LLC", "business").await;

        // Initial state: both businesses linked
        set_person_employers(&pool, person_id, &[biz1, biz2], &[])
            .await
            .expect("initial set failed");

        // Replace: keep biz1, drop biz2, add "Gamma Co"
        let result = set_person_employers(&pool, person_id, &[biz1], &["Gamma Co".to_string()])
            .await
            .expect("replacement set failed");

        assert_eq!(result.len(), 2); // biz1 + new Gamma Co

        // Active links = 2
        let active: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM entity_links \
             WHERE link_label='employs' AND is_deleted=0 \
               AND target_id=CAST(? AS TEXT)",
        )
        .bind(person_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active.0, 2);

        // Old (biz2) link is soft-deleted, not gone
        let deleted: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM entity_links \
             WHERE link_label='employs' AND is_deleted=1 \
               AND source_id=CAST(? AS TEXT)",
        )
        .bind(biz2)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(deleted.0, 1);
    }

    /// Calling against a business entity should return EntityNotAPerson.
    #[tokio::test]
    async fn set_employers_rejects_non_person() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-03").await;
        let biz_id = seed_entity(&pool, "EMP-03", "Acme Corp", "business").await;

        let err = set_person_employers(&pool, biz_id, &[], &[])
            .await
            .expect_err("should have failed with EntityNotAPerson");

        match err {
            AppError::EntityNotAPerson { entity_id, .. } => {
                assert_eq!(entity_id, biz_id);
            }
            other => panic!("expected EntityNotAPerson, got {other:?}"),
        }
    }

    /// Cross-case business should be rejected.
    #[tokio::test]
    async fn set_employers_rejects_cross_case_business() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-04A").await;
        seed_case(&pool, "EMP-04B").await;
        let person_id = seed_entity(&pool, "EMP-04A", "Alice", "person").await;
        let cross_biz = seed_entity(&pool, "EMP-04B", "Foreign Corp", "business").await;

        let err = set_person_employers(&pool, person_id, &[cross_biz], &[])
            .await
            .expect_err("should have failed with ValidationError");

        match err {
            AppError::ValidationError { field, .. } => {
                assert_eq!(field, "existing_business_ids");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    /// Free-text name creates a stub business entity in the person's case.
    #[tokio::test]
    async fn set_employers_creates_stub_business_from_free_text() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-05").await;
        let person_id = seed_entity(&pool, "EMP-05", "Bob", "person").await;

        let result = set_person_employers(&pool, person_id, &[], &["New Ventures LLC".to_string()])
            .await
            .expect("should succeed");

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, "New Ventures LLC");

        // The stub business entity must exist in the same case
        let biz: (String, String) = sqlx::query_as(
            "SELECT case_id, entity_type FROM entities WHERE entity_id=?",
        )
        .bind(result[0].0)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(biz.0, "EMP-05");
        assert_eq!(biz.1, "business");
    }

    /// Names starting with '-' must be rejected.
    #[tokio::test]
    async fn set_employers_rejects_leading_dash_name() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-06").await;
        let person_id = seed_entity(&pool, "EMP-06", "Charlie", "person").await;

        let err = set_person_employers(&pool, person_id, &[], &["-evil".to_string()])
            .await
            .expect_err("should reject leading dash");

        match err {
            AppError::ValidationError { field, .. } => {
                assert_eq!(field, "new_business_names");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    /// Names over 200 chars must be rejected.
    #[tokio::test]
    async fn set_employers_rejects_oversize_name() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-07").await;
        let person_id = seed_entity(&pool, "EMP-07", "Diana", "person").await;

        let long_name = "A".repeat(201);
        let err = set_person_employers(&pool, person_id, &[], &[long_name])
            .await
            .expect_err("should reject oversize name");

        match err {
            AppError::ValidationError { field, .. } => {
                assert_eq!(field, "new_business_names");
            }
            other => panic!("expected ValidationError, got {other:?}"),
        }
    }

    /// Empty arrays clear all employs links; employer column goes NULL.
    #[tokio::test]
    async fn set_employers_empty_clears_all() {
        let pool = make_forensics_pool().await;
        seed_case(&pool, "EMP-08").await;
        let person_id = seed_entity(&pool, "EMP-08", "Eve", "person").await;
        let biz1 = seed_entity(&pool, "EMP-08", "Corp A", "business").await;
        let biz2 = seed_entity(&pool, "EMP-08", "Corp B", "business").await;

        // Set two employers first
        set_person_employers(&pool, person_id, &[biz1, biz2], &[])
            .await
            .expect("initial set failed");

        // Clear all
        let result = set_person_employers(&pool, person_id, &[], &[])
            .await
            .expect("clear failed");
        assert_eq!(result.len(), 0);

        // All links should be soft-deleted
        let active: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM entity_links \
             WHERE link_label='employs' AND is_deleted=0 \
               AND target_id=CAST(? AS TEXT)",
        )
        .bind(person_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active.0, 0);

        // employer column is NULL
        let employer: (Option<String>,) =
            sqlx::query_as("SELECT employer FROM entities WHERE entity_id=?")
                .bind(person_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(employer.0.is_none());
    }
}
