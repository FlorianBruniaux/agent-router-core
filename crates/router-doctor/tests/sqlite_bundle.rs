use rusqlite::{Connection, params};

#[test]
fn bundled_engine_is_the_pinned_wal_reset_fixed_release() -> rusqlite::Result<()> {
    let db = Connection::open_in_memory()?;
    let (version, source): (String, String) =
        db.query_row("SELECT sqlite_version(), sqlite_source_id()", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    // Checks the linked engine, not a manifest string or a WAL-reset reproducer.
    assert_eq!(version, "3.51.3");
    assert_eq!(rusqlite::version_number(), 3_051_003);
    assert_eq!(
        source,
        "2026-03-13 10:38:09 737ae4a34738ffa0c3ff7f9bb18df914dd1cad163f28fd6b6e114a344fe6d618"
    );
    Ok(())
}

#[test]
fn unsigned_sql_values_roundtrip_without_wrapping_or_accepting_negative_values()
-> rusqlite::Result<()> {
    let db = Connection::open_in_memory()?;
    db.execute_batch("CREATE TABLE amounts(value INTEGER NOT NULL)")?;
    for value in [0_u64, 60, i64::MAX as u64] {
        db.execute("INSERT INTO amounts VALUES(?1)", params![value])?;
        let stored: u64 = db.query_row(
            "SELECT value FROM amounts ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(stored, value);
    }
    for value in [i64::MAX as u64 + 1, u64::MAX] {
        assert!(
            db.execute("INSERT INTO amounts VALUES(?1)", params![value])
                .is_err()
        );
    }
    let count: usize = db.query_row("SELECT COUNT(*) FROM amounts", [], |row| row.get(0))?;
    assert_eq!(count, 3, "rejected unsigned values must not mutate storage");
    assert!(
        db.query_row("SELECT -1", [], |row| row.get::<_, u64>(0))
            .is_err()
    );
    assert!(
        db.query_row("SELECT -1", [], |row| row.get::<_, usize>(0))
            .is_err()
    );
    let count_roundtrip: usize = db.query_row("SELECT ?1", [count], |row| row.get(0))?;
    assert_eq!(count_roundtrip, count);
    Ok(())
}
