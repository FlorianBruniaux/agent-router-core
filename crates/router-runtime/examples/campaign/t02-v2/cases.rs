include!("lib.rs");
#[test]
fn t02_v2_empty() {
    assert_eq!(score(17, &[], &[], &[]), Ok(17));
}
#[test]
fn t02_v2_sum_before_division() {
    assert_eq!(score(100, &[3, 3], &[9, 9], &[19, 19]), Ok(99));
}
#[test]
fn t02_v2_negative_quality() {
    assert_eq!(score(-7, &[4], &[10], &[20]), Ok(-8));
}
#[test]
fn t02_v2_cost_limit() {
    assert_eq!(score(0, &[0; 65], &[], &[]), Err("work_limit"));
}
#[test]
fn t02_v2_latency_limit() {
    assert_eq!(score(0, &[], &[0; 65], &[]), Err("work_limit"));
}
#[test]
fn t02_v2_skill_limit() {
    assert_eq!(score(0, &[], &[], &[0; 65]), Err("work_limit"));
}
#[test]
fn t02_v2_exact_work_boundary() {
    assert_eq!(score(10, &[4; 64], &[10; 64], &[20; 64]), Ok(-54));
}
#[test]
fn t02_v2_wide_sums() {
    assert_eq!(score(0, &[u64::MAX; 2], &[], &[]), Ok(-9223372036854775807));
}
#[test]
fn t02_v2_negative_overflow() {
    assert_eq!(score(i64::MIN, &[4], &[], &[]), Err("score_out_of_range"));
}
#[test]
fn t02_v2_positive_overflow() {
    assert_eq!(score(i64::MAX, &[], &[], &[20]), Err("score_out_of_range"));
}
#[test]
fn t02_v2_cancellation_before_range_check() {
    assert_eq!(score(0, &[u64::MAX; 12], &[], &[u64::MAX; 60]), Ok(0));
}
#[test]
fn t02_v2_extrema_identity() {
    assert_eq!(score(i64::MIN, &[], &[], &[]), Ok(i64::MIN));
    assert_eq!(score(i64::MAX, &[], &[], &[]), Ok(i64::MAX));
}

#[test]
fn t02_v2_cost_above_u64() {
    assert_eq!(
        score(0, &[u64::MAX, 1], &[], &[]),
        Ok(-4_611_686_018_427_387_904)
    );
}
#[test]
fn t02_v2_latency_above_u64() {
    assert_eq!(
        score(0, &[], &[u64::MAX, 1], &[]),
        Ok(-1_844_674_407_370_955_161)
    );
}
#[test]
fn t02_v2_skill_above_u64() {
    assert_eq!(
        score(0, &[], &[], &[u64::MAX, 1]),
        Ok(922_337_203_685_477_580)
    );
}
#[test]
fn t02_v2_round_cost() {
    assert_eq!(score(0, &[3, 1], &[], &[]), Ok(-1));
}
#[test]
fn t02_v2_round_latency() {
    assert_eq!(score(0, &[], &[9, 1], &[]), Ok(-1));
}
#[test]
fn t02_v2_round_skill() {
    assert_eq!(score(0, &[], &[], &[19, 1]), Ok(1));
}
