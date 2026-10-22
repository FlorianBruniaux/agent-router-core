include!("lib.rs");
#[test] fn empty() { assert_eq!(score(17, &[], &[], &[]), Ok(17)); }
#[test] fn sum_before_division() { assert_eq!(score(100, &[3,3], &[9,9], &[19,19]), Ok(99)); }
#[test] fn negative_quality() { assert_eq!(score(-7, &[4], &[10], &[20]), Ok(-8)); }
#[test] fn cost_limit() { assert_eq!(score(0, &[0;65], &[], &[]), Err("work_limit")); }
#[test] fn latency_limit() { assert_eq!(score(0, &[], &[0;65], &[]), Err("work_limit")); }
#[test] fn skill_limit() { assert_eq!(score(0, &[], &[], &[0;65]), Err("work_limit")); }
#[test] fn exact_work_boundary() { assert_eq!(score(10, &[4;64], &[10;64], &[20;64]), Ok(-54)); }
#[test] fn wide_sums() { assert_eq!(score(0, &[u64::MAX;2], &[], &[]), Ok(-9223372036854775807)); }
#[test] fn negative_overflow() { assert_eq!(score(i64::MIN, &[4], &[], &[]), Err("score_out_of_range")); }
#[test] fn positive_overflow() { assert_eq!(score(i64::MAX, &[], &[], &[20]), Err("score_out_of_range")); }
#[test] fn cancellation_before_range_check() { assert_eq!(score(0, &[u64::MAX;12], &[], &[u64::MAX;60]), Ok(0)); }
#[test] fn extrema_identity() { assert_eq!(score(i64::MIN, &[], &[], &[]), Ok(i64::MIN)); assert_eq!(score(i64::MAX, &[], &[], &[]), Ok(i64::MAX)); }
