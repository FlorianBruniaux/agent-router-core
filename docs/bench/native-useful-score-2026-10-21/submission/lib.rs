pub fn score(quality: i64, costs: &[u64], latencies: &[u64], skills: &[u64]) -> Result<i64, &'static str> {
    if [costs.len(), latencies.len(), skills.len()].iter().any(|n| *n > 64) { return Err("work_limit"); }
    let sum = |values: &[u64]| values.iter().map(|v| i128::from(*v)).sum::<i128>();
    let value = i128::from(quality) - sum(costs) / 4 - sum(latencies) / 10 + sum(skills) / 20;
    i64::try_from(value).map_err(|_| "score_out_of_range")
}
