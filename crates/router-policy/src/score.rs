use std::{cmp::Ordering, collections::BTreeMap};

use router_types::{
    Exclusion, ExecutionPlan, PlanStage, RiskLevel, SkillId, StageKind, TaskKind,
    VerificationIndependence,
};

use crate::preset::{PRESET_NAME, StageCandidate};
use crate::route::{MAX_PLAN_WORK_UNITS, RouteError};

#[derive(Debug)]
pub(crate) struct RankedPlan {
    pub(crate) plan: ExecutionPlan,
    total_cost_micros: i128,
    model_key: String,
}

pub(crate) fn rank_plans(
    stages: &[Vec<StageCandidate>],
    task_kind: TaskKind,
    risk: RiskLevel,
    exclusions: &mut Vec<Exclusion>,
) -> Result<Vec<RankedPlan>, RouteError> {
    if stages.len() != 3 || stages.iter().any(Vec::is_empty) {
        return Ok(Vec::new());
    }
    enforce_work_limit(stages)?;

    let verifier_quality_policy = match task_kind {
        TaskKind::Security => Some(("security", "verification.security.not_max_quality")),
        TaskKind::Architecture => {
            Some(("architecture", "verification.architecture.not_max_quality"))
        }
        _ => None,
    };
    let required_verify_quality = verifier_quality_policy.map(|_| {
        stages[2]
            .iter()
            .map(|candidate| candidate.model.quality_micros)
            .max()
            .expect("the verify stage has candidates")
    });
    if let (Some((task_label, exclusion_code)), Some(required_quality)) =
        (verifier_quality_policy, required_verify_quality)
    {
        for verify in &stages[2] {
            if verify.model.quality_micros < required_quality {
                exclusions.push(Exclusion {
                    stage: StageKind::Verify,
                    model: verify.model.id.clone(),
                    code: exclusion_code.into(),
                    evidence: format!(
                        "{task_label} verify model '{}' quality {} is below eligible maximum {}",
                        verify.model.id, verify.model.quality_micros, required_quality,
                    ),
                });
            }
        }
    }

    // The verify-below-execute exclusion depends only on the (execute, verify)
    // pair; record it once instead of once per plan-stage model.
    let below_execute = |execute: &StageCandidate, verify: &StageCandidate| {
        matches!(risk, RiskLevel::High | RiskLevel::Critical)
            && verify.model.quality_micros < execute.model.quality_micros
    };
    for execute in &stages[1] {
        for verify in &stages[2] {
            if required_verify_quality.is_some_and(|quality| verify.model.quality_micros < quality)
                || !below_execute(execute, verify)
            {
                continue;
            }
            exclusions.push(Exclusion {
                stage: StageKind::Verify,
                model: verify.model.id.clone(),
                code: "verification.quality.below_execute".into(),
                evidence: format!(
                    "verify model '{}' quality {} is below execute model '{}' quality {}",
                    verify.model.id,
                    verify.model.quality_micros,
                    execute.model.id,
                    execute.model.quality_micros
                ),
            });
        }
    }

    let mut plans = Vec::with_capacity(4);
    for plan in &stages[0] {
        for execute in &stages[1] {
            for verify in &stages[2] {
                if required_verify_quality
                    .is_some_and(|quality| verify.model.quality_micros < quality)
                    || below_execute(execute, verify)
                {
                    continue;
                }
                plans.push(to_ranked_plan([plan, execute, verify], risk)?);
                plans.sort_by(compare_ranked);
                if plans.len() > 3 {
                    plans.truncate(3);
                }
            }
        }
    }
    Ok(plans)
}

fn enforce_work_limit(stages: &[Vec<StageCandidate>]) -> Result<(), RouteError> {
    let combinations = stages
        .iter()
        .map(Vec::len)
        .try_fold(1_usize, usize::checked_mul);
    let payload_per_combination = stages.iter().try_fold(1_usize, |payload, stage| {
        let max_skills = stage
            .iter()
            .map(|candidate| candidate.skills.len())
            .max()
            .unwrap_or(0);
        payload.checked_add(max_skills)
    });
    let work_units = combinations
        .zip(payload_per_combination)
        .and_then(|(combinations, payload)| combinations.checked_mul(payload));
    if work_units.is_none_or(|actual| actual > MAX_PLAN_WORK_UNITS) {
        return Err(RouteError::WorkLimitExceeded {
            actual: work_units,
            max: MAX_PLAN_WORK_UNITS,
        });
    }
    Ok(())
}

fn to_ranked_plan(stages: [&StageCandidate; 3], risk: RiskLevel) -> Result<RankedPlan, RouteError> {
    let quality_micros = stages
        .iter()
        .map(|stage| i128::from(stage.model.quality_micros))
        .min()
        .expect("a plan has three stages");
    let total_cost_micros = checked_sum(
        stages
            .iter()
            .map(|stage| i128::from(stage.model.cost_micros)),
        "total_cost_micros",
    )?;
    let total_latency_micros = stages
        .iter()
        .map(|stage| i128::from(stage.model.latency_micros));
    let total_latency_micros = checked_sum(total_latency_micros, "total_latency_micros")?;
    let mut skills = BTreeMap::<SkillId, i64>::new();
    for stage in stages {
        for skill in &stage.skills {
            skills
                .entry(skill.id.clone())
                .and_modify(|score| *score = (*score).max(skill.score_micros))
                .or_insert(skill.score_micros);
        }
    }
    let retrieved_skill_score_micros = checked_sum(
        skills.values().map(|score| i128::from(*score)),
        "retrieved_skill_score_micros",
    )?;
    let utility_micros = quality_micros
        .checked_sub(total_cost_micros / 4)
        .and_then(|value| value.checked_sub(total_latency_micros / 10))
        .and_then(|value| value.checked_add(retrieved_skill_score_micros / 20))
        .ok_or(RouteError::ArithmeticOutOfRange {
            component: "utility_micros",
        })?;
    let utility_micros =
        i64::try_from(utility_micros).map_err(|_| RouteError::ArithmeticOutOfRange {
            component: "utility_micros",
        })?;
    let model_key = stages
        .iter()
        .map(|stage| stage.model.id.as_str())
        .collect::<Vec<_>>()
        .join("\u{0}");
    let plan_stages = stages
        .into_iter()
        .map(|stage| PlanStage {
            kind: stage.kind,
            model: stage.model.id.clone(),
            effort: stage.effort,
            skills: stage.skills.iter().map(|skill| skill.id.clone()).collect(),
            verification_independence: if stage.kind == StageKind::Verify
                && matches!(risk, RiskLevel::High | RiskLevel::Critical)
            {
                Some(VerificationIndependence::FreshInstance)
            } else {
                None
            },
        })
        .collect();

    Ok(RankedPlan {
        plan: ExecutionPlan {
            preset: PRESET_NAME.into(),
            stages: plan_stages,
            utility_micros,
        },
        total_cost_micros,
        model_key,
    })
}

fn checked_sum(
    values: impl IntoIterator<Item = i128>,
    component: &'static str,
) -> Result<i128, RouteError> {
    values
        .into_iter()
        .try_fold(0_i128, i128::checked_add)
        .ok_or(RouteError::ArithmeticOutOfRange { component })
}

fn compare_ranked(left: &RankedPlan, right: &RankedPlan) -> Ordering {
    right
        .plan
        .utility_micros
        .cmp(&left.plan.utility_micros)
        .then_with(|| left.total_cost_micros.cmp(&right.total_cost_micros))
        .then_with(|| left.model_key.cmp(&right.model_key))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{RankedPlan, compare_ranked, rank_plans, to_ranked_plan};
    use crate::preset::{AttachedSkill, StageCandidate};
    use router_types::{
        EffortLevel, ExecutionPlan, ModelId, ModelSpec, RiskLevel, SkillId, StageKind, TaskKind,
    };

    #[test]
    fn equal_utility_prefers_lower_cost_before_lexicographic_model_key() {
        let lower_cost_later_id = ranked(100, "z-model");
        let higher_cost_earlier_id = ranked(200, "a-model");

        assert!(compare_ranked(&lower_cost_later_id, &higher_cost_earlier_id).is_lt());
    }

    #[test]
    fn streaming_top_three_matches_full_sort_oracle() {
        let stages = candidate_stages(3);
        let mut exclusions = vec![];

        let actual = rank_plans(
            &stages,
            TaskKind::Implement,
            RiskLevel::Medium,
            &mut exclusions,
        )
        .unwrap();
        let mut oracle = Vec::new();
        for plan in &stages[0] {
            for execute in &stages[1] {
                for verify in &stages[2] {
                    oracle
                        .push(to_ranked_plan([plan, execute, verify], RiskLevel::Medium).unwrap());
                }
            }
        }
        oracle.sort_by(compare_ranked);
        oracle.truncate(3);

        assert_eq!(rank_keys(&actual), rank_keys(&oracle));
    }

    #[test]
    fn sixty_four_models_retain_only_three_stable_results() {
        let stages = candidate_stages(64);
        let mut first_exclusions = vec![];
        let mut second_exclusions = vec![];

        let first = rank_plans(
            &stages,
            TaskKind::Implement,
            RiskLevel::Medium,
            &mut first_exclusions,
        )
        .unwrap();
        let second = rank_plans(
            &stages,
            TaskKind::Implement,
            RiskLevel::Medium,
            &mut second_exclusions,
        )
        .unwrap();

        assert_eq!(first.len(), 3);
        assert_eq!(first[0].plan.utility_micros, 999_981);
        assert_eq!(
            first[0].model_key,
            "provider-model-00\0provider-model-00\0provider-model-00"
        );
        assert_eq!(rank_keys(&first), rank_keys(&second));
    }

    #[test]
    fn high_risk_below_execute_exclusion_is_recorded_once_per_execute_verify_pair() {
        let stages = candidate_stages(64);
        let mut exclusions = vec![];

        let plans = rank_plans(
            &stages,
            TaskKind::Implement,
            RiskLevel::High,
            &mut exclusions,
        )
        .unwrap();

        // Quality falls with the model index, so verify is below execute for
        // every pair with verify index greater than execute index.
        let pairs = 64 * 63 / 2;
        assert_eq!(exclusions.len(), pairs);
        // Same set as the naive plan x execute x verify oracle after dedup.
        let mut oracle = Vec::new();
        for _plan in &stages[0] {
            for execute in &stages[1] {
                for verify in &stages[2] {
                    if verify.model.quality_micros < execute.model.quality_micros {
                        oracle.push((
                            verify.model.id.clone(),
                            format!(
                                "verify model '{}' quality {} is below execute model '{}' quality {}",
                                verify.model.id,
                                verify.model.quality_micros,
                                execute.model.id,
                                execute.model.quality_micros
                            ),
                        ));
                    }
                }
            }
        }
        oracle.sort();
        oracle.dedup();
        let mut actual = exclusions
            .iter()
            .map(|e| (e.model.clone(), e.evidence.clone()))
            .collect::<Vec<_>>();
        actual.sort();
        assert_eq!(actual, oracle);
        assert!(
            exclusions
                .iter()
                .all(|e| e.code == "verification.quality.below_execute")
        );
        assert_eq!(plans.len(), 3);
    }

    #[test]
    fn sixty_four_models_with_256_skills_exceeds_work_budget_before_scoring() {
        let stages = candidate_stages_with_skills(64, 256, i64::MAX);
        let mut exclusions = vec![];

        let error = rank_plans(
            &stages,
            TaskKind::Implement,
            RiskLevel::Medium,
            &mut exclusions,
        )
        .unwrap_err();

        assert_eq!(error.code(), "route.resource.work_limit_exceeded");
        assert!(error.is_invalid_request());
        assert_eq!(error.work_limit(), Some((Some(201_588_736), 1_000_000)));
    }

    #[test]
    fn thirty_two_models_with_256_skills_exceeds_work_budget_before_scoring() {
        let stages = candidate_stages_with_skills(32, 256, i64::MAX);
        let mut exclusions = vec![];

        let error = rank_plans(
            &stages,
            TaskKind::Implement,
            RiskLevel::Medium,
            &mut exclusions,
        )
        .unwrap_err();

        assert_eq!(error.code(), "route.resource.work_limit_exceeded");
        assert!(error.is_invalid_request());
        assert_eq!(error.work_limit(), Some((Some(25_198_592), 1_000_000)));
    }

    fn ranked(total_cost_micros: i128, model_key: &str) -> RankedPlan {
        RankedPlan {
            plan: ExecutionPlan {
                preset: "plan-execute-verify".into(),
                stages: vec![],
                utility_micros: 500_000,
            },
            total_cost_micros,
            model_key: model_key.into(),
        }
    }

    fn candidate_stages(count: usize) -> Vec<Vec<StageCandidate>> {
        candidate_stages_with_skills(count, 0, 0)
    }

    fn candidate_stages_with_skills(
        count: usize,
        skill_count: usize,
        cost_micros: i64,
    ) -> Vec<Vec<StageCandidate>> {
        let skills = (0..skill_count)
            .map(|index| AttachedSkill {
                id: SkillId::parse(format!("work-skill-{index:03}")).unwrap(),
                score_micros: 1_000_000,
            })
            .collect::<Vec<_>>();
        [StageKind::Plan, StageKind::Execute, StageKind::Verify]
            .into_iter()
            .map(|kind| {
                (0..count)
                    .map(|index| {
                        let effort = match kind {
                            StageKind::Execute => EffortLevel::Medium,
                            StageKind::Plan | StageKind::Verify => EffortLevel::High,
                        };
                        StageCandidate {
                            kind,
                            model: ModelSpec {
                                id: ModelId::parse(format!("provider-model-{index:02}")).unwrap(),
                                stages: BTreeSet::from([
                                    StageKind::Plan,
                                    StageKind::Execute,
                                    StageKind::Verify,
                                ]),
                                efforts: BTreeSet::from([EffortLevel::Medium, EffortLevel::High]),
                                capabilities: BTreeSet::new(),
                                quality_micros: 1_000_000 - index as i64,
                                cost_micros: cost_micros.saturating_add(index as i64),
                                latency_micros: (count - index) as i64,
                                source: "test-prior".into(),
                            },
                            effort,
                            skills: skills.clone(),
                        }
                    })
                    .collect()
            })
            .collect()
    }

    fn rank_keys(plans: &[RankedPlan]) -> Vec<(i64, i128, String)> {
        plans
            .iter()
            .map(|plan| {
                (
                    plan.plan.utility_micros,
                    plan.total_cost_micros,
                    plan.model_key.clone(),
                )
            })
            .collect()
    }
}
