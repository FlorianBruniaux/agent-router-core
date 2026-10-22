use std::collections::BTreeMap;

use router_catalog::Catalog;
use router_types::{
    Capability, CapabilitySupport, EffortLevel, Exclusion, HostSnapshot, ModelSpec, RouteRequest,
    SkillId, SkillTrust, StageKind,
};

use crate::{
    CapabilityKnowledge, ConstraintEngine, ConstraintVerdict, EligibilityContext, Support,
    is_eligible,
};

pub(crate) const PRESET_NAME: &str = "plan-execute-verify";

#[derive(Clone, Debug)]
pub(crate) struct AttachedSkill {
    pub(crate) id: SkillId,
    pub(crate) score_micros: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct StageCandidate {
    pub(crate) kind: StageKind,
    pub(crate) model: ModelSpec,
    pub(crate) effort: EffortLevel,
    pub(crate) skills: Vec<AttachedSkill>,
}

#[derive(Debug)]
pub(crate) struct CandidateBuild {
    pub(crate) stages: Vec<Vec<StageCandidate>>,
    pub(crate) exclusions: Vec<Exclusion>,
    pub(crate) missing_evidence: Vec<String>,
}

pub(crate) fn build_candidates(request: &RouteRequest, catalog: &Catalog) -> CandidateBuild {
    let engine = ConstraintEngine::default();
    let capabilities = capability_knowledge(request);
    let host = constraint_host(request);
    let mut stages = Vec::with_capacity(3);
    let mut exclusions = Vec::new();
    let mut missing_evidence = Vec::new();

    for (stage, preferred) in [
        (StageKind::Plan, EffortLevel::High),
        (StageKind::Execute, EffortLevel::Medium),
        (StageKind::Verify, EffortLevel::High),
    ] {
        let mut stage_candidates = Vec::new();
        for (_, model) in catalog.models() {
            for effort in effort_preference(preferred) {
                let context = EligibilityContext {
                    task: request.task.clone(),
                    host: host.clone(),
                    model: model.clone(),
                    stage,
                    effort,
                    capabilities: capabilities.clone(),
                };
                let verdicts = engine.evaluate(&context);
                if is_eligible(&verdicts) {
                    stage_candidates.push(StageCandidate {
                        kind: stage,
                        model: model.clone(),
                        effort,
                        skills: compatible_skills(request, catalog, model),
                    });
                    break;
                }
                preserve_non_eligible(
                    stage,
                    model,
                    verdicts,
                    &mut exclusions,
                    &mut missing_evidence,
                );
            }
        }
        stages.push(stage_candidates);
    }

    CandidateBuild {
        stages,
        exclusions,
        missing_evidence,
    }
}

fn effort_preference(preferred: EffortLevel) -> Vec<EffortLevel> {
    const LEVELS: [EffortLevel; 8] = [
        EffortLevel::None,
        EffortLevel::Minimal,
        EffortLevel::Low,
        EffortLevel::Medium,
        EffortLevel::High,
        EffortLevel::Xhigh,
        EffortLevel::Max,
        EffortLevel::Ultra,
    ];
    const REMAINING: [EffortLevel; 6] = [
        EffortLevel::Low,
        EffortLevel::Medium,
        EffortLevel::High,
        EffortLevel::Xhigh,
        EffortLevel::Max,
        EffortLevel::Ultra,
    ];

    let index = LEVELS
        .iter()
        .position(|level| *level == preferred)
        .expect("preset effort must be declared");
    let mut ordered = Vec::with_capacity(REMAINING.len());
    push_unique(&mut ordered, preferred);
    if let Some(higher) = LEVELS.get(index + 1) {
        push_unique(&mut ordered, *higher);
    }
    if index > 0 {
        push_unique(&mut ordered, LEVELS[index - 1]);
    }
    for effort in REMAINING {
        push_unique(&mut ordered, effort);
    }
    ordered
}

fn push_unique(efforts: &mut Vec<EffortLevel>, effort: EffortLevel) {
    if !efforts.contains(&effort) {
        efforts.push(effort);
    }
}

fn capability_knowledge(request: &RouteRequest) -> CapabilityKnowledge {
    request
        .task
        .required_capabilities
        .iter()
        .map(|capability| (*capability, request_support(request, *capability)))
        .collect::<BTreeMap<Capability, Support>>()
        .into()
}

fn constraint_host(request: &RouteRequest) -> HostSnapshot {
    let mut host = request.host.clone();
    for (capability, support) in &request.capability_knowledge {
        match support {
            CapabilitySupport::Supported => {
                host.capabilities.insert(*capability);
            }
            CapabilitySupport::Unsupported | CapabilitySupport::Unknown => {
                host.capabilities.remove(capability);
            }
        }
    }
    host
}

fn request_support(request: &RouteRequest, capability: Capability) -> Support {
    match request.capability_knowledge.get(&capability) {
        Some(CapabilitySupport::Supported) => Support::Supported,
        Some(CapabilitySupport::Unsupported) => Support::Unsupported,
        Some(CapabilitySupport::Unknown) => Support::Unknown,
        None if request.host.capabilities.contains(&capability) => Support::Supported,
        None => Support::Unsupported,
    }
}

fn compatible_skills(
    request: &RouteRequest,
    catalog: &Catalog,
    model: &ModelSpec,
) -> Vec<AttachedSkill> {
    let mut compatible = BTreeMap::<SkillId, i64>::new();
    for candidate in &request.skill_candidates {
        let Some(skill) = catalog.skill(&candidate.skill) else {
            continue;
        };
        if !matches!(
            skill.trust,
            SkillTrust::Builtin | SkillTrust::TrustedLocal | SkillTrust::VerifiedThirdParty
        ) || !skill.task_kinds.contains(&request.task.kind)
            || !skill.required_capabilities.iter().all(|capability| {
                request_support(request, *capability) == Support::Supported
                    && model.capabilities.contains(capability)
            })
        {
            continue;
        }
        compatible
            .entry(candidate.skill.clone())
            .and_modify(|score| *score = (*score).max(candidate.score_micros))
            .or_insert(candidate.score_micros);
    }
    compatible
        .into_iter()
        .map(|(id, score_micros)| AttachedSkill { id, score_micros })
        .collect()
}

fn preserve_non_eligible(
    stage: StageKind,
    model: &ModelSpec,
    verdicts: Vec<ConstraintVerdict>,
    exclusions: &mut Vec<Exclusion>,
    missing_evidence: &mut Vec<String>,
) {
    for verdict in verdicts {
        match verdict {
            ConstraintVerdict::Eligible { .. } => {}
            ConstraintVerdict::Excluded { code, evidence } => exclusions.push(Exclusion {
                stage,
                model: model.id.clone(),
                code: code.into(),
                evidence,
            }),
            ConstraintVerdict::Unknown { code, evidence } => {
                missing_evidence.push(evidence.clone());
                exclusions.push(Exclusion {
                    stage,
                    model: model.id.clone(),
                    code: code.into(),
                    evidence,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::effort_preference;
    use router_types::EffortLevel;

    #[test]
    fn fixed_effort_order_is_nearest_first_and_deduplicated() {
        assert_eq!(
            effort_preference(EffortLevel::High),
            vec![
                EffortLevel::High,
                EffortLevel::Xhigh,
                EffortLevel::Medium,
                EffortLevel::Low,
                EffortLevel::Max,
                EffortLevel::Ultra,
            ]
        );
        assert_eq!(
            effort_preference(EffortLevel::Medium),
            vec![
                EffortLevel::Medium,
                EffortLevel::High,
                EffortLevel::Low,
                EffortLevel::Xhigh,
                EffortLevel::Max,
                EffortLevel::Ultra,
            ]
        );
    }
}
