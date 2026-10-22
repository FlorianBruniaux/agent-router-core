use crate::human::escaped;
use router_types::{DecisionEnvelope, RouteDecision};

pub fn decision_json(decision: &DecisionEnvelope) -> Result<String, serde_json::Error> {
    let mut rendered = serde_json::to_string_pretty(decision)?;
    rendered.push('\n');
    Ok(rendered)
}

pub fn explain(decision: &DecisionEnvelope) -> String {
    let mut lines = vec![format!(
        "Decision {}",
        escaped(&decision.decision_id.to_string())
    )];

    match &decision.decision {
        RouteDecision::Selected {
            plan,
            exclusions,
            missing_evidence,
            ..
        } => {
            lines.push(format!("Preset: {}", escaped(&plan.preset.to_string())));
            let plan = plan
                .stages
                .iter()
                .map(|stage| {
                    format!(
                        "{}/{}",
                        escaped(&stage.model.to_string()),
                        effort_label(stage.effort)
                    )
                })
                .collect::<Vec<_>>()
                .join(" -> ");
            lines.push(format!("Plan: {plan}"));
            lines.push(format!("Excluded candidates: {}", exclusions.len()));
            lines.push(format!("Missing evidence: {}", missing_evidence.len()));
        }
        RouteDecision::NoRoute {
            exclusions,
            missing_evidence,
        } => {
            lines.push("No route".into());
            lines.push(format!("Missing evidence: {}", missing_evidence.len()));
            for exclusion in exclusions {
                lines.push(format!("Stage: {}", stage_label(exclusion.stage)));
                lines.push(format!("Model: {}", escaped(&exclusion.model.to_string())));
                lines.push(format!("Code: {}", escaped(&exclusion.code.to_string())));
                lines.push(format!(
                    "Evidence: {}",
                    escaped(&exclusion.evidence.to_string())
                ));
            }
        }
    }

    format!("{}\n", lines.join("\n"))
}

fn effort_label(effort: router_types::EffortLevel) -> &'static str {
    match effort {
        router_types::EffortLevel::None => "none",
        router_types::EffortLevel::Minimal => "minimal",
        router_types::EffortLevel::Low => "low",
        router_types::EffortLevel::Medium => "medium",
        router_types::EffortLevel::High => "high",
        router_types::EffortLevel::Xhigh => "xhigh",
        router_types::EffortLevel::Max => "max",
        router_types::EffortLevel::Ultra => "ultra",
    }
}

fn stage_label(stage: router_types::StageKind) -> &'static str {
    match stage {
        router_types::StageKind::Plan => "plan",
        router_types::StageKind::Execute => "execute",
        router_types::StageKind::Verify => "verify",
    }
}
