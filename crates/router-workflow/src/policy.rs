use crate::{Result, WorkflowError, hash, text};
use router_types::{ConfigurationLayers, EffectiveRestrictions, RestrictionLayer};
use std::collections::BTreeSet;

fn intersect<T: Ord + Clone>(current: &mut Option<BTreeSet<T>>, next: &Option<BTreeSet<T>>) {
    if let Some(next) = next {
        *current = Some(match current.as_ref() {
            Some(old) => old.intersection(next).cloned().collect(),
            None => next.clone(),
        });
    }
}
fn minimum<T: Ord + Copy>(current: &mut Option<T>, next: Option<T>) {
    if let Some(next) = next {
        *current = Some(current.map_or(next, |old| old.min(next)));
    }
}

pub fn resolve_configuration(config: &ConfigurationLayers) -> Result<EffectiveRestrictions> {
    if config.schema_version != 1 {
        return Err(WorkflowError::Invalid("configuration schema"));
    }
    let ordered = [
        ("defaults", Some(&config.defaults)),
        (
            "active_offline_policy",
            config.active_offline_policy.as_ref(),
        ),
        ("preset", config.preset.as_ref()),
        ("project", config.project.as_ref()),
        ("organization", config.organization.as_ref()),
        ("task", config.task.as_ref()),
    ];
    let layers: Vec<_> = ordered
        .into_iter()
        .filter_map(|(role, layer)| {
            layer.map(|layer| {
                let mut layer = layer.clone();
                layer.name = format!("{role}:{}", layer.name);
                layer
            })
        })
        .collect();
    merge_restrictions(&layers)
}

/// Layers are ordered from lowest to highest preference precedence. Restrictions
/// intersect across every layer, including task and approval-bound overrides.
/// An override may select among permitted options but never erase a prohibition.
pub fn merge_restrictions(layers: &[RestrictionLayer]) -> Result<EffectiveRestrictions> {
    if layers.is_empty() || layers.len() > 16 {
        return Err(WorkflowError::Limit("policy layers"));
    }
    let mut result = EffectiveRestrictions {
        schema_version: 1,
        sources: vec![],
        allowed_models: None,
        allowed_capabilities: None,
        allowed_mutations: None,
        max_cost_microusd: None,
        max_tokens: None,
        max_concurrency: None,
        preferred_model: None,
        policy_hash: String::new(),
    };
    let mut names = BTreeSet::new();
    for layer in layers {
        if !text(&layer.name) || !names.insert(&layer.name) {
            return Err(WorkflowError::Invalid("policy layer name"));
        }
        if layer
            .allowed_models
            .as_ref()
            .is_some_and(|models| models.len() > 64)
            || layer
                .max_concurrency
                .is_some_and(|width| width == 0 || width > 64)
        {
            return Err(WorkflowError::Limit("policy candidates or concurrency"));
        }
        result.sources.push(layer.name.clone());
        intersect(&mut result.allowed_models, &layer.allowed_models);
        intersect(
            &mut result.allowed_capabilities,
            &layer.allowed_capabilities,
        );
        intersect(&mut result.allowed_mutations, &layer.allowed_mutations);
        minimum(&mut result.max_cost_microusd, layer.max_cost_microusd);
        minimum(&mut result.max_tokens, layer.max_tokens);
        minimum(&mut result.max_concurrency, layer.max_concurrency);
        if layer.preferred_model.is_some() {
            result.preferred_model = layer.preferred_model.clone();
        }
    }
    if result.preferred_model.as_ref().is_some_and(|model| {
        result
            .allowed_models
            .as_ref()
            .is_some_and(|set| !set.contains(model))
    }) {
        return Err(WorkflowError::Authority(
            "preferred model is forbidden by a restrictive layer",
        ));
    }
    result.policy_hash = hash(
        &serde_json::to_vec(&result).map_err(|_| WorkflowError::Invalid("policy serialization"))?,
    );
    Ok(result)
}

pub fn validate_restrictions(restrictions: &EffectiveRestrictions) -> Result<()> {
    if restrictions.schema_version != 1
        || restrictions.sources.is_empty()
        || restrictions.sources.len() > 16
        || restrictions.sources.iter().any(|name| !text(name))
        || restrictions.sources.iter().collect::<BTreeSet<_>>().len() != restrictions.sources.len()
        || restrictions
            .allowed_models
            .as_ref()
            .is_some_and(|models| models.len() > 64)
        || restrictions
            .max_concurrency
            .is_some_and(|width| width == 0 || width > 64)
        || restrictions.preferred_model.as_ref().is_some_and(|model| {
            restrictions
                .allowed_models
                .as_ref()
                .is_some_and(|models| !models.contains(model))
        })
    {
        return Err(WorkflowError::Invalid("effective restrictions"));
    }
    let mut copy = restrictions.clone();
    copy.policy_hash.clear();
    if hash(&serde_json::to_vec(&copy).map_err(|_| WorkflowError::Invalid("policy serialization"))?)
        != restrictions.policy_hash
    {
        return Err(WorkflowError::Integrity);
    }
    Ok(())
}
