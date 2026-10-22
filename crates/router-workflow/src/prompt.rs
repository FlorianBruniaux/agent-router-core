use crate::{Result, WorkflowError, hash, safe_path, text};
use router_types::{ModelId, PromptTemplate, PromptValue, PromptVariableType};
use std::collections::{BTreeMap, BTreeSet};

pub fn seal_prompt(mut template: PromptTemplate) -> Result<PromptTemplate> {
    validate(&template)?;
    template.content_sha256.clear();
    template.content_sha256 = hash(
        &serde_json::to_vec(&template)
            .map_err(|_| WorkflowError::Invalid("prompt serialization"))?,
    );
    Ok(template)
}
fn variables(template: &str) -> Result<Vec<(usize, usize, &str)>> {
    let mut found = vec![];
    let mut at = 0;
    while let Some(start) = template[at..].find("${") {
        let start = at + start;
        let end = template[start + 2..]
            .find('}')
            .ok_or(WorkflowError::Invalid("unterminated prompt variable"))?
            + start
            + 2;
        let name = &template[start + 2..end];
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        {
            return Err(WorkflowError::Invalid("prompt variable name"));
        }
        found.push((start, end + 1, name));
        at = end + 1;
        if found.len() > 128 {
            return Err(WorkflowError::Limit("prompt substitutions"));
        }
    }
    Ok(found)
}
fn validate(template: &PromptTemplate) -> Result<()> {
    if template.schema_version != 1
        || !text(&template.id)
        || !text(&template.version)
        || !text(&template.template)
        || !text(&template.output_contract)
        || template.max_rendered_bytes == 0
        || template.max_rendered_bytes > 1024 * 1024
        || template.variables.len() > 32
        || template.compatible_hosts.is_empty()
        || template.compatible_hosts.len() > 32
        || template.compatible_hosts.iter().any(|host| !text(host))
        || template.compatible_models.is_empty()
        || template.compatible_models.len() > 64
    {
        return Err(WorkflowError::Invalid("prompt contract"));
    }
    let references: BTreeSet<_> = variables(&template.template)?
        .into_iter()
        .map(|(_, _, name)| name)
        .collect();
    if references != template.variables.keys().map(String::as_str).collect() {
        return Err(WorkflowError::Invalid("prompt variable declarations"));
    }
    Ok(())
}
fn append(output: &mut String, part: &str, max: usize) -> Result<()> {
    if output
        .len()
        .checked_add(part.len())
        .is_none_or(|length| length > max)
    {
        return Err(WorkflowError::Limit("rendered prompt bytes"));
    }
    output.push_str(part);
    Ok(())
}

/// Substitute values once. Rendering grants no execution authority.
pub fn render_prompt(
    template: &PromptTemplate,
    host: &str,
    model: &ModelId,
    values: &BTreeMap<String, PromptValue>,
) -> Result<String> {
    let sealed = seal_prompt(template.clone())?;
    if sealed.content_sha256 != template.content_sha256 {
        return Err(WorkflowError::Integrity);
    }
    if !template.compatible_hosts.contains(host) || !template.compatible_models.contains(model) {
        return Err(WorkflowError::Authority(
            "prompt host or model incompatible",
        ));
    }
    if values.len() != template.variables.len()
        || values
            .keys()
            .any(|key| !template.variables.contains_key(key))
    {
        return Err(WorkflowError::Invalid("prompt variables missing or extra"));
    }
    let mut rendered = BTreeMap::new();
    for (name, kind) in &template.variables {
        let value = values
            .get(name)
            .ok_or(WorkflowError::Invalid("missing prompt variable"))?;
        let value = match (kind, value) {
            (PromptVariableType::Text, PromptValue::Text(value))
                if value.len() <= template.max_rendered_bytes && !value.contains('\0') =>
            {
                value.clone()
            }
            (PromptVariableType::RelativePath, PromptValue::Text(value)) if safe_path(value) => {
                value.clone()
            }
            (PromptVariableType::Integer, PromptValue::Integer(value)) => value.to_string(),
            (PromptVariableType::Boolean, PromptValue::Boolean(value)) => value.to_string(),
            _ => return Err(WorkflowError::Invalid("prompt variable type or bound")),
        };
        rendered.insert(name.as_str(), value);
    }
    let mut result = String::new();
    let mut at = 0;
    for (start, end, name) in variables(&template.template)? {
        append(
            &mut result,
            &template.template[at..start],
            template.max_rendered_bytes,
        )?;
        append(
            &mut result,
            rendered
                .get(name)
                .ok_or(WorkflowError::Invalid("prompt variable"))?,
            template.max_rendered_bytes,
        )?;
        at = end;
    }
    append(
        &mut result,
        &template.template[at..],
        template.max_rendered_bytes,
    )?;
    Ok(result)
}
