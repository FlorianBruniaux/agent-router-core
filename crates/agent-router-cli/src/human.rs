//! Human projections of the exact structured result. Rendering never changes
//! authority, dispatch, exit status or the independently usable JSON contract.
//!
//! Layout: a summary of the outcome (status, selection or abstention, approval
//! digest), then the detail, then the top-level hashes and digests. The detail
//! keeps every other field; only the null side of a decided selection/abstention
//! pair is left out, because the summary already states which side holds.
use serde_json::{Map, Value};
use std::fmt::Write;

const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_NODES: usize = 200_000;

pub(crate) fn render(title: &str, document: &str) -> String {
    if document.len() > MAX_BYTES {
        return format!(
            "{title}\nHuman view omitted: result exceeds the display limit. Use --json for the complete structured result.\n"
        );
    }
    let Ok(value) = serde_json::from_str::<Value>(document) else {
        return format!("{title}\nHuman view unavailable. Use --json for the structured result.\n");
    };
    let mut output = format!("{title}\n");
    let mut remaining = MAX_NODES;
    let written = match &value {
        Value::Object(fields) => write_document(&mut output, fields, &mut remaining),
        _ => write_value(&mut output, &value, 0, &mut remaining),
    };
    if written.is_err() {
        output.push_str("\nOutput shortened at the display limit. Use --json for the complete structured result.\n");
    }
    output
}

/// Escapes control characters and Unicode format characters (bidi controls,
/// zero-width and invisible marks) so untrusted text cannot rewrite the
/// terminal or visually reorder a line. Shared by every human projection.
pub(crate) fn escaped(text: &str) -> String {
    let mut output = String::new();
    for character in text.chars() {
        if character.is_control() || is_format(character) {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}

/// Unicode general category Cf (Unicode 16) plus the Zl/Zp line and paragraph
/// separators, which also rewrite a terminal line.
fn is_format(character: char) -> bool {
    matches!(character as u32,
        0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x890..=0x891 | 0x8e2 | 0x180e
        | 0x200b..=0x200f | 0x2028..=0x202e | 0x2060..=0x2064 | 0x2066..=0x206f
        | 0xfeff | 0xfff9..=0xfffb | 0x110bd | 0x110cd | 0x13430..=0x1343f
        | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0001 | 0xe0020..=0xe007f)
}

/// Top-level fields that state an outcome, in precedence order.
const STATUS_KEYS: [&str; 4] = ["status", "state", "overall", "outcome"];
/// Fields that name an array element or a selection, in precedence order.
const NAME_KEYS: [&str; 8] = [
    "id",
    "name",
    "candidate_id",
    "run_id",
    "node_id",
    "plan_id",
    "artifact_id",
    "case_id",
];

/// A hash or digest field: grouped after the detail, never shortened.
fn is_hash_key(key: &str) -> bool {
    matches!(key, "hash" | "sha256" | "digest")
        || ["_hash", "_hashes", "_sha256", "_digest"]
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

/// A short name for an object: its identifier, plus `model/effort` when it
/// describes a candidate. A selection is named by its candidate.
fn item_label(value: &Value) -> Option<String> {
    let fields = value.as_object()?;
    let id = NAME_KEYS
        .iter()
        .find_map(|key| fields.get(*key)?.as_str().filter(|id| !id.is_empty()));
    let Some(id) = id else {
        return fields.get("candidate").and_then(item_label);
    };
    let mut label = escaped(id);
    if let Some(model) = fields.get("model").and_then(Value::as_str) {
        let effort = fields.get("effort").and_then(Value::as_str);
        let detail = match effort {
            Some(effort) => format!("{model}/{effort}"),
            None => model.to_owned(),
        };
        let _ = write!(label, " ({})", escaped(&detail));
    }
    Some(label)
}

/// The summary lines and the top-level keys they replace or make redundant.
fn summary(fields: &Map<String, Value>) -> (Vec<String>, Vec<&'static str>) {
    let mut lines = Vec::new();
    let mut consumed = Vec::new();
    let text = |value: &Value| {
        scalar(value).filter(|_| !(value.is_null() || value.is_array() || value.is_object()))
    };
    let selected = fields.get("selected").filter(|value| !value.is_null());
    let abstention = fields.get("abstention").filter(|value| !value.is_null());
    if let Some((key, status)) = STATUS_KEYS
        .iter()
        .find_map(|key| Some((*key, text(fields.get(*key)?)?)))
    {
        lines.push(format!("Status: {status}"));
        consumed.push(key);
    } else if let Some(state) = fields
        .get("run")
        .and_then(|run| STATUS_KEYS.iter().find_map(|key| text(run.get(*key)?)))
    {
        lines.push(format!("Status: {state}"));
    } else if fields.contains_key("selected") && fields.contains_key("abstention") {
        match (selected, abstention) {
            (Some(_), None) => lines.push("Status: selected".into()),
            (None, Some(_)) => lines.push("Status: abstained".into()),
            _ => {}
        }
    }
    if let Some(selected) = selected {
        if let Some(label) = item_label(selected) {
            lines.push(format!("Selected: {label}"));
        } else if let Some(value) = text(selected) {
            lines.push(format!("Selected: {value}"));
            consumed.push("selected");
        }
        if abstention.is_none() && fields.contains_key("abstention") {
            consumed.push("abstention");
        }
    }
    if let Some(abstention) = abstention {
        if let Some(reason) = text(abstention) {
            lines.push(format!("Abstention: {reason}"));
            consumed.push("abstention");
        }
        if selected.is_none() && fields.contains_key("selected") {
            consumed.push("selected");
        }
    }
    if let Some(executed) = fields.get("executed").and_then(Value::as_bool) {
        lines.push(format!("Executed: {}", if executed { "yes" } else { "no" }));
        consumed.push("executed");
    }
    if let Some(digest) = fields.get("approval_digest").and_then(Value::as_str) {
        lines.push(format!("Approval digest: {}", escaped(digest)));
        consumed.push("approval_digest");
    }
    (lines, consumed)
}

fn write_document(
    output: &mut String,
    fields: &Map<String, Value>,
    remaining: &mut usize,
) -> Result<(), ()> {
    let (lines, consumed) = summary(fields);
    for line in &lines {
        writeln!(output, "{line}").map_err(|_| ())?;
    }
    if !lines.is_empty() {
        output.push('\n');
    }
    let shown = |key: &String| !consumed.contains(&key.as_str());
    // The decided side of a selection or abstention leads the detail.
    let leading = |key: &String| matches!(key.as_str(), "selected" | "abstention");
    let detail: Vec<_> = fields
        .iter()
        .filter(|(key, _)| shown(key) && leading(key))
        .chain(
            fields
                .iter()
                .filter(|(key, _)| shown(key) && !leading(key) && !is_hash_key(key)),
        )
        .collect();
    let hashes: Vec<_> = fields
        .iter()
        .filter(|(key, _)| shown(key) && is_hash_key(key))
        .collect();
    write_fields(output, detail, 0, remaining)?;
    if !hashes.is_empty() {
        writeln!(output, "Hashes:").map_err(|_| ())?;
        write_fields(output, hashes, 1, remaining)?;
    }
    Ok(())
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Null => Some("not set (null)".into()),
        Value::Bool(value) => Some(if *value { "yes" } else { "no" }.into()),
        Value::Number(value) => Some(value.to_string()),
        Value::String(value) if value == "unknown" => Some("UNKNOWN".into()),
        Value::String(value) => Some(escaped(value)),
        Value::Array(values) if values.is_empty() => Some("none".into()),
        Value::Object(values) if values.is_empty() => Some("none".into()),
        _ => None,
    }
}

fn label(key: &str) -> String {
    let text = escaped(key).replace('_', " ");
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn write_value(
    output: &mut String,
    value: &Value,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), ()> {
    if depth > 64 || *remaining == 0 || output.len() > MAX_BYTES {
        return Err(());
    }
    *remaining -= 1;
    let indent = "  ".repeat(depth);
    match value {
        Value::Object(fields) => {
            // Hashes and digests follow the other fields of the same object.
            let ordered = fields
                .iter()
                .filter(|(key, _)| !is_hash_key(key))
                .chain(fields.iter().filter(|(key, _)| is_hash_key(key)))
                .collect();
            write_fields(output, ordered, depth, remaining)?;
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if let Some(text) = scalar(value) {
                    writeln!(output, "{indent}- {text}").map_err(|_| ())?;
                    *remaining = remaining.checked_sub(1).ok_or(())?;
                } else {
                    match item_label(value) {
                        Some(name) => writeln!(output, "{indent}- {name}"),
                        None => writeln!(output, "{indent}- [{}]", index + 1),
                    }
                    .map_err(|_| ())?;
                    write_value(output, value, depth + 1, remaining)?;
                }
                if output.len() > MAX_BYTES {
                    return Err(());
                }
            }
        }
        _ => writeln!(output, "{indent}{}", scalar(value).ok_or(())?).map_err(|_| ())?,
    }
    Ok(())
}

fn write_fields(
    output: &mut String,
    fields: Vec<(&String, &Value)>,
    depth: usize,
    remaining: &mut usize,
) -> Result<(), ()> {
    let indent = "  ".repeat(depth);
    for (key, value) in fields {
        if let Some(text) = scalar(value) {
            writeln!(output, "{indent}{}: {text}", label(key)).map_err(|_| ())?;
            *remaining = remaining.checked_sub(1).ok_or(())?;
        } else {
            writeln!(output, "{indent}{}:", label(key)).map_err(|_| ())?;
            write_value(output, value, depth + 1, remaining)?;
        }
        if output.len() > MAX_BYTES {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_unknown_and_exact_approval_while_neutralizing_terminal_controls() {
        let digest = "a".repeat(64);
        let value = serde_json::json!({"approval_digest":digest,"objective":"unknown",
            "observed_model":null,"warning":"untrusted\u{1b}[2J\n\u{202e}text", "ready":false});
        let output = render("Run review", &value.to_string());
        assert!(output.contains(&format!("Approval digest: {digest}")));
        assert!(output.contains("Objective: UNKNOWN"));
        assert!(output.contains("Observed model: not set (null)"));
        assert!(output.contains("Ready: no"));
        assert!(!output.contains('\u{1b}'));
        assert!(!output.contains('\u{202e}'));
        assert!(output.contains("\\n"));
    }

    #[test]
    fn an_abstention_leads_with_its_reason_and_drops_only_the_null_selection() {
        let value = serde_json::json!({"schema_version":2,"selected":null,
            "abstention":"below_threshold","alternatives":[],"pool_hash":"b".repeat(64)});
        let output = render("Routing decision", &value.to_string());
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(
            &lines[..4],
            &[
                "Routing decision",
                "Status: abstained",
                "Abstention: below_threshold",
                ""
            ],
            "{output}"
        );
        assert!(!output.contains("Selected"), "{output}");
        assert!(output.contains("Alternatives: none"), "{output}");
        assert!(
            output.ends_with(&format!("Hashes:\n  Pool hash: {}\n", "b".repeat(64))),
            "{output}"
        );
    }

    #[test]
    fn neither_side_decided_keeps_both_nulls_visible() {
        let value = serde_json::json!({"selected":null,"abstention":null});
        let output = render("Routing decision", &value.to_string());
        assert!(!output.contains("Status:"), "{output}");
        assert!(output.contains("Selected: not set (null)"), "{output}");
        assert!(output.contains("Abstention: not set (null)"), "{output}");
    }

    #[test]
    fn a_run_review_summarizes_state_execution_and_the_full_approval_digest() {
        let digest = "c".repeat(64);
        let value = serde_json::json!({"schema_version":1,"approval_digest":digest,"executed":false,
            "run":{"run_id":"r1","state":"awaiting_approval","definition_hash":"d".repeat(64),"attempts":0}});
        let output = render("Run", &value.to_string());
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines[1], "Status: awaiting_approval");
        assert_eq!(lines[2], "Executed: no");
        assert_eq!(lines[3], format!("Approval digest: {digest}"));
        // Stated once, in the summary; nested hashes follow their siblings.
        assert_eq!(output.matches(&digest).count(), 1, "{output}");
        let state = output.find("  State: awaiting_approval").unwrap();
        let hash = output.find("  Definition hash: ").unwrap();
        assert!(state < hash, "{output}");
    }

    #[test]
    fn an_unknown_status_stays_unknown_in_the_summary() {
        let value = serde_json::json!({"overall":"unknown","counts":null});
        let output = render("Diagnostics", &value.to_string());
        assert!(
            output.starts_with("Diagnostics\nStatus: UNKNOWN\n\n"),
            "{output}"
        );
        assert!(output.contains("Counts: not set (null)"), "{output}");
    }

    #[test]
    fn array_elements_are_named_when_they_carry_an_identifier() {
        let value = serde_json::json!({"items":[{"id":"a\u{1b}b","kind":"model"},{"value":1}]});
        let output = render("List", &value.to_string());
        assert!(output.contains("  - a\\u{1b}b\n"), "{output}");
        assert!(output.contains("  - [2]\n"), "{output}");
        assert!(!output.contains('\u{1b}'));
    }

    #[test]
    fn escapes_a_sample_of_every_format_block_and_line_separators() {
        for code in [
            0xad_u32, 0x600, 0x605, 0x6dd, 0x70f, 0x890, 0x891, 0x8e2, 0x180e, 0x200b, 0x2028,
            0x2029, 0x2060, 0x2064, 0x206f, 0xfeff, 0xfff9, 0xfffb, 0x110bd, 0x110cd, 0x13430,
            0x1343f, 0x1bca0, 0x1bca3, 0x1d173, 0x1d17a, 0xe0001, 0xe0020, 0xe007f,
        ] {
            let character = char::from_u32(code).unwrap();
            let text = escaped(&format!("a{character}b"));
            assert!(!text.contains(character), "U+{code:04X} leaked");
            assert!(
                text.contains(&format!("\\u{{{code:x}}}")),
                "U+{code:04X}: {text}"
            );
        }
    }

    #[test]
    fn escapes_unicode_format_characters() {
        let text = escaped("a\u{200e}b\u{200f}c\u{61c}d\u{202e}e\u{2066}f\u{feff}g");
        assert_eq!(
            text,
            "a\\u{200e}b\\u{200f}c\\u{61c}d\\u{202e}e\\u{2066}f\\u{feff}g"
        );
        assert_eq!(escaped("plain \u{e9}\u{4e2d}"), "plain \u{e9}\u{4e2d}");
    }
}
