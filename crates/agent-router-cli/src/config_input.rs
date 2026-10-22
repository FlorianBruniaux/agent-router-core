//! Explicit local configuration formats. Parsing never follows references or
//! expands environment variables, and error codes never include source text.
use crate::{CliError, read_bounded};
use router_types::ConfigurationLayers;
use serde_json::{Map, Number, Value};
use std::{collections::BTreeSet, path::Path};
use yaml_rust2::{
    parser::{Event, Parser},
    scanner::{Scanner, TScalarStyle, TokenType},
};

const MAX_BYTES: usize = 256 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 4096;
const MAX_SCALAR_BYTES: usize = 8192;

fn invalid() -> CliError {
    CliError::Product("configuration.invalid")
}
fn limit() -> CliError {
    CliError::Product("configuration.limit")
}

pub(super) fn read(path: &Path) -> Result<ConfigurationLayers, CliError> {
    let extension = path.extension().and_then(|value| value.to_str());
    if !matches!(extension, Some("json" | "toml" | "yaml" | "yml")) {
        return Err(CliError::Product("configuration.format"));
    }
    let bytes = read_bounded(
        path,
        MAX_BYTES,
        CliError::Product("configuration.read"),
        limit(),
    )?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    let value = match extension {
        Some("json") => router_adapter_api::strict_json(&bytes).map_err(|_| invalid())?,
        Some("toml") => {
            // toml_edit's recursion guard remains enabled (the unbounded
            // feature is not selected). Application bounds are tighter below.
            let value: toml::Value = toml::from_str(text).map_err(|_| invalid())?;
            toml_value(value, 0, &mut 0)?
        }
        Some("yaml" | "yml") => yaml_value(text)?,
        _ => return Err(CliError::Product("configuration.format")),
    };
    validate_tree(&value, 0, &mut 0)?;
    serde_json::from_value(value).map_err(|_| invalid())
}

fn count_node(depth: usize, nodes: &mut usize) -> Result<(), CliError> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return Err(limit());
    }
    Ok(())
}
fn scalar(value: &str) -> Result<(), CliError> {
    if value.len() > MAX_SCALAR_BYTES {
        Err(limit())
    } else {
        Ok(())
    }
}
fn validate_tree(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), CliError> {
    count_node(depth, nodes)?;
    match value {
        Value::String(value) => scalar(value)?,
        Value::Array(values) => {
            // Configuration arrays represent sets of identifiers, never ordered
            // lists. Reject duplicates before Serde can collapse a BTreeSet.
            let mut seen = BTreeSet::new();
            for value in values {
                let Value::String(item) = value else {
                    return Err(invalid());
                };
                if !seen.insert(item) {
                    return Err(invalid());
                }
                validate_tree(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                scalar(key)?;
                validate_tree(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn toml_value(value: toml::Value, depth: usize, nodes: &mut usize) -> Result<Value, CliError> {
    count_node(depth, nodes)?;
    Ok(match value {
        toml::Value::String(value) => {
            scalar(&value)?;
            Value::String(value)
        }
        toml::Value::Integer(value) => Value::Number(value.into()),
        toml::Value::Float(value) => Value::Number(Number::from_f64(value).ok_or_else(invalid)?),
        toml::Value::Boolean(value) => Value::Bool(value),
        // No configuration field is a date/time. Do not coerce it to a string.
        toml::Value::Datetime(_) => return Err(invalid()),
        toml::Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| toml_value(value, depth + 1, nodes))
                .collect::<Result<_, _>>()?,
        ),
        toml::Value::Table(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    scalar(&key)?;
                    Ok((key, toml_value(value, depth + 1, nodes)?))
                })
                .collect::<Result<_, CliError>>()?,
        ),
    })
}

enum Frame {
    Array(Vec<Value>),
    Object {
        values: Map<String, Value>,
        key: Option<String>,
    },
}

fn append(value: Value, stack: &mut [Frame], root: &mut Option<Value>) -> Result<(), CliError> {
    match stack.last_mut() {
        Some(Frame::Array(values)) => values.push(value),
        Some(Frame::Object { values, key }) => {
            if let Some(key) = key.take() {
                if values.insert(key, value).is_some() {
                    return Err(invalid());
                }
            } else {
                let Value::String(next) = value else {
                    return Err(invalid());
                };
                // Merge keys are never interpreted, including without aliases.
                if next == "<<" || values.contains_key(&next) {
                    return Err(invalid());
                }
                *key = Some(next);
            }
        }
        None => {
            if root.replace(value).is_some() {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn yaml_value(text: &str) -> Result<Value, CliError> {
    // Check tokens before tree construction. Anchors/aliases are refused rather
    // than expanded, including unused anchors and all explicit tags/directives.
    let mut scanner = Scanner::new(text.chars());
    for (index, token) in scanner.by_ref().enumerate() {
        if index >= MAX_NODES * 4 {
            return Err(limit());
        }
        if matches!(
            token.1,
            TokenType::VersionDirective(..)
                | TokenType::TagDirective(..)
                | TokenType::Anchor(..)
                | TokenType::Alias(..)
                | TokenType::Tag(..)
        ) {
            return Err(invalid());
        }
    }
    if scanner.get_error().is_some() {
        return Err(invalid());
    }
    let mut parser = Parser::new_from_str(text);
    let mut stack = Vec::new();
    let mut root = None;
    let mut nodes = 0;
    let mut documents = 0;
    let mut ended = false;
    loop {
        let event = parser.next_token().map_err(|_| invalid())?.0;
        match event {
            Event::StreamStart => {}
            Event::DocumentStart => {
                documents += 1;
                if documents != 1 {
                    return Err(invalid());
                }
            }
            Event::DocumentEnd => {
                if !stack.is_empty() || root.is_none() {
                    return Err(invalid());
                }
                ended = true;
            }
            Event::StreamEnd => {
                if documents != 1 || !ended || !stack.is_empty() {
                    return Err(invalid());
                }
                return root.ok_or_else(invalid);
            }
            Event::Scalar(value, style, 0, None) => {
                count_node(stack.len(), &mut nodes)?;
                scalar(&value)?;
                let value = if style == TScalarStyle::Plain {
                    yaml_scalar(value)?
                } else {
                    Value::String(value)
                };
                append(value, &mut stack, &mut root)?;
            }
            Event::SequenceStart(0, None) => {
                count_node(stack.len(), &mut nodes)?;
                stack.push(Frame::Array(Vec::new()));
            }
            Event::MappingStart(0, None) => {
                count_node(stack.len(), &mut nodes)?;
                stack.push(Frame::Object {
                    values: Map::new(),
                    key: None,
                });
            }
            Event::SequenceEnd => {
                let Some(Frame::Array(values)) = stack.pop() else {
                    return Err(invalid());
                };
                append(Value::Array(values), &mut stack, &mut root)?;
            }
            Event::MappingEnd => {
                let Some(Frame::Object { values, key: None }) = stack.pop() else {
                    return Err(invalid());
                };
                append(Value::Object(values), &mut stack, &mut root)?;
            }
            _ => return Err(invalid()),
        }
    }
}

fn yaml_scalar(value: String) -> Result<Value, CliError> {
    match value.as_str() {
        "" | "~" | "null" | "Null" | "NULL" => return Ok(Value::Null),
        "true" | "True" | "TRUE" => return Ok(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Ok(Value::Bool(false)),
        _ => {}
    }
    let unsigned = value.strip_prefix('+').unwrap_or(&value);
    if !unsigned.is_empty() && unsigned.bytes().all(|b| b.is_ascii_digit()) {
        return unsigned
            .parse::<u64>()
            .map(|n| Value::Number(n.into()))
            .map_err(|_| invalid());
    }
    if let Some(digits) = value.strip_prefix('-') {
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            return value
                .parse::<i64>()
                .map(|n| Value::Number(n.into()))
                .map_err(|_| invalid());
        }
    }
    for (prefix, radix) in [("0x", 16), ("0o", 8)] {
        if let Some(digits) = unsigned.strip_prefix(prefix) {
            return u64::from_str_radix(digits, radix)
                .map(|n| Value::Number(n.into()))
                .map_err(|_| invalid());
        }
    }
    if matches!(
        value.to_ascii_lowercase().as_str(),
        ".nan" | ".inf" | "+.inf" | "-.inf"
    ) {
        return Err(invalid());
    }
    if value.contains(['.', 'e', 'E']) {
        if let Ok(number) = value.parse::<f64>() {
            return Number::from_f64(number)
                .map(Value::Number)
                .ok_or_else(invalid);
        }
    }
    Ok(Value::String(value))
}
