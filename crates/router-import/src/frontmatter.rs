//! Bounded YAML frontmatter reader. Only `name` and `description` are read;
//! every other key is recorded by name and otherwise discarded, so fields such
//! as `permissions`, `tools` or `model` can never create authority.
use std::collections::BTreeSet;
use yaml_rust2::{
    parser::{Event, Parser},
    scanner::{Scanner, TokenType},
};

pub(crate) const MAX_FRONTMATTER_BYTES: usize = 16 * 1024;
const MAX_NODES: usize = 512;
const MAX_DEPTH: usize = 8;
const MAX_SCALAR_BYTES: usize = 4096;
const MAX_KEY_BYTES: usize = 64;

#[derive(Debug, Default)]
pub(crate) struct Frontmatter {
    pub name: Option<String>,
    pub description: Option<String>,
    pub ignored: BTreeSet<String>,
}

/// Splits `---` delimited frontmatter from the body. `None` when absent,
/// unterminated or larger than the bound.
pub(crate) fn split(text: &str) -> Option<&str> {
    let rest = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))?;
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim_end_matches(['\n', '\r']) == "---" {
            return (offset <= MAX_FRONTMATTER_BYTES).then(|| &rest[..offset]);
        }
        offset += line.len();
        if offset > MAX_FRONTMATTER_BYTES {
            return None;
        }
    }
    None
}

/// Anchors, aliases, tags and directives are refused rather than expanded.
pub(crate) fn parse(text: &str) -> Result<Frontmatter, ()> {
    let mut scanner = Scanner::new(text.chars());
    for (index, token) in scanner.by_ref().enumerate() {
        if index >= MAX_NODES * 4
            || matches!(
                token.1,
                TokenType::VersionDirective(..)
                    | TokenType::TagDirective(..)
                    | TokenType::Anchor(..)
                    | TokenType::Alias(..)
                    | TokenType::Tag(..)
            )
        {
            return Err(());
        }
    }
    if scanner.get_error().is_some() {
        return Err(());
    }
    let mut parser = Parser::new_from_str(text);
    let mut out = Frontmatter::default();
    let mut seen = BTreeSet::new();
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut documents = 0;
    let mut key: Option<String> = None;
    loop {
        let event = parser.next_token().map_err(|_| ())?.0;
        match event {
            Event::StreamStart => {}
            Event::DocumentStart => {
                documents += 1;
                if documents != 1 {
                    return Err(());
                }
            }
            Event::DocumentEnd => {}
            Event::StreamEnd => {
                return if documents == 1 && depth == 0 {
                    Ok(out)
                } else {
                    Err(())
                };
            }
            Event::MappingStart(0, None) if depth == 0 => {
                nodes += 1;
                depth = 1;
            }
            Event::MappingStart(0, None) | Event::SequenceStart(0, None) if depth >= 1 => {
                // A nested value; a container can never be a key.
                nodes += 1;
                if key.is_none() || depth >= MAX_DEPTH {
                    return Err(());
                }
                depth += 1;
            }
            Event::MappingEnd | Event::SequenceEnd => {
                depth = depth.checked_sub(1).ok_or(())?;
                if depth == 1 {
                    settle(&mut key, &mut out, &mut seen, None)?;
                }
            }
            Event::Scalar(value, _, 0, None) => {
                nodes += 1;
                if value.len() > MAX_SCALAR_BYTES {
                    return Err(());
                }
                match depth {
                    1 => match key.take() {
                        None => {
                            if value.is_empty() || value.len() > MAX_KEY_BYTES {
                                return Err(());
                            }
                            key = Some(value);
                        }
                        Some(name) => {
                            key = Some(name);
                            settle(&mut key, &mut out, &mut seen, Some(value))?;
                        }
                    },
                    d if d > 1 => {}
                    _ => return Err(()),
                }
            }
            _ => return Err(()),
        }
        if nodes > MAX_NODES {
            return Err(());
        }
    }
}

fn settle(
    key: &mut Option<String>,
    out: &mut Frontmatter,
    seen: &mut BTreeSet<String>,
    scalar: Option<String>,
) -> Result<(), ()> {
    let name = key.take().ok_or(())?;
    if !seen.insert(name.clone()) {
        return Err(());
    }
    match (name.as_str(), scalar) {
        ("name", Some(value)) => out.name = Some(value),
        ("description", Some(value)) => out.description = Some(value),
        // `name` or `description` holding a container is malformed.
        ("name" | "description", None) => return Err(()),
        _ => {
            out.ignored.insert(name);
        }
    }
    Ok(())
}
