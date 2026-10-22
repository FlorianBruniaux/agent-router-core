use std::collections::BTreeMap;

/// Keep full technical tokens (e.g. C++, src/lib.rs, foo::bar) alongside words.
/// Delimiters are deterministic and language-independent. No stemming or stop list.
pub(crate) fn terms(text: &str) -> BTreeMap<String, u32> {
    let lower = text.to_lowercase();
    let mut result = BTreeMap::new();
    for word in lower
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
    {
        *result.entry(word.to_string()).or_default() += 1;
    }
    for token in lower.split_whitespace() {
        let token = token.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';' | '!' | '?'
            )
        });
        if !token.is_empty()
            && token
                .chars()
                .any(|c| matches!(c, '_' | '-' | '.' | '/' | ':' | '+' | '#'))
        {
            *result.entry(token.to_string()).or_default() += 1;
        }
    }
    result
}

/// Distinct quoted phrases in first-occurrence order. More than
/// `MAX_QUERY_PHRASES` distinct phrases is a limit error: every phrase is
/// matched against every field of every candidate asset.
pub(crate) fn quoted_phrases(text: &str) -> crate::Result<Vec<String>> {
    let mut phrases: Vec<String> = Vec::new();
    for candidate in text.split('"').skip(1).step_by(2).map(phrase) {
        if candidate.is_empty() || phrases.contains(&candidate) {
            continue;
        }
        if phrases.len() >= crate::MAX_QUERY_PHRASES {
            return Err(crate::RetrievalError::Limit("query phrases"));
        }
        phrases.push(candidate);
    }
    Ok(phrases)
}

pub(crate) fn phrase(text: &str) -> String {
    text.to_lowercase()
        .split(|c: char| {
            !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':' | '+' | '#'))
        })
        .map(|token| token.trim_end_matches(['.', ':']))
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}
