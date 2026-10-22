//! Structured validation contracts evaluated against a caller-supplied view.
//!
//! The evaluator performs no I/O and spawns no process. It only proves that the
//! supplied view satisfies the contract. Binding the view to a real artifact is
//! the caller's responsibility (R13-b). A report always leaves `objective` at
//! UNKNOWN: satisfying a contract is not evidence that the task goal was met.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CONTRACT_VERSION: u32 = 1;
pub const REPORT_SCHEMA: &str = "router.validation.report.v1";
pub const MAX_CONTRACT_BYTES: usize = 64 * 1024;
pub const MAX_ASSERTIONS: usize = 64;
pub const MAX_SCOPE_ENTRIES: usize = 64;
pub const MAX_PATH_BYTES: usize = 512;
pub const MAX_POINTER_BYTES: usize = 512;
pub const MAX_CHANGED_PATHS: usize = 4096;
pub const MAX_VIEW_FILES: usize = 1024;
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_JSON_DEPTH: usize = 32;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("contract exceeds {MAX_CONTRACT_BYTES} bytes")]
    ContractTooLarge,
    #[error("contract JSON nesting exceeds {MAX_JSON_DEPTH}")]
    ContractTooDeep,
    #[error("invalid contract: {0}")]
    InvalidContract(String),
    #[error("unsupported contract version {0}")]
    UnsupportedVersion(u32),
    #[error("contract has no assertions")]
    NoAssertions,
    #[error("contract has more than {MAX_ASSERTIONS} assertions")]
    TooManyAssertions,
    #[error("scope has more than {MAX_SCOPE_ENTRIES} entries")]
    TooManyScopeEntries,
    #[error("changed_paths_within_scope requires a non-empty scope")]
    ScopeRequired,
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("invalid sha256 in assertion {0}")]
    InvalidDigest(usize),
    #[error("invalid JSON pointer in assertion {0}")]
    InvalidPointer(usize),
    #[error("max_bytes in assertion {0} exceeds {MAX_FILE_BYTES}")]
    SizeBoundTooLarge(usize),
    #[error("view has too many changed paths or files")]
    ViewTooLarge,
    #[error("view file {0} exceeds {MAX_FILE_BYTES} bytes")]
    ViewFileTooLarge(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationContract {
    pub version: u32,
    #[serde(default)]
    pub scope: Vec<String>,
    pub assertions: Vec<Assertion>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Assertion {
    ChangedPathsWithinScope {},
    PathPresent {
        path: String,
    },
    PathAbsent {
        path: String,
    },
    Sha256 {
        path: String,
        sha256: String,
    },
    JsonPointerEquals {
        path: String,
        pointer: String,
        value: Value,
    },
    MaxSize {
        path: String,
        max_bytes: u64,
    },
}

impl Assertion {
    fn kind(&self) -> AssertionKind {
        match self {
            Self::ChangedPathsWithinScope {} => AssertionKind::ChangedPathsWithinScope,
            Self::PathPresent { .. } => AssertionKind::PathPresent,
            Self::PathAbsent { .. } => AssertionKind::PathAbsent,
            Self::Sha256 { .. } => AssertionKind::Sha256,
            Self::JsonPointerEquals { .. } => AssertionKind::JsonPointerEquals,
            Self::MaxSize { .. } => AssertionKind::MaxSize,
        }
    }
}

/// A contract that passed every structural bound. Fields are private so an
/// unchecked contract cannot be evaluated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedContract {
    contract: ValidationContract,
    sha256: String,
}

impl ValidatedContract {
    pub fn contract(&self) -> &ValidationContract {
        &self.contract
    }

    /// Digest of the exact contract bytes that were parsed.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

pub fn parse_contract(bytes: &[u8]) -> Result<ValidatedContract, ValidationError> {
    if bytes.len() > MAX_CONTRACT_BYTES {
        return Err(ValidationError::ContractTooLarge);
    }
    if !within_depth(bytes) {
        return Err(ValidationError::ContractTooDeep);
    }
    let value =
        strict_json(bytes).map_err(|error| ValidationError::InvalidContract(error.to_string()))?;
    let contract: ValidationContract = serde_json::from_value(value)
        .map_err(|error| ValidationError::InvalidContract(error.to_string()))?;
    check_contract(&contract)?;
    Ok(ValidatedContract {
        contract,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

/// Parses JSON and rejects duplicate object keys at every depth, so a
/// `JsonPointerEquals.value` cannot silently merge repeated keys.
fn strict_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
    struct Strict(Value);
    struct StrictVisitor;
    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = Strict;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("JSON with unique object keys")
        }
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Strict, E> {
            Ok(Strict(value.into()))
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Strict, E> {
            Ok(Strict(value.into()))
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Strict, E> {
            Ok(Strict(value.into()))
        }
        fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Strict, E> {
            serde_json::Number::from_f64(value)
                .map(|number| Strict(number.into()))
                .ok_or_else(|| E::custom("non-finite number"))
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Strict, E> {
            Ok(Strict(value.into()))
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Strict, E> {
            Ok(Strict(value.into()))
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
            Ok(Strict(Value::Null))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
            let mut items = Vec::new();
            while let Some(Strict(item)) = seq.next_element()? {
                items.push(item);
            }
            Ok(Strict(items.into()))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
            let mut fields = serde_json::Map::new();
            while let Some((key, Strict(item))) = map.next_entry::<String, Strict>()? {
                if fields.insert(key, item).is_some() {
                    return Err(A::Error::custom("duplicate object key"));
                }
            }
            Ok(Strict(fields.into()))
        }
    }
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_any(StrictVisitor)
        }
    }
    serde_json::from_slice::<Strict>(bytes).map(|strict| strict.0)
}

fn check_contract(contract: &ValidationContract) -> Result<(), ValidationError> {
    if contract.version != CONTRACT_VERSION {
        return Err(ValidationError::UnsupportedVersion(contract.version));
    }
    if contract.assertions.is_empty() {
        return Err(ValidationError::NoAssertions);
    }
    if contract.assertions.len() > MAX_ASSERTIONS {
        return Err(ValidationError::TooManyAssertions);
    }
    if contract.scope.len() > MAX_SCOPE_ENTRIES {
        return Err(ValidationError::TooManyScopeEntries);
    }
    for entry in &contract.scope {
        check_path(entry)?;
    }
    for (index, assertion) in contract.assertions.iter().enumerate() {
        match assertion {
            Assertion::ChangedPathsWithinScope {} => {
                if contract.scope.is_empty() {
                    return Err(ValidationError::ScopeRequired);
                }
            }
            Assertion::PathPresent { path } | Assertion::PathAbsent { path } => check_path(path)?,
            Assertion::Sha256 { path, sha256 } => {
                check_path(path)?;
                if sha256.len() != 64
                    || !sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(ValidationError::InvalidDigest(index));
                }
            }
            Assertion::JsonPointerEquals { path, pointer, .. } => {
                check_path(path)?;
                if pointer.len() > MAX_POINTER_BYTES
                    || !(pointer.is_empty() || pointer.starts_with('/'))
                {
                    return Err(ValidationError::InvalidPointer(index));
                }
            }
            Assertion::MaxSize { path, max_bytes } => {
                check_path(path)?;
                if *max_bytes > MAX_FILE_BYTES {
                    return Err(ValidationError::SizeBoundTooLarge(index));
                }
            }
        }
    }
    Ok(())
}

/// Relative, normalized, `/`-separated paths only.
fn check_path(path: &str) -> Result<(), ValidationError> {
    let bad = path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if bad {
        let shown: String = path.chars().take(64).collect();
        return Err(ValidationError::InvalidPath(shown));
    }
    Ok(())
}

/// Nesting depth of the raw JSON text, computed before any recursive parse.
fn within_depth(bytes: &[u8]) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &byte in bytes {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Caller-supplied facts. The evaluator never reads the disk.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ValidationView {
    pub changed_paths: Vec<String>,
    /// Present files and their contents. A missing key means the path is absent.
    pub files: BTreeMap<String, Vec<u8>>,
}

impl ValidationView {
    fn check(&self) -> Result<BTreeSet<&str>, ValidationError> {
        if self.changed_paths.len() > MAX_CHANGED_PATHS || self.files.len() > MAX_VIEW_FILES {
            return Err(ValidationError::ViewTooLarge);
        }
        for path in &self.changed_paths {
            check_path(path)?;
        }
        for (path, content) in &self.files {
            check_path(path)?;
            if content.len() as u64 > MAX_FILE_BYTES {
                return Err(ValidationError::ViewFileTooLarge(path.clone()));
            }
        }
        Ok(self.changed_paths.iter().map(String::as_str).collect())
    }

    fn digest(&self, changed: &BTreeSet<&str>) -> String {
        #[derive(Serialize)]
        struct Canonical<'a> {
            changed_paths: &'a BTreeSet<&'a str>,
            files: BTreeMap<&'a str, String>,
        }
        let files = self
            .files
            .iter()
            .map(|(path, content)| (path.as_str(), hex::encode(Sha256::digest(content))))
            .collect();
        digest_json(&Canonical {
            changed_paths: changed,
            files,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionKind {
    ChangedPathsWithinScope,
    PathPresent,
    PathAbsent,
    Sha256,
    JsonPointerEquals,
    MaxSize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    OutOfScope,
    PathMissing,
    PathPresent,
    DigestMismatch,
    InvalidJson,
    JsonTooDeep,
    PointerMissing,
    PointerMismatch,
    SizeExceeded,
}

/// The task goal is never established by a structural contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Objective {
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionResult {
    pub index: u32,
    pub kind: AssertionKind,
    pub path: Option<String>,
    pub outcome: Outcome,
    pub code: Option<FailureCode>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    pub schema: String,
    pub contract_sha256: String,
    pub view_sha256: String,
    pub validation: Outcome,
    pub objective: Objective,
    pub results: Vec<AssertionResult>,
    /// Digest of the report body. It has the 64 lowercase hex format that
    /// `VerificationRecord.evidence_sha256` expects; it is not an attestation.
    pub evidence_sha256: String,
}

#[derive(Serialize)]
struct ReportBody<'a> {
    schema: &'a str,
    contract_sha256: &'a str,
    view_sha256: &'a str,
    validation: Outcome,
    objective: Objective,
    results: &'a [AssertionResult],
}

impl ValidationReport {
    fn body_digest(&self) -> String {
        digest_json(&ReportBody {
            schema: &self.schema,
            contract_sha256: &self.contract_sha256,
            view_sha256: &self.view_sha256,
            validation: self.validation,
            objective: self.objective,
            results: &self.results,
        })
    }

    /// True when `evidence_sha256` matches the report body.
    pub fn digest_is_consistent(&self) -> bool {
        self.evidence_sha256 == self.body_digest()
    }

    /// Canonical bytes of the whole report.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        // Infallible: plain structs and enums with string keys only.
        serde_json::to_vec(self).expect("report serialization is infallible")
    }
}

fn digest_json<T: Serialize>(value: &T) -> String {
    // Infallible: callers pass plain structs and enums with string keys only.
    let bytes = serde_json::to_vec(value).expect("digest input serialization is infallible");
    hex::encode(Sha256::digest(bytes))
}

pub fn evaluate(
    contract: &ValidatedContract,
    view: &ValidationView,
) -> Result<ValidationReport, ValidationError> {
    let changed = view.check()?;
    let scope = &contract.contract.scope;
    let results: Vec<AssertionResult> = contract
        .contract
        .assertions
        .iter()
        .enumerate()
        .map(|(index, assertion)| {
            let (path, code) = check_assertion(assertion, scope, &changed, view);
            AssertionResult {
                index: index as u32,
                kind: assertion.kind(),
                path,
                outcome: if code.is_none() {
                    Outcome::Passed
                } else {
                    Outcome::Failed
                },
                code,
            }
        })
        .collect();
    let validation = if results.iter().all(|r| r.outcome == Outcome::Passed) {
        Outcome::Passed
    } else {
        Outcome::Failed
    };
    let mut report = ValidationReport {
        schema: REPORT_SCHEMA.to_owned(),
        contract_sha256: contract.sha256.clone(),
        view_sha256: view.digest(&changed),
        validation,
        objective: Objective::Unknown,
        results,
        evidence_sha256: String::new(),
    };
    report.evidence_sha256 = report.body_digest();
    Ok(report)
}

fn in_scope(scope: &[String], path: &str) -> bool {
    scope.iter().any(|entry| {
        path == entry
            || path
                .strip_prefix(entry.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn check_assertion(
    assertion: &Assertion,
    scope: &[String],
    changed: &BTreeSet<&str>,
    view: &ValidationView,
) -> (Option<String>, Option<FailureCode>) {
    match assertion {
        Assertion::ChangedPathsWithinScope {} => {
            let offender = changed.iter().find(|path| !in_scope(scope, path));
            (
                offender.map(|p| (*p).to_owned()),
                offender.map(|_| FailureCode::OutOfScope),
            )
        }
        Assertion::PathPresent { path } => {
            let code = (!view.files.contains_key(path)).then_some(FailureCode::PathMissing);
            (Some(path.clone()), code)
        }
        Assertion::PathAbsent { path } => {
            let code = view
                .files
                .contains_key(path)
                .then_some(FailureCode::PathPresent);
            (Some(path.clone()), code)
        }
        Assertion::Sha256 { path, sha256 } => {
            let code = match view.files.get(path) {
                None => Some(FailureCode::PathMissing),
                Some(content) if hex::encode(Sha256::digest(content)) == *sha256 => None,
                Some(_) => Some(FailureCode::DigestMismatch),
            };
            (Some(path.clone()), code)
        }
        Assertion::JsonPointerEquals {
            path,
            pointer,
            value,
        } => {
            let code = match view.files.get(path) {
                None => Some(FailureCode::PathMissing),
                Some(content) => check_pointer(content, pointer, value),
            };
            (Some(path.clone()), code)
        }
        Assertion::MaxSize { path, max_bytes } => {
            let code = match view.files.get(path) {
                None => Some(FailureCode::PathMissing),
                Some(content) if content.len() as u64 <= *max_bytes => None,
                Some(_) => Some(FailureCode::SizeExceeded),
            };
            (Some(path.clone()), code)
        }
    }
}

fn check_pointer(content: &[u8], pointer: &str, expected: &Value) -> Option<FailureCode> {
    if !within_depth(content) {
        return Some(FailureCode::JsonTooDeep);
    }
    let Ok(document) = serde_json::from_slice::<Value>(content) else {
        return Some(FailureCode::InvalidJson);
    };
    match document.pointer(pointer) {
        None => Some(FailureCode::PointerMissing),
        Some(found) if found == expected => None,
        Some(_) => Some(FailureCode::PointerMismatch),
    }
}
