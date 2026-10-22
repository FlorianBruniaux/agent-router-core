//! Inert importer: turns an explicitly named local directory of Markdown agent
//! and skill definitions into an UNSIGNED candidate `SignedCatalogManifest`
//! plus an import report. It signs nothing, grants nothing, activates nothing
//! and writes only a brand-new output file. Every imported asset is `untrusted`
//! with UNKNOWN permission, no tools, no mutations and a read-only sandbox.
//! Skill scripts are refused (R08 owns any executable-skill decision).
mod frontmatter;
mod scan;

use router_catalog::{
    CatalogAssetKind, SignedAssetPayload, SignedAssetRequirements, SignedAssetRestrictions,
    SignedCatalogEntry, SignedCatalogError, SignedCatalogManifest, seal_signed_manifest,
};
use router_retrieval::{AssetKey, AssetKind, AssetMetadata, AssetSignals, BodyReference, Signal};
use router_types::{
    AssetSourceProvenance, CapabilitySupport, DataSensitivity, PhaseAssetKind,
    PhaseRegisteredAsset, PhaseSandbox, SkillId, SkillSpec, SkillTrust,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const MAX_DESCRIPTION_BYTES: usize = 2048;
const MAX_ID_BYTES: usize = 96;

/// Report paths are operator-facing text: control and bidirectional characters
/// are written as `\u{..}` and a literal backslash as `\\`, so a hostile file
/// name cannot inject terminal escapes or reorder the rendered report.
pub(crate) fn escape_path(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for c in path.chars() {
        if c == '\\' {
            escaped.push_str("\\\\");
        } else if c.is_control() || router_catalog::is_bidi_control(c) {
            escaped.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            escaped.push(c);
        }
    }
    escaped
}

/// Everything except the directory contents is supplied by the operator.
/// Frontmatter `license`, `author`, `source` and similar keys are ignored.
#[derive(Clone, Debug)]
pub struct ImportRequest {
    pub source_dir: PathBuf,
    pub catalog_id: String,
    pub catalog_version: String,
    /// Public locator or identifier, never a local path.
    pub source_locator: String,
    pub revision: String,
    pub license_expression: String,
    pub authors: Vec<String>,
    pub valid_from_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("import.request: {0}")]
    Request(&'static str),
    #[error("import.source: {0}")]
    Source(&'static str),
    #[error("import.limit: {0}")]
    Limit(&'static str),
    #[error("import.io: {0}")]
    Io(&'static str),
    #[error("import.no_assets")]
    NoAssets,
    #[error("import.catalog: {0}")]
    Catalog(#[from] SignedCatalogError),
    #[error("import.output_exists")]
    OutputExists,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    Symlink,
    NotRegular,
    UnsafePath,
    TooLarge,
    NotUtf8,
    Unreadable,
    UnsupportedFile,
    /// Skill scripts and any executable file are refused; see R08.
    #[serde(rename = "executable_script_see_r08")]
    ExecutableScript,
    InvalidFrontmatter,
    MissingName,
    InvalidName,
    MissingDescription,
    InvalidDescription,
    DuplicateId,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct RefusedFile {
    pub path: String,
    pub reason: RefusalReason,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImportedAsset {
    pub kind: CatalogAssetKind,
    pub id: String,
    pub path: String,
    pub body_sha256: String,
    /// Frontmatter keys read by nobody: they granted nothing.
    pub ignored_frontmatter_keys: Vec<String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NameConflict {
    pub id: String,
    pub paths: Vec<String>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ImportReport {
    pub imported: Vec<ImportedAsset>,
    pub refused: Vec<RefusedFile>,
    pub name_conflicts: Vec<NameConflict>,
}

#[derive(Clone, Debug)]
pub struct ImportOutput {
    pub manifest: SignedCatalogManifest,
    pub report: ImportReport,
}
impl ImportOutput {
    /// Deterministic bytes of the unsigned candidate manifest.
    pub fn manifest_bytes(&self) -> Result<Vec<u8>, ImportError> {
        canonical(&self.manifest)
    }
    pub fn report_bytes(&self) -> Result<Vec<u8>, ImportError> {
        canonical(&self.report)
    }
    /// Writes both files, each with create-new semantics. An existing path is
    /// refused and nothing pre-existing is touched; a file created here is
    /// removed again if its sibling cannot be written.
    pub fn write_new(&self, manifest_path: &Path, report_path: &Path) -> Result<(), ImportError> {
        if manifest_path == report_path {
            return Err(ImportError::Request("output paths must differ"));
        }
        let manifest = self.manifest_bytes()?;
        let report = self.report_bytes()?;
        let created = create_new(manifest_path, &manifest)?;
        if let Err(error) = create_new(report_path, &report) {
            created.remove();
            return Err(error);
        }
        Ok(())
    }
}

fn canonical(value: &impl Serialize) -> Result<Vec<u8>, ImportError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|_| ImportError::Io("serialize output"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Identity of a file this process created, so cleanup never removes a file
/// that another party substituted at the same path.
struct Created {
    path: PathBuf,
    identity: Option<(u64, u64)>,
}
impl Created {
    fn remove(&self) {
        let same = match (self.identity, fs::symlink_metadata(&self.path)) {
            (Some(id), Ok(meta)) => file_identity(&meta) == Some(id),
            (None, Ok(_)) => true,
            (_, Err(_)) => false,
        };
        if same {
            let _ = fs::remove_file(&self.path);
        }
    }
}
#[cfg(unix)]
fn file_identity(meta: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((meta.dev(), meta.ino()))
}
#[cfg(not(unix))]
fn file_identity(_: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

fn create_new(path: &Path, bytes: &[u8]) -> Result<Created, ImportError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ImportError::OutputExists
        } else {
            ImportError::Io("create output")
        }
    })?;
    let created = Created {
        path: path.to_owned(),
        identity: file.metadata().ok().and_then(|meta| file_identity(&meta)),
    };
    if file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        created.remove();
        return Err(ImportError::Io("write output"));
    }
    Ok(created)
}

pub fn import_directory(request: &ImportRequest) -> Result<ImportOutput, ImportError> {
    validate_request(request)?;
    let scanned = scan::scan(&request.source_dir).map_err(|failure| match failure {
        scan::ScanFailure::Source(reason) => ImportError::Source(reason),
        scan::ScanFailure::Limit(reason) => ImportError::Limit(reason),
        scan::ScanFailure::Io(reason) => ImportError::Io(reason),
    })?;
    let mut report = ImportReport {
        refused: scanned.refused,
        ..ImportReport::default()
    };
    let mut parsed = Vec::new();
    for file in scanned.files {
        match parse_definition(&file.bytes) {
            Ok((id, description, ignored)) => parsed.push((file, id, description, ignored)),
            Err(reason) => report.refused.push(RefusedFile {
                path: escape_path(&file.relative),
                reason,
            }),
        }
    }
    // A shared name is ambiguous: neither file is imported.
    let mut by_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, id, _, _) in &parsed {
        by_id
            .entry(id.clone())
            .or_default()
            .push(file.relative.clone());
    }
    let duplicated: BTreeSet<String> = by_id
        .iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(id, _)| id.clone())
        .collect();
    for id in &duplicated {
        let mut paths = by_id[id].clone();
        paths.sort();
        for path in &paths {
            report.refused.push(RefusedFile {
                path: escape_path(path),
                reason: RefusalReason::DuplicateId,
            });
        }
        report.name_conflicts.push(NameConflict {
            id: id.clone(),
            paths,
        });
    }
    let mut assets = Vec::new();
    for (file, id, description, ignored) in parsed {
        if duplicated.contains(&id) {
            continue;
        }
        let body_sha256 = hex::encode(Sha256::digest(&file.bytes));
        let kind = if file.agent {
            CatalogAssetKind::Agent
        } else {
            CatalogAssetKind::Skill
        };
        assets.push(build_entry(
            request,
            kind,
            &id,
            &description,
            &file.relative,
            &body_sha256,
            file.bytes.len(),
        )?);
        report.imported.push(ImportedAsset {
            kind,
            id,
            path: file.relative,
            body_sha256,
            ignored_frontmatter_keys: ignored.into_iter().collect(),
        });
    }
    if assets.is_empty() {
        return Err(ImportError::NoAssets);
    }
    report.imported.sort_by(|a, b| a.path.cmp(&b.path));
    report.refused.sort();
    let manifest = seal_signed_manifest(SignedCatalogManifest {
        schema_version: 1,
        id: request.catalog_id.clone(),
        version: request.catalog_version.clone(),
        valid_from_unix_seconds: request.valid_from_unix_seconds,
        valid_until_unix_seconds: request.valid_until_unix_seconds,
        assets,
        content_sha256: String::new(),
    })?;
    Ok(ImportOutput { manifest, report })
}

fn parse_definition(bytes: &[u8]) -> Result<(String, String, BTreeSet<String>), RefusalReason> {
    let text = std::str::from_utf8(bytes).map_err(|_| RefusalReason::NotUtf8)?;
    let yaml = frontmatter::split(text).ok_or(RefusalReason::InvalidFrontmatter)?;
    let front = frontmatter::parse(yaml).map_err(|()| RefusalReason::InvalidFrontmatter)?;
    let name = front.name.ok_or(RefusalReason::MissingName)?;
    if !valid_id(&name) {
        return Err(RefusalReason::InvalidName);
    }
    let description = front.description.ok_or(RefusalReason::MissingDescription)?;
    let description = description.split_whitespace().collect::<Vec<_>>().join(" ");
    if description.is_empty() {
        return Err(RefusalReason::MissingDescription);
    }
    if description.len() > MAX_DESCRIPTION_BYTES
        || description
            .chars()
            .any(|c| c.is_control() || router_catalog::is_bidi_control(c))
    {
        return Err(RefusalReason::InvalidDescription);
    }
    Ok((name, description, front.ignored))
}

/// Stricter than the catalog label: no separators, no leading dot, no `..`.
fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && !value.starts_with(['.', '-'])
        && !value.contains("..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn build_entry(
    request: &ImportRequest,
    kind: CatalogAssetKind,
    id: &str,
    description: &str,
    path: &str,
    body_sha256: &str,
    body_len: usize,
) -> Result<SignedCatalogEntry, ImportError> {
    let sandboxes = BTreeSet::from([PhaseSandbox::ReadOnly]);
    let (payload, retrieval_kind) = match kind {
        CatalogAssetKind::Agent => (
            SignedAssetPayload::Agent(PhaseRegisteredAsset {
                kind: PhaseAssetKind::Agent,
                id: id.to_owned(),
                content_sha256: body_sha256.to_owned(),
                trust: SkillTrust::Untrusted,
                license: request.license_expression.clone(),
                permission: CapabilitySupport::Unknown,
                required_capabilities: BTreeSet::new(),
                required_mutations: BTreeSet::new(),
                allowed_sandboxes: sandboxes.clone(),
                maximum_sensitivity: DataSensitivity::Public,
            }),
            AssetKind::Agent,
        ),
        _ => (
            SignedAssetPayload::Skill(SkillSpec {
                id: SkillId::parse(id).map_err(|_| ImportError::Request("skill id"))?,
                description: description.to_owned(),
                task_kinds: BTreeSet::new(),
                required_capabilities: BTreeSet::new(),
                trust: SkillTrust::Untrusted,
            }),
            AssetKind::Skill,
        ),
    };
    Ok(SignedCatalogEntry {
        schema_version: 1,
        id: id.to_owned(),
        version: request.revision.clone(),
        provenance: AssetSourceProvenance {
            source: request.source_locator.clone(),
            revision: request.revision.clone(),
            source_sha256: body_sha256.to_owned(),
        },
        license_expression: request.license_expression.clone(),
        authors: request.authors.clone(),
        valid_from_unix_seconds: request.valid_from_unix_seconds,
        valid_until_unix_seconds: request.valid_until_unix_seconds,
        declared_trust: SkillTrust::Untrusted,
        capabilities: BTreeSet::new(),
        requirements: SignedAssetRequirements {
            capabilities: BTreeSet::new(),
            mutations: BTreeSet::new(),
            tools: BTreeSet::new(),
            compatible_hosts: BTreeSet::new(),
        },
        restrictions: SignedAssetRestrictions {
            allowed_mutations: BTreeSet::new(),
            allowed_sandboxes: sandboxes,
            maximum_sensitivity: DataSensitivity::Public,
        },
        context_cost_estimate: (body_len as u64).div_ceil(4),
        deprecated_by: None,
        payload_sha256: String::new(),
        payload,
        search: Some(AssetMetadata {
            id: id.to_owned(),
            kind: retrieval_kind,
            trust: SkillTrust::Untrusted,
            task_kinds: Vec::new(),
            triggers: Vec::new(),
            description: description.to_owned(),
            examples: Vec::new(),
            tags: Vec::new(),
            paths: Vec::new(),
            anti_triggers: Vec::new(),
            body: Some(BodyReference {
                path: path.to_owned(),
                sha256: body_sha256.to_owned(),
            }),
        }),
        signals: Some(AssetSignals {
            asset: AssetKey {
                kind: retrieval_kind,
                id: id.to_owned(),
            },
            languages: Signal::Unknown,
            required_tools: Signal::Unknown,
            history: Signal::Unknown,
        }),
    })
}

fn validate_request(request: &ImportRequest) -> Result<(), ImportError> {
    let need = |value: &str, limit: usize, what: &'static str| {
        if value.trim().is_empty() || value.len() > limit || value.chars().any(char::is_control) {
            Err(ImportError::Request(what))
        } else {
            Ok(())
        }
    };
    need(&request.catalog_id, 128, "catalog id")?;
    need(&request.catalog_version, 128, "catalog version")?;
    need(&request.revision, 128, "revision")?;
    need(&request.license_expression, 256, "license expression")?;
    need(&request.source_locator, 512, "source locator")?;
    // The signed catalog verifier predicate, so a candidate cannot carry a
    // locator that sealing would refuse.
    if !router_catalog::public_source(&request.source_locator) {
        return Err(ImportError::Request(
            "source locator must be a public locator",
        ));
    }
    if request.authors.is_empty() || request.authors.len() > 16 {
        return Err(ImportError::Request("authors"));
    }
    let mut seen = BTreeSet::new();
    for author in &request.authors {
        need(author, 128, "author")?;
        if !seen.insert(author) {
            return Err(ImportError::Request("duplicate author"));
        }
    }
    if request.valid_from_unix_seconds >= request.valid_until_unix_seconds {
        return Err(ImportError::Request("validity window"));
    }
    Ok(())
}
