use router_types::{SkillTrust, TaskKind};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    Agent,
    Skill,
    Prompt,
    Tool,
    Model,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetKey {
    pub kind: AssetKind,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BodyReference {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetMetadata {
    pub id: String,
    pub kind: AssetKind,
    pub trust: SkillTrust,
    #[serde(default)]
    pub task_kinds: Vec<TaskKind>,
    #[serde(default)]
    pub triggers: Vec<String>,
    pub description: String,
    #[serde(default)]
    pub examples: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub anti_triggers: Vec<String>,
    #[serde(default)]
    pub body: Option<BodyReference>,
}

impl AssetMetadata {
    pub fn key(&self) -> AssetKey {
        AssetKey {
            kind: self.kind,
            id: self.id.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataDocument {
    pub schema_version: String,
    pub catalog_version: String,
    pub assets: Vec<AssetMetadata>,
}

/// Version 2 binds canonical metadata to an independently supplied catalog
/// content digest. Neither digest authenticates the source of its contents.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEnvelope {
    pub schema_version: String,
    pub catalog_content_sha256: String,
    pub metadata_content_sha256: String,
    pub metadata: MetadataDocument,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Identifier,
    TaskKinds,
    Triggers,
    Description,
    Examples,
    Tags,
    Paths,
}

impl Field {
    /// Every field in declaration order; the index hash lists boosts in this order.
    pub(crate) const ALL: [Field; 7] = [
        Self::Identifier,
        Self::TaskKinds,
        Self::Triggers,
        Self::Description,
        Self::Examples,
        Self::Tags,
        Self::Paths,
    ];

    pub fn boost_millis(self) -> u32 {
        match self {
            Self::Identifier => 8000,
            Self::TaskKinds => 6000,
            Self::Triggers => 5000,
            Self::Description => 3000,
            Self::Examples => 2500,
            Self::Tags | Self::Paths => 2000,
        }
    }
}

/// These defaults are conservative policy parameters, not calibrated recall claims.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPolicy {
    pub minimum_score_micros: u64,
    pub minimum_coverage_micros: u32,
    pub ambiguity_margin_micros: u32,
}

impl Default for SearchPolicy {
    fn default() -> Self {
        Self {
            minimum_score_micros: 500_000,
            minimum_coverage_micros: 250_000,
            ambiguity_margin_micros: 100_000,
        }
    }
}

fn default_top_k() -> usize {
    5
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    pub text: String,
    #[serde(default)]
    pub kind: Option<AssetKind>,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    #[serde(default)]
    pub policy: SearchPolicy,
}

impl SearchQuery {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            kind: None,
            top_k: 5,
            policy: SearchPolicy::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatchEvidence {
    pub field: Field,
    pub term: String,
    pub term_frequency: u32,
    pub document_frequency: u32,
    pub field_length: u32,
    pub boost_millis: u32,
    pub contribution_micros: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FieldScore {
    pub field: Field,
    pub score_micros: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SearchCandidate {
    pub asset: AssetKey,
    pub trust: SkillTrust,
    /// Unnormalized lexical BM25 score. This is evidence, never route utility.
    pub bm25_micros: u64,
    /// 0..=1_000_000; always zero for untrusted assets.
    pub route_utility_micros: i64,
    pub coverage_micros: u32,
    pub fields: Vec<FieldScore>,
    pub evidence: Vec<MatchEvidence>,
    /// Exact quoted phrases found contiguously in the matched metadata field.
    pub phrase_evidence: Vec<PhraseEvidence>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PhraseEvidence {
    pub field: Field,
    pub phrase: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Abstention {
    EmptyQuery,
    NoMatches,
    UntrustedOnly,
    WeakMatch,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    Blocked,
    AntiTrigger,
    RequiredPhraseMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Exclusion {
    pub asset: AssetKey,
    pub reason: ExclusionReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SearchResult {
    pub schema_version: String,
    pub catalog_version: String,
    /// Absent in legacy v1 results, which are explicitly unbound to a catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_content_sha256: Option<String>,
    pub source_hash: String,
    pub index_hash: String,
    pub policy: SearchPolicy,
    pub candidates: Vec<SearchCandidate>,
    pub selected: Option<AssetKey>,
    pub abstention: Option<Abstention>,
    /// Bounded to MAX_RESULTS. excluded_count gives the full count.
    pub exclusions: Vec<Exclusion>,
    pub excluded_count: usize,
    pub postings_visited: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedBody {
    pub asset: AssetKey,
    pub sha256: String,
    pub text: String,
}
