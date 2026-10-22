use crate::*;
use router_types::{CapabilitySupport, TaskKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_HISTORY_SAMPLES: u32 = 1_000_000;
pub const MAX_SIGNAL_AGE_SECONDS: u64 = 30 * 86_400;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignalProvenance {
    pub source_id: String,
    pub source_version: String,
    pub source_sha256: String,
    pub observed_at_unix_seconds: u64,
}
impl SignalProvenance {
    fn validate(&self) -> Result<()> {
        if !fusion::valid_identifier(&self.source_id)
            || self.source_version.trim().is_empty()
            || self.source_version.len() > 128
            || self.source_version.chars().any(char::is_control)
        {
            return Err(RetrievalError::Invalid("signal provenance"));
        }
        index::validate_digest(&self.source_sha256)
    }
    fn fresh(&self, now: u64, age: u64) -> bool {
        self.observed_at_unix_seconds <= now && now - self.observed_at_unix_seconds <= age
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum Signal<T> {
    Unknown,
    Observed {
        value: T,
        provenance: SignalProvenance,
    },
}
impl<T> Signal<T> {
    fn observed(&self, now: u64, age: u64) -> Option<(&T, &SignalProvenance)> {
        match self {
            Self::Observed { value, provenance } if provenance.fresh(now, age) => {
                Some((value, provenance))
            }
            _ => None,
        }
    }
    fn validate(&self) -> Result<()> {
        match self {
            Self::Unknown => Ok(()),
            Self::Observed { provenance, .. } => provenance.validate(),
        }
    }
}
/// Imported outcome counts are attestations, not manufactured labels. Transport
/// completion is retained separately and never contributes to success ranking.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessHistory {
    pub task_kind: TaskKind,
    pub language: Option<String>,
    pub attempts: u32,
    pub verified_successes: u32,
    pub transport_successes: u32,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetSignals {
    pub asset: AssetKey,
    pub languages: Signal<Vec<String>>,
    pub required_tools: Signal<Vec<String>>,
    pub history: Signal<SuccessHistory>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEnvelopeV3 {
    pub schema_version: String,
    pub catalog_content_sha256: String,
    pub metadata_content_sha256: String,
    pub metadata: MetadataDocument,
    pub signals: Vec<AssetSignals>,
}
impl MetadataEnvelopeV3 {
    pub fn new(
        metadata: MetadataDocument,
        signals: Vec<AssetSignals>,
        catalog_hash: &str,
    ) -> Result<Self> {
        let mut document = Self {
            schema_version: "3".into(),
            catalog_content_sha256: catalog_hash.into(),
            metadata_content_sha256: String::new(),
            metadata,
            signals,
        };
        document.normalize()?;
        document.metadata_content_sha256 =
            index::hash_document(&(&document.metadata, &document.signals))?;
        Ok(document)
    }
    fn normalize(&mut self) -> Result<()> {
        if self.schema_version != "3" {
            return Err(RetrievalError::Invalid("context metadata schema"));
        }
        index::validate_digest(&self.catalog_content_sha256)?;
        self.metadata = index::canonical(self.metadata.clone())?;
        if self.signals.len() != self.metadata.assets.len() {
            return Err(RetrievalError::Invalid(
                "signals require one entry per asset",
            ));
        }
        self.signals.sort_by(|a, b| a.asset.cmp(&b.asset));
        for (asset, signal) in self.metadata.assets.iter().zip(&mut self.signals) {
            if signal.asset != asset.key() {
                return Err(RetrievalError::Invalid("duplicate or unknown signal asset"));
            }
            for values in [&mut signal.languages, &mut signal.required_tools] {
                values.validate()?;
                if let Signal::Observed { value, .. } = values {
                    canonical_terms(value)?;
                }
            }
            signal.history.validate()?;
            if let Signal::Observed { value, .. } = &signal.history {
                if value.attempts > MAX_HISTORY_SAMPLES
                    || value.verified_successes > value.attempts
                    || value.transport_successes > value.attempts
                    || value
                        .language
                        .as_ref()
                        .is_some_and(|v| !fusion::valid_identifier(v))
                {
                    return Err(RetrievalError::Invalid("history sample counts or language"));
                }
            }
        }
        index::hash_document(&(&self.metadata, &self.signals))?;
        Ok(())
    }
    pub(crate) fn validated(mut self) -> Result<Self> {
        self.normalize()?;
        index::validate_digest(&self.metadata_content_sha256)?;
        if index::hash_document(&(&self.metadata, &self.signals))? != self.metadata_content_sha256 {
            return Err(RetrievalError::Stale);
        }
        Ok(self)
    }
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        let value = self.clone().validated()?;
        let bytes =
            serde_json::to_vec(&value).map_err(|_| RetrievalError::Invalid("metadata JSON"))?;
        if bytes.len() > MAX_DOCUMENT_BYTES {
            return Err(RetrievalError::Limit("metadata document bytes"));
        }
        Ok(bytes)
    }
}
fn canonical_terms(values: &mut Vec<String>) -> Result<()> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(RetrievalError::Limit("signal items"));
    }
    if values.iter().any(|v| !fusion::valid_identifier(v)) {
        return Err(RetrievalError::Invalid("signal identifier"));
    }
    values.sort();
    values.dedup();
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolObservation {
    pub tool: String,
    pub support: CapabilitySupport,
    pub provenance: SignalProvenance,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticPolicy {
    #[default]
    Disabled,
    Required,
    LexicalFallback,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetrieverWeights {
    pub bm25: u32,
    pub languages: u32,
    pub required_tools: u32,
    pub verified_history: u32,
    pub semantic: u32,
}
impl Default for RetrieverWeights {
    fn default() -> Self {
        Self {
            bm25: 1_000_000,
            languages: 1_000_000,
            required_tools: 1_000_000,
            verified_history: 1_000_000,
            semantic: 1_000_000,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSearchQuery {
    pub query: SearchQuery,
    pub languages: Vec<String>,
    pub required_tools: Vec<String>,
    pub available_tools: Vec<ToolObservation>,
    pub task_kind: Option<TaskKind>,
    pub provenance: SignalProvenance,
    pub now_unix_seconds: u64,
    pub max_signal_age_seconds: u64,
    pub minimum_history_samples: u32,
    pub rrf_k: u32,
    #[serde(default)]
    pub fusion_ambiguity_margin_micros: u32,
    #[serde(default)]
    pub weights: RetrieverWeights,
    pub semantic_policy: SemanticPolicy,
}
impl ContextSearchQuery {
    pub fn new(query: SearchQuery, provenance: SignalProvenance, now: u64) -> Self {
        Self {
            query,
            languages: vec![],
            required_tools: vec![],
            available_tools: vec![],
            task_kind: None,
            provenance,
            now_unix_seconds: now,
            max_signal_age_seconds: 86_400,
            minimum_history_samples: 5,
            rrf_k: 60,
            fusion_ambiguity_margin_micros: 0,
            weights: RetrieverWeights::default(),
            semantic_policy: SemanticPolicy::Disabled,
        }
    }
    fn validated(&self) -> Result<Self> {
        index::validate_query(&self.query)?;
        let mut query = self.clone();
        canonical_terms(&mut query.languages)?;
        canonical_terms(&mut query.required_tools)?;
        if self.available_tools.len() > MAX_LIST_ITEMS
            || self.minimum_history_samples == 0
            || self.minimum_history_samples > MAX_HISTORY_SAMPLES
            || self.max_signal_age_seconds > MAX_SIGNAL_AGE_SECONDS
            || self.rrf_k == 0
            || self.rrf_k > 10_000
            || self.fusion_ambiguity_margin_micros > 1_000_000
        {
            return Err(RetrievalError::Limit("context query"));
        }
        let weights = [
            self.weights.bm25,
            self.weights.languages,
            self.weights.required_tools,
            self.weights.verified_history,
            self.weights.semantic,
        ];
        if weights.iter().any(|w| *w > 1_000_000)
            || weights.iter().all(|w| *w == 0)
            || (self.semantic_policy != SemanticPolicy::Disabled && self.weights.semantic == 0)
        {
            return Err(RetrievalError::Invalid("retriever weights"));
        }
        self.provenance.validate()?;
        if !self
            .provenance
            .fresh(self.now_unix_seconds, self.max_signal_age_seconds)
        {
            return Err(RetrievalError::Invalid("stale query provenance"));
        }
        query.available_tools.sort_by(|a, b| a.tool.cmp(&b.tool));
        let mut seen = BTreeSet::new();
        for tool in &query.available_tools {
            if !fusion::valid_identifier(&tool.tool) || !seen.insert(&tool.tool) {
                return Err(RetrievalError::Invalid("tool observation"));
            }
            tool.provenance.validate()?;
        }
        Ok(query)
    }
    pub fn content_hash(&self) -> Result<String> {
        index::hash_document(&self.validated()?)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticRanking {
    pub schema_version: u32,
    pub index_hash: String,
    pub query_hash: String,
    pub provenance: SignalProvenance,
    pub hits: Vec<RankedHit>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticStatus {
    Disabled,
    Applied,
    UnavailableFallback,
    InvalidFallback,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextExclusionReason {
    Blocked,
    Untrusted,
    AntiTrigger,
    RequiredPhraseMissing,
    RequiredToolsUnknown,
    RequiredToolsStale,
    ToolUnsupported,
    ToolUnknown,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextExclusion {
    pub asset: AssetKey,
    pub reason: ContextExclusionReason,
    pub tool: Option<String>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    Languages,
    RequiredTools,
    VerifiedHistory,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalStatus {
    Observed,
    Unknown,
    Stale,
    InsufficientSamples,
    ContextMismatch,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignalEvidence {
    pub signal: SignalKind,
    pub status: SignalStatus,
    pub score_micros: u64,
    pub matched: Vec<String>,
    pub provenance: Option<SignalProvenance>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCandidate {
    pub fusion: FusedCandidate,
    pub lexical: Option<SearchCandidate>,
    pub signals: Vec<SignalEvidence>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSearchResult {
    pub schema_version: String,
    pub kind: Option<AssetKind>,
    pub postings_visited: usize,
    pub catalog_content_sha256: String,
    pub source_hash: String,
    pub index_hash: String,
    pub query_hash: String,
    pub candidates: Vec<ContextCandidate>,
    pub selected: Option<AssetKey>,
    pub abstention: Option<Abstention>,
    pub exclusions: Vec<ContextExclusion>,
    pub excluded_count: usize,
    pub semantic_status: SemanticStatus,
    pub semantic_provenance: Option<SignalProvenance>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IndexUpdateReport {
    pub inserted: usize,
    pub updated: usize,
    pub removed: usize,
    pub retokenized_assets: usize,
    pub source_hash: String,
    pub index_hash: String,
}

impl Bm25Index {
    pub fn search_contextual_current_with_catalog(
        &self,
        source: &[u8],
        query: &ContextSearchQuery,
        catalog_hash: &str,
    ) -> Result<ContextSearchResult> {
        self.validate_catalog_hash(catalog_hash)?;
        if !self.is_current(source)? {
            return Err(RetrievalError::Stale);
        }
        self.search_contextual(query, catalog_hash)
    }
    pub fn search_contextual(
        &self,
        query: &ContextSearchQuery,
        catalog_hash: &str,
    ) -> Result<ContextSearchResult> {
        self.search_contextual_with_semantic(query, catalog_hash, None)
    }
    /// Every source is metadata-only and filtered by the same catalog, trust,
    /// phrase and tool-evidence checks. A supplied semantic list cannot add IDs.
    pub fn search_contextual_with_semantic(
        &self,
        query: &ContextSearchQuery,
        catalog_hash: &str,
        semantic: Option<&SemanticRanking>,
    ) -> Result<ContextSearchResult> {
        self.validate_catalog_hash(catalog_hash)?;
        let signals = self.signals.as_ref().ok_or(RetrievalError::Invalid(
            "contextual metadata requires schema 3",
        ))?;
        let query = query.validated()?;
        let query_hash = query.content_hash()?;
        let lexical = self.search_metadata(&query.query, false)?;
        let mut lexical_by_key: BTreeMap<_, _> = lexical
            .candidates
            .into_iter()
            .map(|c| (c.asset.clone(), c))
            .collect();
        let anti = self.excluded_by_trigger(&query.query.text)?;
        let phrases = tokenize::quoted_phrases(&query.query.text)?;
        let mut exclusions = Vec::new();
        let mut excluded_count = 0;
        let mut eligible = BTreeMap::new();
        let mut evidence = BTreeMap::new();
        let mut ranks: [Vec<RankedHit>; 4] = std::array::from_fn(|_| vec![]);
        for (key, values) in signals {
            if query.query.kind.is_some_and(|kind| kind != key.kind) {
                continue;
            }
            let asset = self
                .asset(key.kind, &key.id)
                .ok_or(RetrievalError::Invalid("signal asset"))?;
            let excluded = if asset.trust == router_types::SkillTrust::Blocked {
                Some((ContextExclusionReason::Blocked, None))
            } else if !trusted(asset.trust) {
                Some((ContextExclusionReason::Untrusted, None))
            } else if anti.contains(key) {
                Some((ContextExclusionReason::AntiTrigger, None))
            } else if phrases
                .iter()
                .any(|phrase| !matches_phrase(asset, values, &query, phrase))
            {
                Some((ContextExclusionReason::RequiredPhraseMissing, None))
            } else {
                tool_exclusion(values, &query)
            };
            if let Some((reason, tool)) = excluded {
                lexical_by_key.remove(key);
                excluded_count += 1;
                if exclusions.len() < MAX_RESULTS {
                    exclusions.push(ContextExclusion {
                        asset: key.clone(),
                        reason,
                        tool,
                    });
                }
                continue;
            }
            let records = score_signals(values, &query);
            if let Some(hit) = lexical_by_key.get(key) {
                ranks[0].push(RankedHit {
                    asset: key.clone(),
                    score_micros: hit.bm25_micros,
                });
            }
            for (i, record) in records.iter().enumerate() {
                if record.score_micros > 0 {
                    ranks[i + 1].push(RankedHit {
                        asset: key.clone(),
                        score_micros: record.score_micros,
                    });
                }
            }
            eligible.insert(key.clone(), asset);
            evidence.insert(key.clone(), records);
        }
        let mut sources = Vec::new();
        for ((id, mut hits), weight) in ["bm25", "languages", "required-tools", "verified-history"]
            .into_iter()
            .zip(ranks)
            .zip([
                query.weights.bm25,
                query.weights.languages,
                query.weights.required_tools,
                query.weights.verified_history,
            ])
        {
            hits.sort_by(|a, b| {
                b.score_micros
                    .cmp(&a.score_micros)
                    .then_with(|| a.asset.cmp(&b.asset))
            });
            hits.truncate(MAX_RANKED_HITS);
            if !hits.is_empty() && weight > 0 {
                sources.push(RankedSource {
                    id: id.into(),
                    weight_micros: weight,
                    hits,
                });
            }
        }
        let (semantic_status, semantic_provenance) =
            add_semantic(self, &query, &query_hash, semantic, &eligible, &mut sources)?;
        // Examine at least two before truncation, including caller top_k=1.
        let fused = fuse_rankings(
            &sources,
            RrfConfig {
                k: query.rrf_k,
                top_k: query.query.top_k.max(2),
            },
        )?;
        let mut candidates: Vec<_> = fused
            .into_iter()
            .map(|fusion| ContextCandidate {
                lexical: lexical_by_key.remove(&fusion.asset),
                signals: evidence.remove(&fusion.asset).unwrap_or_default(),
                fusion,
            })
            .collect();
        let abstention = context_abstention(&candidates, &query);
        let selected = if abstention.is_none() {
            candidates.first().map(|c| c.fusion.asset.clone())
        } else {
            None
        };
        candidates.truncate(query.query.top_k);
        Ok(ContextSearchResult {
            schema_version: "3".into(),
            kind: query.query.kind,
            postings_visited: lexical.postings_visited,
            catalog_content_sha256: catalog_hash.into(),
            source_hash: self.source_hash().into(),
            index_hash: self.index_hash().into(),
            query_hash,
            candidates,
            selected,
            abstention,
            exclusions,
            excluded_count,
            semantic_status,
            semantic_provenance,
        })
    }
    /// Separate top-k per family, never a model score competing with a skill.
    pub fn search_families(
        &self,
        query: &ContextSearchQuery,
        catalog_hash: &str,
    ) -> Result<Vec<ContextSearchResult>> {
        let mut results = Vec::new();
        for kind in [
            AssetKind::Agent,
            AssetKind::Skill,
            AssetKind::Prompt,
            AssetKind::Tool,
            AssetKind::Model,
        ] {
            let mut query = query.clone();
            query.query.kind = Some(kind);
            results.push(self.search_contextual(&query, catalog_hash)?);
        }
        Ok(results)
    }
}
fn tool_exclusion(
    values: &AssetSignals,
    query: &ContextSearchQuery,
) -> Option<(ContextExclusionReason, Option<String>)> {
    let required = match &values.required_tools {
        Signal::Unknown => return Some((ContextExclusionReason::RequiredToolsUnknown, None)),
        Signal::Observed { value, provenance } => {
            if !provenance.fresh(query.now_unix_seconds, query.max_signal_age_seconds) {
                return Some((ContextExclusionReason::RequiredToolsStale, None));
            }
            value
        }
    };
    for name in required.iter().chain(&query.required_tools) {
        let observed = query.available_tools.iter().find(|tool| &tool.tool == name);
        let support = observed
            .filter(|tool| {
                tool.provenance
                    .fresh(query.now_unix_seconds, query.max_signal_age_seconds)
            })
            .map_or(CapabilitySupport::Unknown, |tool| tool.support);
        match support {
            CapabilitySupport::Supported => {}
            CapabilitySupport::Unsupported => {
                return Some((ContextExclusionReason::ToolUnsupported, Some(name.clone())));
            }
            CapabilitySupport::Unknown => {
                return Some((ContextExclusionReason::ToolUnknown, Some(name.clone())));
            }
        }
    }
    None
}
fn base_evidence<T>(
    kind: SignalKind,
    signal: &Signal<T>,
    query: &ContextSearchQuery,
) -> SignalEvidence {
    let (status, provenance) = match signal {
        Signal::Unknown => (SignalStatus::Unknown, None),
        Signal::Observed { provenance, .. } => (
            if provenance.fresh(query.now_unix_seconds, query.max_signal_age_seconds) {
                SignalStatus::Observed
            } else {
                SignalStatus::Stale
            },
            Some(provenance.clone()),
        ),
    };
    SignalEvidence {
        signal: kind,
        status,
        score_micros: 0,
        matched: vec![],
        provenance,
    }
}
fn score_signals(values: &AssetSignals, query: &ContextSearchQuery) -> Vec<SignalEvidence> {
    let phrase = format!(" {} ", tokenize::phrase(&query.query.text));
    let mut output = Vec::new();
    for (kind, signal, desired) in [
        (SignalKind::Languages, &values.languages, &query.languages),
        (
            SignalKind::RequiredTools,
            &values.required_tools,
            &query.required_tools,
        ),
    ] {
        let mut evidence = base_evidence(kind, signal, query);
        if let Some((values, _)) =
            signal.observed(query.now_unix_seconds, query.max_signal_age_seconds)
        {
            evidence.matched = values
                .iter()
                .filter(|value| desired.contains(value) || phrase.contains(&format!(" {value} ")))
                .cloned()
                .collect();
            evidence.score_micros = evidence.matched.len() as u64 * 2_000_000;
        }
        output.push(evidence);
    }
    let mut history = base_evidence(SignalKind::VerifiedHistory, &values.history, query);
    if let Some((value, _)) = values
        .history
        .observed(query.now_unix_seconds, query.max_signal_age_seconds)
    {
        if query.task_kind != Some(value.task_kind)
            || value.language.as_ref().is_some_and(|language| {
                !query.languages.contains(language) && !phrase.contains(&format!(" {language} "))
            })
        {
            history.status = SignalStatus::ContextMismatch;
        } else if value.attempts < query.minimum_history_samples {
            history.status = SignalStatus::InsufficientSamples;
        } else {
            history.score_micros =
                u64::from(value.verified_successes) * 1_000_000 / u64::from(value.attempts);
        }
    }
    output.push(history);
    output
}
fn add_semantic(
    index: &Bm25Index,
    query: &ContextSearchQuery,
    query_hash: &str,
    semantic: Option<&SemanticRanking>,
    eligible: &BTreeMap<AssetKey, &AssetMetadata>,
    sources: &mut Vec<RankedSource>,
) -> Result<(SemanticStatus, Option<SignalProvenance>)> {
    if query.semantic_policy == SemanticPolicy::Disabled {
        return if semantic.is_some() {
            Err(RetrievalError::SemanticInvalid)
        } else {
            Ok((SemanticStatus::Disabled, None))
        };
    }
    if !cfg!(feature = "semantic-ranking") || semantic.is_none() {
        return if query.semantic_policy == SemanticPolicy::Required {
            Err(RetrievalError::SemanticUnavailable)
        } else {
            Ok((SemanticStatus::UnavailableFallback, None))
        };
    }
    let value = semantic.ok_or(RetrievalError::SemanticUnavailable)?;
    let invalid = value.schema_version != 1
        || value.index_hash != index.index_hash()
        || value.query_hash != query_hash
        || value.provenance.validate().is_err()
        || !value
            .provenance
            .fresh(query.now_unix_seconds, query.max_signal_age_seconds)
        || value.hits.len() > MAX_RANKED_HITS
        || value.hits.iter().any(|hit| {
            index.asset(hit.asset.kind, &hit.asset.id).is_none()
                || query.query.kind.is_some_and(|kind| kind != hit.asset.kind)
        });
    if invalid {
        return if query.semantic_policy == SemanticPolicy::Required {
            Err(RetrievalError::SemanticInvalid)
        } else {
            Ok((SemanticStatus::InvalidFallback, None))
        };
    }
    let hits = value
        .hits
        .iter()
        .filter(|hit| eligible.contains_key(&hit.asset))
        .cloned()
        .collect();
    sources.push(RankedSource {
        id: "semantic".into(),
        weight_micros: query.weights.semantic,
        hits,
    });
    Ok((SemanticStatus::Applied, Some(value.provenance.clone())))
}
fn context_abstention(
    candidates: &[ContextCandidate],
    query: &ContextSearchQuery,
) -> Option<Abstention> {
    if query.query.text.trim().is_empty()
        && query.languages.is_empty()
        && query.required_tools.is_empty()
        && query.task_kind.is_none()
    {
        return Some(Abstention::EmptyQuery);
    }
    let Some(first) = candidates.first() else {
        return Some(Abstention::NoMatches);
    };
    if let Some(lexical) = &first.lexical {
        if lexical.bm25_micros < query.query.policy.minimum_score_micros
            || lexical.coverage_micros < query.query.policy.minimum_coverage_micros
        {
            return Some(Abstention::WeakMatch);
        }
    }
    if let Some(second) = candidates.get(1) {
        let lexical_only = first
            .fusion
            .sources
            .iter()
            .chain(&second.fusion.sources)
            .all(|s| s.source == "bm25");
        if lexical_only {
            if let (Some(a), Some(b)) = (&first.lexical, &second.lexical) {
                if u128::from(a.bm25_micros.saturating_sub(b.bm25_micros)) * 1_000_000
                    <= u128::from(a.bm25_micros)
                        * u128::from(query.query.policy.ambiguity_margin_micros)
                {
                    return Some(Abstention::Ambiguous);
                }
            }
        } else {
            // Canonical tie ordering gives equal source scores different ranks;
            // that arbitrary ordering must not manufacture confidence.
            let a: Vec<_> = first
                .fusion
                .sources
                .iter()
                .map(|s| (&s.source, s.source_score_micros))
                .collect();
            let b: Vec<_> = second
                .fusion
                .sources
                .iter()
                .map(|s| (&s.source, s.source_score_micros))
                .collect();
            if a == b
                || u128::from(first.fusion.rrf_score_nanos - second.fusion.rrf_score_nanos)
                    * 1_000_000
                    <= u128::from(first.fusion.rrf_score_nanos)
                        * u128::from(query.fusion_ambiguity_margin_micros)
            {
                return Some(Abstention::Ambiguous);
            }
        }
    }
    None
}

fn matches_phrase(
    asset: &AssetMetadata,
    signals: &AssetSignals,
    query: &ContextSearchQuery,
    phrase: &str,
) -> bool {
    let expected = format!(" {phrase} ");
    let matches = |text: &str| format!(" {} ", tokenize::phrase(text)).contains(&expected);
    index::fields(asset).is_ok_and(|fields| fields.iter().any(|(_, text)| matches(text)))
        || [&signals.languages, &signals.required_tools]
            .iter()
            .any(|signal| {
                signal
                    .observed(query.now_unix_seconds, query.max_signal_age_seconds)
                    .is_some_and(|(values, _)| values.iter().any(|value| matches(value)))
            })
}
