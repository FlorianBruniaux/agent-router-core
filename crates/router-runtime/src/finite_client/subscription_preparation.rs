//! Inert subscription profile. It is deliberately not dispatch authority.
use super::*;

#[derive(serde::Serialize)]
pub(super) struct SubscriptionPreparation {
    pub(super) account_sha256: String,
    pub(super) controller_sha256: String,
}

impl OwnedBroker {
    /// Prepares credential-free files for review. No auth read, refresh, network,
    /// provider discovery or process launch occurs. Runtime refuses this profile
    /// until a separate authenticated controller entrance is qualified.
    pub fn prepare_codex_subscription_tools_state(
        &self,
        store: &Path,
        run: &PreparedRun,
        account_sha256: &str,
        controller_sha256: &str,
    ) -> Result<FiniteCodexState> {
        if !matches!(run.requested_model.as_str(), "gpt-6-luna" | "gpt-6-astra")
            || !matches!(
                run.requested_effort,
                router_types::EffortLevel::Medium | router_types::EffortLevel::Xhigh
            )
            || !is_digest(account_sha256)
            || !is_digest(controller_sha256)
        {
            return Err(RuntimeError::Invalid("subscription preparation identity"));
        }
        self.prepare_codex_state_mode(
            store,
            run,
            true,
            Some(SubscriptionPreparation {
                account_sha256: account_sha256.into(),
                controller_sha256: controller_sha256.into(),
            }),
        )
    }
}

pub(super) fn codex_configuration_for(
    run: &PreparedRun,
    broker: &OwnedBroker,
    tools: bool,
    subscription: Option<&SubscriptionPreparation>,
) -> Result<Vec<u8>> {
    let bytes = codex_configuration_mode(run, broker, tools)?;
    if subscription.is_none() {
        return Ok(bytes);
    }
    if !tools {
        return Err(RuntimeError::Sandbox);
    }
    let config = String::from_utf8(bytes)
        .map_err(|_| RuntimeError::Integrity("subscription configuration"))?;
    Ok(config
        .replace("local_fixture", "codex_subscription_relay")
        .replace(
            "Finite client preparation, local fixture only",
            "Codex subscription via private controller, no direct credentials",
        )
        .into_bytes())
}

pub(super) fn codex_catalog_for(
    run: &PreparedRun,
    tools: bool,
    subscription: Option<&SubscriptionPreparation>,
) -> Result<Vec<u8>> {
    let bytes = codex_local_catalog_mode(run, tools)?;
    if subscription.is_none() {
        return Ok(bytes);
    }
    if !tools {
        return Err(RuntimeError::Sandbox);
    }
    let mut catalog: serde_json::Value = serde_json::from_slice(&bytes)?;
    let model = &mut catalog["models"][0];
    model["display_name"] = run.requested_model.as_str().into();
    model["description"] = "Operator-authored bounded subscription routing profile; not a provider availability measurement".into();
    model["base_instructions"] = "Complete the public task using only the three advertised finite tools. Respect the public requirements and the authorised output path. Use .scratch for temporary files and checks. Never claim that a check ran unless its result was returned.".into();
    model["supported_reasoning_levels"][0]["description"] =
        "Operator-selected fixed reasoning effort".into();
    // Keep the same conservative operator bound as the qualification profile.
    // It is not a claim about the vendor's maximum context window.
    Ok(serde_json::to_vec(&catalog)?)
}
