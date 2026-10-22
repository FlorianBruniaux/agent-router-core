//! Move preparation owners together. This module grants no launch authority.
use super::*;

/// Held by HostState through its exact, locked namespace cleanup boundary.
/// Neither the bundle nor any of its owners can be reconstructed from JSON.
pub(crate) struct FiniteClientResources {
    pub(super) reviewed: FiniteClientReview,
    pub(super) startup: FiniteCodexStartup,
}
impl FiniteClientResources {
    pub(crate) fn check(&self, home: &Path) -> Result<()> {
        if home != Path::new(&self.reviewed.manifest.private_state) {
            return Err(RuntimeError::Integrity("finite client handoff state"));
        }
        self.reviewed.check_files()?;
        self.startup
            .check(home, &self.reviewed.run, &self.reviewed.broker)
    }
    pub(crate) fn cleanup(mut self) -> Result<()> {
        let assets = self
            .reviewed
            .owned_assets
            .take()
            .ok_or(RuntimeError::Integrity("missing finite client copies"))?;
        for copy in assets.copies {
            copy.cleanup()?;
        }
        if let Some(namespace) = self.reviewed.owned_namespace.take() {
            namespace.copy.cleanup()?;
        }
        // On success the broker and startup pins outlive disposal of every copy.
        Ok(())
    }
}
impl ApprovedFiniteClient {
    /// Transfers the producer-created home, startup pins, copies and listener
    /// into the existing namespace-state lifecycle. This is preparation only:
    /// no Command, runtime approval, OS evidence or provider permission follows.
    /// The generic native home-write sandbox refuses this state. A dedicated
    /// qualified backend must own it before arming its exact private lease.
    pub fn into_namespace_state(self) -> Result<HostState> {
        let mut reviewed = self.reviewed;
        reviewed.check_files()?;
        if reviewed.owned_assets.is_none() {
            return Err(RuntimeError::Sandbox);
        }
        let FiniteCodexState { mut state, startup } =
            reviewed.owned_state.take().ok_or(RuntimeError::Sandbox)?;
        state.retain_finite_client(FiniteClientResources { reviewed, startup })?;
        Ok(state)
    }
}

/// Retains the submitted inode and scratch owner through private artifact capture.
pub(crate) struct StoppedToolsObservation {
    pub(crate) terminal: Option<crate::finite_tools::ToolTerminal>,
    pub(crate) output: Option<super::tools_state::VerifiedToolsOutput>,
}
impl FiniteClientResources {
    pub(crate) fn observe_tools(
        &mut self,
        require_complete: bool,
    ) -> Result<Option<StoppedToolsObservation>> {
        let Some(tools) = self.reviewed.owned_tools.as_mut() else {
            return Ok(None);
        };
        let terminal = tools.terminal_observation(require_complete)?;
        let output = if require_complete {
            let observed = terminal
                .as_ref()
                .ok_or(RuntimeError::Integrity("missing stopped tools terminal"))?;
            let workspace = self
                .reviewed
                .owned_workspace
                .as_ref()
                .ok_or(RuntimeError::Sandbox)?;
            tools.promote_output(workspace, observed)?
        } else {
            None
        };
        Ok(Some(StoppedToolsObservation { terminal, output }))
    }
}
