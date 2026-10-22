use crate::{Result, RuntimeError};

/// Network authority enforced by the runtime sandbox for a process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAuthority {
    /// Keep the sandbox's default network denial.
    Deny,
    /// Preserve the broad network grant explicitly approved for the phase.
    PhaseGranted,
    /// Restrict a controller to its broker transport. Currently unsupported.
    ControllerBrokerOnly,
}

impl NetworkAuthority {
    pub(crate) fn seatbelt_rule(self) -> Result<&'static str> {
        match self {
            Self::Deny => Ok(""),
            Self::PhaseGranted => Ok("(allow network*)\n"),
            Self::ControllerBrokerOnly => Err(RuntimeError::Sandbox),
        }
    }

    pub(crate) fn bubblewrap_args(self) -> Result<&'static [&'static str]> {
        match self {
            Self::Deny => Ok(&[]),
            Self::PhaseGranted => Ok(&["--share-net"]),
            Self::ControllerBrokerOnly => Err(RuntimeError::Sandbox),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkAuthority;
    use crate::RuntimeError;

    #[test]
    fn network_authority_deny_emits_no_grant() {
        assert_eq!(NetworkAuthority::Deny.seatbelt_rule().unwrap(), "");
        assert_eq!(
            NetworkAuthority::Deny.bubblewrap_args().unwrap(),
            &[] as &[&str]
        );
    }

    #[test]
    fn network_authority_phase_granted_preserves_broad_grant() {
        assert_eq!(
            NetworkAuthority::PhaseGranted.seatbelt_rule().unwrap(),
            "(allow network*)\n"
        );
        assert_eq!(
            NetworkAuthority::PhaseGranted.bubblewrap_args().unwrap(),
            &["--share-net"]
        );
    }

    #[test]
    fn network_authority_controller_broker_only_refuses_seatbelt() {
        assert!(matches!(
            NetworkAuthority::ControllerBrokerOnly.seatbelt_rule(),
            Err(RuntimeError::Sandbox)
        ));
    }

    #[test]
    fn network_authority_controller_broker_only_refuses_bubblewrap() {
        assert!(matches!(
            NetworkAuthority::ControllerBrokerOnly.bubblewrap_args(),
            Err(RuntimeError::Sandbox)
        ));
    }
}
