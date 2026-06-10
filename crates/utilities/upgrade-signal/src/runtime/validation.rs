//! Runtime upgrade signal validation.

use alloy_primitives::Address;
use base_common_genesis::BaseUpgrade;

use crate::{UpgradeSignalError, UpgradeSignalSchedule};

/// Runtime schedule validation context shared by execution and consensus refresh paths.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UpgradeSignalRuntimeValidation {
    /// Whether positive Beryl signals require an execution activation admin address.
    pub require_activation_admin_for_beryl: bool,
    /// Execution activation admin address for the L2 chain, when known.
    pub activation_admin_address: Option<Address>,
}

impl UpgradeSignalRuntimeValidation {
    /// Creates a validation context with execution-specific checks disabled.
    pub const fn disabled() -> Self {
        Self { require_activation_admin_for_beryl: false, activation_admin_address: None }
    }

    /// Creates a validation context that enforces execution activation admin invariants.
    pub const fn with_activation_admin_address(activation_admin_address: Option<Address>) -> Self {
        Self { require_activation_admin_for_beryl: true, activation_admin_address }
    }

    /// Creates the fail-closed validation context used when no activation admin source is known.
    ///
    /// This requires an activation admin address for positive Beryl signals but has none, so a
    /// positive Beryl signal is rejected rather than applied unguarded.
    pub const fn fail_closed() -> Self {
        Self::with_activation_admin_address(None)
    }

    /// Validates a schedule before it mutates the process-local runtime registry.
    pub fn validate_schedule(
        &self,
        chain_id: u64,
        schedule: &UpgradeSignalSchedule,
    ) -> Result<(), UpgradeSignalError> {
        if self.require_activation_admin_for_beryl
            && self.activation_admin_address.is_none()
            && schedule.signals.iter().any(|signal| {
                signal.positive_activation_timestamp().is_some()
                    && signal.hardfork_id == BaseUpgrade::Beryl
            })
        {
            return Err(UpgradeSignalError::missing_activation_admin_address(chain_id));
        }

        Ok(())
    }
}

impl Default for UpgradeSignalRuntimeValidation {
    fn default() -> Self {
        Self::disabled()
    }
}
