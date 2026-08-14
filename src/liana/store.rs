// store.rs — persist registered policies as JSON.
//
// On device this maps to writing `policy_<id>.json` via the KeyOS FileSystem.
// Here it is pure (string) so it is fully testable; the app wires the I/O.

use super::{Error, RegisteredPolicy, Result};

pub const MAX_POLICIES: usize = 16;

pub fn to_json(policy: &RegisteredPolicy) -> Result<String> {
    serde_json::to_string_pretty(policy).map_err(|e| Error::Parse(format!("serialize: {e}")))
}

pub fn from_json(s: &str) -> Result<RegisteredPolicy> {
    serde_json::from_str(s).map_err(|e| Error::Parse(format!("deserialize: {e}")))
}

/// An in-memory collection of registered policies. The app loads/saves the
/// JSON for each entry through KeyOS storage; this models the lookups.
#[derive(Debug, Default, Clone)]
pub struct PolicyStore {
    policies: Vec<RegisteredPolicy>,
}

impl PolicyStore {
    pub fn new() -> Self { Self::default() }

    pub fn all(&self) -> &[RegisteredPolicy] { &self.policies }

    pub fn len(&self) -> usize { self.policies.len() }

    pub fn is_empty(&self) -> bool { self.policies.is_empty() }

    /// Add a policy. Rejects duplicate descriptor or canonical policy identity.
    pub fn add(&mut self, policy: RegisteredPolicy) -> Result<()> {
        if self.policies.iter().any(|p| {
            p.descriptor_checksum == policy.descriptor_checksum
                || (!policy.policy_id.is_empty() && p.policy_id == policy.policy_id)
        }) {
            return Err(Error::Parse(format!(
                "policy with checksum #{} already registered",
                policy.descriptor_checksum
            )));
        }
        if self.policies.len() >= MAX_POLICIES {
            return Err(Error::Parse(format!("maximum registered policy count ({MAX_POLICIES}) reached")));
        }
        self.policies.push(policy);
        Ok(())
    }

    pub fn find_by_checksum(&self, checksum: &str) -> Option<&RegisteredPolicy> {
        self.policies.iter().find(|p| p.descriptor_checksum == checksum)
    }

    pub fn remove(&mut self, checksum: &str) -> bool {
        let before = self.policies.len();
        self.policies.retain(|p| p.descriptor_checksum != checksum);
        self.policies.len() != before
    }

    /// Set the archived flag on a policy; returns the updated policy (cloned) so
    /// the caller can persist it.
    pub fn set_archived(&mut self, checksum: &str, archived: bool) -> Option<RegisteredPolicy> {
        let p = self.policies.iter_mut().find(|p| p.descriptor_checksum == checksum)?;
        p.archived = archived;
        Some(p.clone())
    }

    /// Rename a policy; returns the updated policy (cloned) so the caller can persist it.
    pub fn set_name(&mut self, checksum: &str, name: &str) -> Option<RegisteredPolicy> {
        let p = self.policies.iter_mut().find(|p| p.descriptor_checksum == checksum)?;
        p.name = name.to_string();
        Some(p.clone())
    }

    pub fn set_signer_name(
        &mut self,
        checksum: &str,
        signer_id: &str,
        name: &str,
    ) -> Option<RegisteredPolicy> {
        let policy = self.policies.iter_mut().find(|policy| policy.descriptor_checksum == checksum)?;
        let signer =
            policy.signers.iter_mut().find(|signer| signer.xpub == signer_id && !signer.owned_by_passport)?;
        signer.name = name.to_owned();
        Some(policy.clone())
    }
}
// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later
