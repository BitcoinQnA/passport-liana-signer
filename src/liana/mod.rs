// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Liana policy/PSBT/signing logic, on the SDK's bitcoin stack.
//!
//! Bitcoin + miniscript come from `ngwallet::bdk_wallet` (the same crates the
//! Bitcoin app uses), so this compiles for both the host simulator and the
//! `armv7a-unknown-xous-elf` device target — unlike a crates.io `miniscript`
//! with std/secp, which doesn't link on device. The logic mirrors the
//! host-tested `liana-signer-core` reference crate verbatim.

// Ported reference library (mirrors liana-signer-core). Some API items
// (e.g. sign_and_finalize, store helpers) are exercised by tests rather than
// the binary's hot path, so allow unused items at the module level.
#![allow(dead_code)]

pub use ngwallet::bdk_wallet::{bitcoin, miniscript};

pub mod descriptor;
pub mod policy;
pub mod psbt;
pub mod signing;
pub mod store;
pub mod transport;

use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;
pub const POLICY_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Descriptor text could not be parsed.
    Parse(String),
    /// Parsed, but uses a form this POC does not support (e.g. Taproot).
    Unsupported(String),
    /// PSBT does not match any registered policy.
    NotRegistered,
    /// Passport does not own a key on the active spend path.
    NoPassportKey,
    /// Signing/finalizing failed.
    Sign(String),
    /// PSBT/policy matching failed.
    Match(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse(s) | Error::Unsupported(s) | Error::Sign(s) | Error::Match(s) => {
                f.write_str(s)
            }
            Error::NotRegistered => {
                f.write_str("Transaction does not match a registered wallet policy.")
            }
            Error::NoPassportKey => {
                f.write_str("This Passport has no key on the selected spending path.")
            }
        }
    }
}
impl std::error::Error for Error {}

/// A Liana policy the user has registered on Passport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisteredPolicy {
    /// JSON storage schema. Defaults to v1 for policies saved by earlier builds
    /// before the field existed.
    #[serde(default = "default_policy_schema_version")]
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub network: String,
    pub descriptor: String,
    pub descriptor_checksum: String,
    /// Foundation's canonical Passport wallet-policy identity. Empty only for
    /// legacy records that have not yet been migrated from their descriptor.
    #[serde(default)]
    pub policy_id: String,
    /// Canonical BIP388-style template and key vector used to bind QR address
    /// requests to this exact registered policy.
    #[serde(default)]
    pub policy_template: String,
    #[serde(default)]
    pub policy_keys: Vec<String>,
    pub policy_fingerprint: String,
    pub signers: Vec<PolicySigner>,
    pub paths: Vec<SpendPath>,
    /// Archived policies are hidden from the home list; they can be restored or
    /// permanently deleted from the archive. Defaults false for older records.
    #[serde(default)]
    pub archived: bool,
}

fn default_policy_schema_version() -> u32 {
    POLICY_SCHEMA_VERSION
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicySigner {
    pub fingerprint: String,
    pub derivation_path: String,
    pub xpub: String,
    pub owned_by_passport: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpendPathKind {
    Primary,
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpendPath {
    pub kind: SpendPathKind,
    pub threshold: usize,
    pub total_keys: usize,
    pub relative_timelock_blocks: Option<u32>,
    pub signer_fingerprints: Vec<String>,
}

impl SpendPath {
    /// Approximate the relative timelock in months (~4380 blocks/month).
    pub fn approx_months(&self) -> Option<u32> {
        self.relative_timelock_blocks.map(|b| b / 4380)
    }
}
