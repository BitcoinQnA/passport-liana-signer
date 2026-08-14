// signing.rs — the security gate + the actual sign/finalize.
//
// Rules (from the plan):
//  - Never sign an unregistered/unmatched policy.
//  - Never silently fall back to a generic signing path.
//  - Refuse PSBTs with unknown/unsupported policy elements.
//  - Only sign when Passport owns a key on the *active* spend path.
//  - Recovery-path spends are allowed but flagged for explicit confirmation.

use super::bitcoin::bip32::Xpriv;
use super::bitcoin::secp256k1::{All, Secp256k1};
use super::bitcoin::Psbt;
use super::miniscript::psbt::PsbtExt;
use super::psbt::MatchResult;
use super::{Error, RegisteredPolicy, Result, SpendPathKind};

#[derive(Debug, Clone, PartialEq)]
pub enum SignDecision {
    /// Safe to sign. Carries the active path; Recovery requires explicit
    /// user confirmation in the UI before `sign_and_finalize` is called.
    Allow { path: SpendPathKind, requires_confirmation: bool },
    /// Do not sign. Carries a user-facing reason.
    Refuse(String),
}

/// Decide whether signing is permitted, given a match result.
pub fn decide(m: &MatchResult, _policy: &RegisteredPolicy) -> SignDecision {
    if !m.matched {
        return SignDecision::Refuse("This transaction does not match the registered wallet policy.".into());
    }
    let Some(path) = m.active_path else {
        return SignDecision::Refuse(refusal_reason(m, "Unable to determine the signing path."));
    };
    if !m.passport_can_sign {
        return SignDecision::Refuse(refusal_reason(
            m,
            "This Passport has no key on the selected spending path.",
        ));
    }
    SignDecision::Allow { path, requires_confirmation: matches!(path, SpendPathKind::Recovery) }
}

fn refusal_reason(m: &MatchResult, fallback: &str) -> String {
    m.reasons
        .iter()
        .rev()
        .find(|reason| !reason.starts_with("nSequence unlocks recovery older("))
        .cloned()
        .unwrap_or_else(|| fallback.into())
}

/// Sign every input we can with the device master key, WITHOUT finalizing.
/// This is the correct output for a coordinator workflow (Liana combines and
/// finalizes). Errors if the device added fewer signatures than the PSBT match
/// said it should.
pub fn sign(
    mut psbt: Psbt,
    master: &Xpriv,
    secp: &Secp256k1<All>,
    expected_signatures: usize,
) -> Result<Psbt> {
    sign_with_master(&mut psbt, master, secp, expected_signatures)?;
    Ok(psbt)
}

/// True if, after our signature, the PSBT can be finalized on its own (i.e.
/// Passport is the only signer the active path needs). Used as a UI hint;
/// never required for the coordinator workflow.
pub fn is_finalizable(psbt: &Psbt, secp: &Secp256k1<All>) -> bool { psbt.clone().finalize(secp).is_ok() }

/// Sign every input we can with the device master key, then finalize.
/// Returns the finalized PSBT (ready for Liana to broadcast).
pub fn sign_and_finalize(
    mut psbt: Psbt,
    master: &Xpriv,
    secp: &Secp256k1<All>,
    expected_signatures: usize,
) -> Result<Psbt> {
    sign_with_master(&mut psbt, master, secp, expected_signatures)?;
    psbt.finalize_mut(secp).map_err(|errs| Error::Sign(format!("finalize failed: {errs:?}")))?;
    Ok(psbt)
}

fn sign_with_master(
    psbt: &mut Psbt,
    master: &Xpriv,
    secp: &Secp256k1<All>,
    expected_signatures: usize,
) -> Result<usize> {
    if expected_signatures == 0 {
        return Err(Error::Sign("no device signatures were expected for this PSBT".into()));
    }
    let reported_keys = match psbt.sign(master, secp) {
        Ok(keys) => keys.len(),
        Err((keys, _errs)) => keys.len(),
    };
    let device_signatures = count_device_partial_sigs(psbt, master.fingerprint(secp));
    if reported_keys == 0 && device_signatures == 0 {
        return Err(Error::Sign("device key produced no signatures".into()));
    }
    if device_signatures < expected_signatures {
        return Err(Error::Sign(format!(
            "device key produced {device_signatures} of {expected_signatures} expected signatures"
        )));
    }
    Ok(device_signatures)
}

fn count_device_partial_sigs(psbt: &Psbt, device_fp: super::bitcoin::bip32::Fingerprint) -> usize {
    psbt.inputs
        .iter()
        .map(|input| {
            input
                .partial_sigs
                .keys()
                .filter(|pk| {
                    input.bip32_derivation.get(&pk.inner).map(|(fp, _)| *fp == device_fp).unwrap_or(false)
                })
                .count()
        })
        .sum()
}
// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later
