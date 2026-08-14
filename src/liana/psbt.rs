// psbt.rs — match a PSBT against a registered policy and determine the active
// spend branch. This is the security gate's input: we only sign what matches.

use std::collections::HashSet;

use super::bitcoin::bip32::Fingerprint;
use super::bitcoin::psbt;
use super::bitcoin::sighash::EcdsaSighashType;
use super::bitcoin::Psbt;
use super::miniscript::psbt::{PsbtInputExt, PsbtOutputExt};
use super::{descriptor, RegisteredPolicy, Result, SpendPathKind};

/// Outcome of matching a PSBT against a registered policy.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchResult {
    /// Every input's witnessScript matched a script derived from this policy.
    pub matched: bool,
    /// The spend branch the PSBT intends to use (inferred from input sequence).
    pub active_path: Option<SpendPathKind>,
    /// Relative timelock (blocks) of the active path, if it is a recovery path.
    pub active_timelock_blocks: Option<u32>,
    /// Passport owns a key on the active path AND that key is in the PSBT's
    /// bip32 derivations (i.e. we can actually contribute a signature).
    pub passport_can_sign: bool,
    /// Number of PSBT inputs that reference Passport's fingerprint in their
    /// bip32 derivations.
    pub passport_derivation_inputs: usize,
    /// Minimum number of signatures Passport is expected to add for this PSBT.
    /// For the supported Liana P2WSH flow this is one signature per input when
    /// Passport owns the active path.
    pub expected_signatures: usize,
    pub matched_inputs: usize,
    pub total_inputs: usize,
    /// Output indexes proven to belong to this policy using the complete PSBT
    /// derivation map and output script.
    pub change_outputs: HashSet<usize>,
    /// Human-readable notes for the signing-review screen / debugging.
    pub reasons: Vec<String>,
}

/// Match a PSBT against a single registered policy.
pub fn match_psbt(psbt: &Psbt, policy: &RegisteredPolicy, passport_fp: Fingerprint) -> Result<MatchResult> {
    let parsed = descriptor::import(&policy.descriptor)?;
    let singles = parsed
        .descriptor
        .clone()
        .into_single_descriptors()
        .map_err(|e| super::Error::Match(format!("multipath split: {e}")))?;

    let total_inputs = psbt.inputs.len();
    let mut matched_inputs = 0;
    let mut expected_signatures = 0usize;
    let mut reasons = Vec::new();

    for (i, input) in psbt.inputs.iter().enumerate() {
        match match_input(input, &singles, passport_fp) {
            Ok(owned_keys) => {
                matched_inputs += 1;
                expected_signatures = expected_signatures.saturating_add(owned_keys);
            }
            Err(reason) => reasons.push(format!("input {i}: {reason}")),
        }
    }
    let matched = total_inputs > 0 && matched_inputs == total_inputs;

    if !matched {
        return Ok(MatchResult {
            matched: false,
            active_path: None,
            active_timelock_blocks: None,
            passport_can_sign: false,
            passport_derivation_inputs: 0,
            expected_signatures: 0,
            matched_inputs,
            total_inputs,
            change_outputs: HashSet::new(),
            reasons,
        });
    }

    let change_outputs = match validate_psbt_safety(psbt, &singles, passport_fp) {
        Ok(change_outputs) => change_outputs,
        Err(reason) => {
            reasons.push(reason);
            return Ok(MatchResult {
                matched: true,
                active_path: None,
                active_timelock_blocks: None,
                passport_can_sign: false,
                passport_derivation_inputs: 0,
                expected_signatures: 0,
                matched_inputs,
                total_inputs,
                change_outputs: HashSet::new(),
                reasons,
            });
        }
    };

    // A sequence may make several Miniscript paths valid at once. Preserve
    // that fact instead of assuming the deepest unlocked recovery path is the
    // one being used. Every input must expose the same compatible path set so
    // one review cannot conceal mixed authorization conditions.
    let input_paths: Vec<Vec<(SpendPathKind, Option<u32>)>> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|txin| compatible_paths(policy, psbt.unsigned_tx.version.0, txin.sequence))
        .collect();
    let first_paths = input_paths.first().cloned().unwrap_or_default();
    if input_paths.iter().any(|paths| *paths != first_paths) {
        reasons.push("inputs use mixed primary/recovery spend paths".into());
        return Ok(MatchResult {
            matched: true,
            active_path: None,
            active_timelock_blocks: None,
            passport_can_sign: false,
            passport_derivation_inputs: 0,
            expected_signatures: 0,
            matched_inputs,
            total_inputs,
            change_outputs: HashSet::new(),
            reasons,
        });
    }

    // The PSBT must reference Passport's key in segwit-v0 bip32 origins on
    // every policy input, and Passport must own a key on at least one path that
    // is compatible with every input's lock conditions.
    let passport_derivation_inputs = psbt
        .inputs
        .iter()
        .filter(|inp| inp.bip32_derivation.values().any(|(fp, _)| *fp == passport_fp))
        .count();
    let fp_str = passport_fp.to_string();
    let mut owned_compatible: Vec<(SpendPathKind, Option<u32>)> = first_paths
        .iter()
        .copied()
        .filter(|(kind, timelock)| {
            policy.paths.iter().any(|path| {
                path.kind == *kind
                    && path.relative_timelock_blocks == *timelock
                    && path.signer_fingerprints.contains(&fp_str)
            })
        })
        .collect();
    owned_compatible
        .sort_by_key(|(kind, timelock)| (matches!(kind, SpendPathKind::Recovery), timelock.unwrap_or(0)));
    let selected = owned_compatible.first().copied();
    let (active_path, active_timelock_blocks) = selected.unwrap_or((SpendPathKind::Primary, None));
    for (_, timelock) in &owned_compatible {
        if let Some(blocks) = timelock {
            reasons.push(format!("nSequence permits recovery older({blocks})"));
        }
    }
    let owns_active_key = selected.is_some();
    let passport_can_sign =
        owns_active_key && expected_signatures > 0 && passport_derivation_inputs == total_inputs;
    if !owns_active_key {
        reasons.push("Passport key is not on the active spend path".into());
    } else if passport_derivation_inputs != total_inputs {
        reasons.push(format!(
            "Passport key is referenced by {passport_derivation_inputs} of {total_inputs} policy inputs; refusing partial signing"
        ));
    }

    Ok(MatchResult {
        matched,
        active_path: Some(active_path),
        active_timelock_blocks,
        passport_can_sign,
        passport_derivation_inputs,
        expected_signatures,
        matched_inputs,
        total_inputs,
        change_outputs,
        reasons,
    })
}

/// Find the registered policy a PSBT belongs to, out of many.
pub fn match_against_all<'a>(
    psbt: &Psbt,
    policies: &'a [RegisteredPolicy],
    passport_fp: Fingerprint,
) -> Result<Option<(&'a RegisteredPolicy, MatchResult)>> {
    let mut matched: Option<(&'a RegisteredPolicy, MatchResult)> = None;
    for p in policies {
        let r = match_psbt(psbt, p, passport_fp)?;
        if r.matched {
            if matched.is_some() {
                return Err(super::Error::Match(
                    "PSBT matches more than one registered policy; refusing ambiguous match".into(),
                ));
            }
            matched = Some((p, r));
        }
    }
    Ok(matched)
}

/// Relative block-height from an nSequence, if it encodes one.
fn relative_blocks(seq: super::bitcoin::Sequence) -> Option<u32> {
    seq.to_relative_lock_time().and_then(|lt| match lt {
        super::bitcoin::relative::LockTime::Blocks(h) => Some(h.value() as u32),
        super::bitcoin::relative::LockTime::Time(_) => None,
    })
}

fn compatible_paths(
    policy: &RegisteredPolicy,
    transaction_version: i32,
    sequence: super::bitcoin::Sequence,
) -> Vec<(SpendPathKind, Option<u32>)> {
    let sequence_blocks = relative_blocks(sequence);
    policy
        .paths
        .iter()
        .filter(|path| match path.kind {
            SpendPathKind::Primary => true,
            SpendPathKind::Recovery => {
                transaction_version >= 2
                    && matches!(
                        (sequence_blocks, path.relative_timelock_blocks),
                        (Some(sequence), Some(required)) if sequence >= required
                    )
            }
        })
        .map(|path| (path.kind, path.relative_timelock_blocks))
        .collect()
}

fn validate_psbt_safety(
    psbt: &Psbt,
    singles: &[super::miniscript::Descriptor<super::miniscript::DescriptorPublicKey>],
    passport_fp: Fingerprint,
) -> std::result::Result<HashSet<usize>, String> {
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err("PSBT input map count does not match unsigned transaction inputs".into());
    }
    if psbt.outputs.len() != psbt.unsigned_tx.output.len() {
        return Err("PSBT output map count does not match unsigned transaction outputs".into());
    }

    let mut input_sum = 0u64;
    for (i, input) in psbt.inputs.iter().enumerate() {
        validate_sighash(i, input)?;
        if input.redeem_script.is_some() {
            return Err(format!("input {i}: redeem_script is not supported for native P2WSH policies"));
        }
        let utxo = input
            .witness_utxo
            .as_ref()
            .ok_or_else(|| format!("input {i}: no witness_utxo (cannot verify amount)"))?;
        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or_else(|| format!("input {i}: missing witness_script for P2WSH spend"))?;
        let _ = witness_script;
        match_input(input, singles, passport_fp).map_err(|reason| format!("input {i}: {reason}"))?;
        validate_non_witness_utxo(i, psbt, input, utxo)?;
        input_sum =
            input_sum.checked_add(utxo.value.to_sat()).ok_or_else(|| "input amount overflow".to_string())?;
    }

    let mut output_sum = 0u64;
    for output in &psbt.unsigned_tx.output {
        output_sum = output_sum
            .checked_add(output.value.to_sat())
            .ok_or_else(|| "output amount overflow".to_string())?;
    }

    if output_sum > input_sum {
        return Err("transaction outputs exceed verified inputs".into());
    }

    let mut change_outputs = HashSet::new();
    for (index, (output, txout)) in psbt.outputs.iter().zip(&psbt.unsigned_tx.output).enumerate() {
        match match_output(output, txout, singles, passport_fp) {
            Ok(true) => {
                change_outputs.insert(index);
            }
            Ok(false) => {}
            Err(reason) => return Err(format!("output {index}: {reason}")),
        }
    }

    Ok(change_outputs)
}

fn derivation_indexes(
    derivations: &std::collections::BTreeMap<
        super::bitcoin::secp256k1::PublicKey,
        super::bitcoin::bip32::KeySource,
    >,
) -> HashSet<u32> {
    derivations
        .values()
        .filter_map(|(_, path)| path.into_iter().next_back())
        .filter_map(|child| match child {
            super::bitcoin::bip32::ChildNumber::Normal { index } => Some(*index),
            super::bitcoin::bip32::ChildNumber::Hardened { .. } => None,
        })
        .collect()
}

fn match_input(
    input: &psbt::Input,
    singles: &[super::miniscript::Descriptor<super::miniscript::DescriptorPublicKey>],
    passport_fp: Fingerprint,
) -> std::result::Result<usize, String> {
    let utxo = input.witness_utxo.as_ref().ok_or_else(|| "no witness_utxo (cannot verify)".to_string())?;
    let witness_script =
        input.witness_script.as_ref().ok_or_else(|| "missing witness_script for P2WSH spend".to_string())?;
    let indexes = derivation_indexes(&input.bip32_derivation);
    if indexes.is_empty() {
        return Err("missing unhardened policy derivations".into());
    }

    let mut matches = Vec::new();
    for descriptor in singles {
        for index in &indexes {
            let Ok(definite) = descriptor.at_derivation_index(*index) else {
                continue;
            };
            let mut expected = psbt::Input::default();
            let Ok(derived) = expected.update_with_descriptor_unchecked(&definite) else {
                continue;
            };
            if derived.script_pubkey() == utxo.script_pubkey
                && expected.witness_script.as_ref() == Some(witness_script)
                && expected.bip32_derivation == input.bip32_derivation
            {
                let owned = expected
                    .bip32_derivation
                    .values()
                    .filter(|(fingerprint, _)| *fingerprint == passport_fp)
                    .count();
                matches.push(owned);
            }
        }
    }

    match matches.as_slice() {
        [owned] if *owned > 0 => Ok(*owned),
        [..] if matches.len() > 1 => Err("derivations match the policy ambiguously".into()),
        _ => Err("scripts and derivations do not match the registered policy".into()),
    }
}

fn match_output(
    output: &psbt::Output,
    txout: &super::bitcoin::TxOut,
    singles: &[super::miniscript::Descriptor<super::miniscript::DescriptorPublicKey>],
    passport_fp: Fingerprint,
) -> std::result::Result<bool, String> {
    if !output.bip32_derivation.values().any(|(fingerprint, _)| *fingerprint == passport_fp) {
        return Ok(false);
    }
    let indexes = derivation_indexes(&output.bip32_derivation);
    let mut matches = 0usize;
    for descriptor in singles {
        for index in &indexes {
            let Ok(definite) = descriptor.at_derivation_index(*index) else {
                continue;
            };
            let mut expected = psbt::Output::default();
            let Ok(derived) = expected.update_with_descriptor_unchecked(&definite) else {
                continue;
            };
            if derived.script_pubkey() == txout.script_pubkey
                && expected.bip32_derivation == output.bip32_derivation
                && (output.witness_script.is_none() || output.witness_script == expected.witness_script)
                && output.redeem_script == expected.redeem_script
            {
                matches += 1;
            }
        }
    }
    match matches {
        0 => Err("derivations do not match a registered-policy output".into()),
        1 => Ok(true),
        _ => Err("derivations match the policy ambiguously".into()),
    }
}

fn validate_sighash(i: usize, input: &psbt::Input) -> std::result::Result<(), String> {
    let sighash = input.ecdsa_hash_ty().map_err(|e| format!("input {i}: non-standard sighash type: {e}"))?;
    if sighash != EcdsaSighashType::All {
        return Err(format!("input {i}: unsupported sighash type {sighash}; only SIGHASH_ALL is allowed"));
    }
    Ok(())
}

fn validate_non_witness_utxo(
    i: usize,
    psbt: &Psbt,
    input: &psbt::Input,
    witness_utxo: &super::bitcoin::TxOut,
) -> std::result::Result<(), String> {
    let Some(prev_tx) = input.non_witness_utxo.as_ref() else {
        return Ok(());
    };
    let Some(txin) = psbt.unsigned_tx.input.get(i) else {
        return Err(format!("input {i}: missing unsigned transaction input"));
    };
    let prevout = txin.previous_output;
    if prev_tx.compute_txid() != prevout.txid {
        return Err(format!("input {i}: non_witness_utxo txid does not match prevout"));
    }
    let prev_output = prev_tx
        .output
        .get(prevout.vout as usize)
        .ok_or_else(|| format!("input {i}: prevout index is outside non_witness_utxo outputs"))?;
    if prev_output != witness_utxo {
        return Err(format!("input {i}: witness_utxo does not match non_witness_utxo prevout"));
    }
    Ok(())
}
// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later
