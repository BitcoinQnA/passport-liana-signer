// psbt.rs — match a PSBT against a registered policy and determine the active
// spend branch. This is the security gate's input: we only sign what matches.

use std::collections::{HashMap, HashSet};

use super::bitcoin::bip32::Fingerprint;
use super::bitcoin::psbt;
use super::bitcoin::sighash::EcdsaSighashType;
use super::bitcoin::Psbt;
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
    pub matched_inputs: usize,
    pub total_inputs: usize,
    /// Human-readable notes for the signing-review screen / debugging.
    pub reasons: Vec<String>,
}

/// Match a PSBT against a single registered policy.
/// `gap` is how many derivation indices to check per descriptor path.
pub fn match_psbt(
    psbt: &Psbt,
    policy: &RegisteredPolicy,
    passport_fp: Fingerprint,
    gap: u32,
) -> Result<MatchResult> {
    let parsed = descriptor::import(&policy.descriptor)?;
    let singles = parsed
        .descriptor
        .clone()
        .into_single_descriptors()
        .map_err(|e| super::Error::Match(format!("multipath split: {e}")))?;

    // Precompute candidate scriptPubKeys and witnessScripts for each path/index.
    // The scriptPubKey identifies which registered policy owns the input; the
    // witnessScript check makes sure the signer is not asked to sign against
    // inconsistent PSBT metadata.
    let mut candidates: HashMap<super::bitcoin::ScriptBuf, HashSet<super::bitcoin::ScriptBuf>> =
        HashMap::new();
    for single in &singles {
        for idx in 0..gap {
            if let Ok(def) = single.at_derivation_index(idx) {
                let witness_script = def
                    .explicit_script()
                    .map_err(|e| super::Error::Match(format!("explicit script: {e}")))?;
                candidates.entry(def.script_pubkey()).or_default().insert(witness_script);
            }
        }
    }

    let total_inputs = psbt.inputs.len();
    let mut matched_inputs = 0;
    let mut reasons = Vec::new();

    for (i, input) in psbt.inputs.iter().enumerate() {
        match input.witness_utxo.as_ref() {
            Some(utxo) if candidates.contains_key(&utxo.script_pubkey) => matched_inputs += 1,
            Some(_) => reasons.push(format!("input {i}: scriptPubKey not from this policy")),
            None => reasons.push(format!("input {i}: no witness_utxo (cannot verify)")),
        }
    }
    let matched = total_inputs > 0 && matched_inputs == total_inputs;

    if !matched {
        return Ok(MatchResult {
            matched: false,
            active_path: None,
            active_timelock_blocks: None,
            passport_can_sign: false,
            matched_inputs,
            total_inputs,
            reasons,
        });
    }

    if let Err(reason) = validate_psbt_safety(psbt, &candidates) {
        reasons.push(reason);
        return Ok(MatchResult {
            matched: true,
            active_path: None,
            active_timelock_blocks: None,
            passport_can_sign: false,
            matched_inputs,
            total_inputs,
            reasons,
        });
    }

    // Infer the active branch from every input's nSequence. For a decaying
    // (multi-tier) policy, a relative-block nSequence unlocks every recovery
    // tier whose older(n) it satisfies; the deepest tier reached (largest n)
    // is the one being exercised. Mixed active branches are refused because a
    // single signing confirmation would be ambiguous.
    let input_paths: Vec<Option<u32>> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|txin| {
            let seq_blocks = relative_blocks(txin.sequence);
            deepest_unlocked_recovery(policy, seq_blocks)
        })
        .collect();
    let first_path = input_paths.first().copied().flatten();
    if input_paths.iter().any(|p| *p != first_path) {
        reasons.push("inputs use mixed primary/recovery spend paths".into());
        return Ok(MatchResult {
            matched: true,
            active_path: None,
            active_timelock_blocks: None,
            passport_can_sign: false,
            matched_inputs,
            total_inputs,
            reasons,
        });
    }

    let (active_path, active_timelock_blocks) = match first_path {
        Some(n) => {
            if psbt.unsigned_tx.version.0 < 2 {
                reasons.push("recovery spends require transaction version 2 or higher for BIP68".into());
                return Ok(MatchResult {
                    matched: true,
                    active_path: None,
                    active_timelock_blocks: None,
                    passport_can_sign: false,
                    matched_inputs,
                    total_inputs,
                    reasons,
                });
            }
            reasons.push(format!("nSequence unlocks recovery older({n})"));
            (SpendPathKind::Recovery, Some(n))
        }
        None => (SpendPathKind::Primary, None),
    };

    // The PSBT must reference Passport's key in segwit-v0 bip32 origins, and
    // Passport must own a key on a path that is spendable *right now* — the
    // primary path always, plus any recovery tier the nSequence has unlocked. A
    // key on a not-yet-matured tier cannot sign.
    let passport_in_psbt =
        psbt.inputs.iter().any(|inp| inp.bip32_derivation.values().any(|(fp, _)| *fp == passport_fp));
    let fp_str = passport_fp.to_string();
    let owns_active_key = policy.paths.iter().any(|p| {
        let active = match (active_path, p.kind) {
            (SpendPathKind::Primary, SpendPathKind::Primary) => true,
            (SpendPathKind::Recovery, SpendPathKind::Recovery) => {
                p.relative_timelock_blocks == active_timelock_blocks
            }
            _ => false,
        };
        active && p.signer_fingerprints.contains(&fp_str)
    });
    let passport_can_sign = passport_in_psbt && owns_active_key;
    if !passport_can_sign {
        reasons
            .push("Passport key is not on a currently-spendable path (or not referenced by the PSBT)".into());
    }

    Ok(MatchResult {
        matched,
        active_path: Some(active_path),
        active_timelock_blocks,
        passport_can_sign,
        matched_inputs,
        total_inputs,
        reasons,
    })
}

/// Find the registered policy a PSBT belongs to, out of many.
pub fn match_against_all<'a>(
    psbt: &Psbt,
    policies: &'a [RegisteredPolicy],
    passport_fp: Fingerprint,
    gap: u32,
) -> Result<Option<(&'a RegisteredPolicy, MatchResult)>> {
    let mut matched: Option<(&'a RegisteredPolicy, MatchResult)> = None;
    for p in policies {
        let r = match_psbt(psbt, p, passport_fp, gap)?;
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

fn deepest_unlocked_recovery(policy: &RegisteredPolicy, seq_blocks: Option<u32>) -> Option<u32> {
    policy
        .paths
        .iter()
        .filter(|p| matches!(p.kind, SpendPathKind::Recovery))
        .filter_map(|p| match (seq_blocks, p.relative_timelock_blocks) {
            (Some(s), Some(n)) if s >= n => Some(n),
            _ => None,
        })
        .max()
}

fn validate_psbt_safety(
    psbt: &Psbt,
    candidates: &HashMap<super::bitcoin::ScriptBuf, HashSet<super::bitcoin::ScriptBuf>>,
) -> std::result::Result<(), String> {
    if psbt.inputs.len() != psbt.unsigned_tx.input.len() {
        return Err("PSBT input map count does not match unsigned transaction inputs".into());
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
        let allowed_scripts = candidates
            .get(&utxo.script_pubkey)
            .ok_or_else(|| format!("input {i}: scriptPubKey not from this policy"))?;
        let witness_script = input
            .witness_script
            .as_ref()
            .ok_or_else(|| format!("input {i}: missing witness_script for P2WSH spend"))?;
        if !allowed_scripts.contains(witness_script) {
            return Err(format!("input {i}: witness_script does not match the registered policy"));
        }
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

    Ok(())
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
