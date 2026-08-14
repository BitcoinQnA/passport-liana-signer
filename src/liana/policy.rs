// policy.rs — convert a descriptor into the app's simplified policy model:
// classify spend paths (primary vs recovery), extract timelocks + signers.

use super::descriptor::ParsedDescriptor;
use super::miniscript::policy::{Liftable, Semantic};
use super::miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};
use super::{
    Error, PolicySigner, RegisteredPolicy, Result, SpendPath, SpendPathKind, POLICY_SCHEMA_VERSION,
};

type Sem = Semantic<DescriptorPublicKey>;

/// Analyze the spend paths of a (possibly multipath) descriptor.
pub fn analyze_paths(desc: &Descriptor<DescriptorPublicKey>) -> Result<Vec<SpendPath>> {
    // Lift the receive-path (index 0) single descriptor to a semantic policy.
    let singles =
        desc.clone().into_single_descriptors().map_err(|e| Error::Parse(format!("multipath split: {e}")))?;
    let first = singles.first().ok_or_else(|| Error::Parse("descriptor produced no paths".into()))?;
    let policy = first.lift().map_err(|e| Error::Parse(format!("lift to policy: {e}")))?;

    // Flatten the OR-disjunction tree into individual spend branches. A
    // decaying policy nests its recovery tiers (`or_d(primary, or_d(rec1,
    // rec2))` lifts to nested `Thresh(1, …)`), so we recurse rather than only
    // splitting the top level.
    let mut branches: Vec<&Sem> = Vec::new();
    collect_branches(&policy, &mut branches);
    let paths: Vec<SpendPath> = branches.iter().map(|b| analyze_branch(b)).collect();
    if paths.is_empty() {
        return Err(Error::Unsupported("no spendable paths found".into()));
    }
    Ok(paths)
}

/// Recursively flatten OR nodes (`Thresh(1, n>1)`) into separate spend
/// branches, while keeping a 1-of-n key multisig (a `Thresh(1, n)` whose
/// children are all bare keys) as a single branch.
fn collect_branches<'a>(sem: &'a Sem, out: &mut Vec<&'a Sem>) {
    if let Semantic::Thresh(t) = sem {
        let is_or = t.k() == 1 && t.n() > 1;
        let all_keys = t.iter().all(|c| matches!(c.as_ref(), Semantic::Key(_)));
        if is_or && !all_keys {
            for sub in t.iter() {
                collect_branches(sub.as_ref(), out);
            }
            return;
        }
    }
    out.push(sem);
}

fn analyze_branch(sem: &Sem) -> SpendPath {
    let older = find_older(sem);
    let fingerprints = collect_keys(sem);
    let (threshold, total) = key_threshold(sem);
    SpendPath {
        kind: if older.is_some() { SpendPathKind::Recovery } else { SpendPathKind::Primary },
        threshold,
        total_keys: total,
        relative_timelock_blocks: older,
        signer_fingerprints: fingerprints,
    }
}

fn find_older(sem: &Sem) -> Option<u32> {
    match sem {
        Semantic::Older(n) => Some(n.to_consensus_u32()),
        Semantic::Thresh(t) => t.iter().find_map(|c| find_older(c.as_ref())),
        _ => None,
    }
}

fn collect_keys(sem: &Sem) -> Vec<String> {
    match sem {
        Semantic::Key(pk) => vec![pk.master_fingerprint().to_string()],
        Semantic::Thresh(t) => t.iter().flat_map(|c| collect_keys(c.as_ref())).collect(),
        _ => vec![],
    }
}

/// (required signatures, total keys) for a branch.
fn key_threshold(sem: &Sem) -> (usize, usize) {
    match sem {
        Semantic::Key(_) => (1, 1),
        Semantic::Thresh(t) => {
            let children: Vec<&Sem> = t.iter().map(|a| a.as_ref()).collect();
            let key_children = children.iter().filter(|c| matches!(c, Semantic::Key(_))).count();
            let timelock_slots =
                children.iter().filter(|c| matches!(c, Semantic::Older(_) | Semantic::After(_))).count();
            // Nested non-key, non-timelock child (e.g. an inner multisig thresh).
            let nested: Vec<&&Sem> = children
                .iter()
                .filter(|c| !matches!(c, Semantic::Key(_) | Semantic::Older(_) | Semantic::After(_)))
                .collect();

            if key_children > 0 && nested.is_empty() {
                // A multisig (and/thresh of keys) optionally guarded by a timelock.
                let k = t.k().saturating_sub(timelock_slots).max(1);
                (k, key_children)
            } else if let Some(inner) = nested.first() {
                key_threshold(inner)
            } else {
                (1, key_children.max(1))
            }
        }
        _ => (1, 1),
    }
}

/// All signers in the descriptor, flagged for Passport ownership.
pub fn signers(
    desc: &Descriptor<DescriptorPublicKey>,
    passport_fp: super::bitcoin::bip32::Fingerprint,
) -> Vec<PolicySigner> {
    let mut out = Vec::new();
    desc.for_each_key(|k| {
        let fp = k.master_fingerprint();
        let path = k.full_derivation_path().map(|p| p.to_string()).unwrap_or_default();
        out.push(PolicySigner {
            fingerprint: fp.to_string(),
            derivation_path: path,
            xpub: k.to_string(),
            owned_by_passport: fp == passport_fp,
        });
        true
    });
    out
}

/// Build a RegisteredPolicy from a parsed descriptor.
pub fn build_registered_policy(
    id: impl Into<String>,
    name: impl Into<String>,
    network: impl Into<String>,
    parsed: &ParsedDescriptor,
    passport_fp: super::bitcoin::bip32::Fingerprint,
) -> Result<RegisteredPolicy> {
    let paths = analyze_paths(&parsed.descriptor)?;
    let signers = signers(&parsed.descriptor, passport_fp);
    Ok(RegisteredPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        id: id.into(),
        name: name.into(),
        network: network.into(),
        descriptor: parsed.canonical.clone(),
        descriptor_checksum: parsed.checksum.clone(),
        policy_fingerprint: parsed.checksum.clone(),
        signers,
        paths,
        archived: false,
    })
}
