// descriptor.rs — import, normalize, validate, checksum.

use std::str::FromStr;

use super::miniscript::policy::{Liftable, Semantic};
use super::miniscript::{Descriptor, DescriptorPublicKey};
use super::{Error, Result};

type Sem = Semantic<DescriptorPublicKey>;

/// A parsed + validated Liana-shaped descriptor.
pub struct ParsedDescriptor {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    /// 8-char miniscript checksum (the compact policy fingerprint we show).
    pub checksum: String,
    /// Canonical string including `#checksum`.
    pub canonical: String,
}

/// Import descriptor text. Supports the P2WSH (`wsh(...)`) Liana shape. Taproot
/// is intentionally out of scope for this release and rejected clearly rather
/// than silently accepted.
pub fn import(text: &str) -> Result<ParsedDescriptor> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(Error::Parse("empty descriptor".into()));
    }

    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(trimmed)
        .map_err(|e| Error::Parse(format!("invalid descriptor: {e}")))?;

    match &descriptor {
        Descriptor::Wsh(_) => validate_liana_wsh(&descriptor)?,
        Descriptor::Tr(_) => {
            return Err(Error::Unsupported(
                "Taproot (tr) Liana descriptors are not supported in this release; use P2WSH (wsh)".into(),
            ))
        }
        other => {
            return Err(Error::Unsupported(format!(
                "only P2WSH (wsh) Liana descriptors are supported, got: {}",
                kind_name(other)
            )))
        }
    }

    let canonical = descriptor.to_string();
    let checksum = canonical
        .rsplit('#')
        .next()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| Error::Parse("descriptor has no checksum".into()))?
        .to_string();

    Ok(ParsedDescriptor { descriptor, checksum, canonical })
}

fn kind_name(d: &Descriptor<DescriptorPublicKey>) -> &'static str {
    match d {
        Descriptor::Bare(_) => "bare",
        Descriptor::Pkh(_) => "pkh",
        Descriptor::Wpkh(_) => "wpkh",
        Descriptor::Sh(_) => "sh",
        Descriptor::Wsh(_) => "wsh",
        Descriptor::Tr(_) => "tr",
    }
}

fn validate_liana_wsh(desc: &Descriptor<DescriptorPublicKey>) -> Result<()> {
    let singles =
        desc.clone().into_single_descriptors().map_err(|e| Error::Parse(format!("multipath split: {e}")))?;
    let first = singles.first().ok_or_else(|| Error::Parse("descriptor produced no paths".into()))?;
    let policy = first.lift().map_err(|e| Error::Parse(format!("lift to policy: {e}")))?;

    let mut branches = Vec::new();
    collect_branches(&policy, &mut branches);
    if branches.is_empty() {
        return Err(Error::Unsupported("Liana P2WSH policy has no spendable branches".into()));
    }

    let mut primary_paths = 0usize;
    let mut recovery_locks = std::collections::HashSet::new();
    for branch in branches {
        reject_unsupported_nodes(branch)?;
        if key_count(branch) == 0 {
            return Err(Error::Unsupported("Liana P2WSH branches must contain at least one key".into()));
        }

        let mut olders = Vec::new();
        collect_older_locks(branch, &mut olders);
        match olders.as_slice() {
            [] => primary_paths += 1,
            [lock] => {
                if lock.is_time_locked() {
                    return Err(Error::Unsupported(
                        "Liana P2WSH recovery paths must use block-based older(n), not time-based CSV".into(),
                    ));
                }
                let blocks = lock.to_consensus_u32();
                if blocks == 0 {
                    return Err(Error::Unsupported(
                        "Liana P2WSH recovery paths must use a non-zero older(n) timelock".into(),
                    ));
                }
                if !recovery_locks.insert(blocks) {
                    return Err(Error::Unsupported(
                        "Liana P2WSH recovery paths must have distinct older(n) timelocks".into(),
                    ));
                }
            }
            _ => {
                return Err(Error::Unsupported(
                    "Liana P2WSH branches may contain at most one older(n) timelock".into(),
                ))
            }
        }
    }

    if primary_paths != 1 {
        return Err(Error::Unsupported(
            "Liana P2WSH policies must have exactly one primary non-timelocked path".into(),
        ));
    }

    Ok(())
}

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

fn reject_unsupported_nodes(sem: &Sem) -> Result<()> {
    match sem {
        Semantic::Unsatisfiable | Semantic::Trivial => {
            Err(Error::Unsupported("Liana P2WSH branches must not be trivial or unsatisfiable".into()))
        }
        Semantic::After(_) => {
            Err(Error::Unsupported("absolute locktimes are not supported in Liana P2WSH policies".into()))
        }
        Semantic::Sha256(_) | Semantic::Hash256(_) | Semantic::Ripemd160(_) | Semantic::Hash160(_) => {
            Err(Error::Unsupported("hashlock/preimage policies are not supported".into()))
        }
        Semantic::Thresh(t) => {
            for child in t.iter() {
                reject_unsupported_nodes(child.as_ref())?;
            }
            Ok(())
        }
        Semantic::Key(_) | Semantic::Older(_) => Ok(()),
    }
}

fn key_count(sem: &Sem) -> usize {
    match sem {
        Semantic::Key(_) => 1,
        Semantic::Thresh(t) => t.iter().map(|c| key_count(c.as_ref())).sum(),
        _ => 0,
    }
}

fn collect_older_locks<'a>(sem: &'a Sem, out: &mut Vec<&'a super::miniscript::RelLockTime>) {
    match sem {
        Semantic::Older(lock) => out.push(lock),
        Semantic::Thresh(t) => {
            for child in t.iter() {
                collect_older_locks(child.as_ref(), out);
            }
        }
        _ => {}
    }
}
