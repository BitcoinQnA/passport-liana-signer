// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Device wallet key, backed by the same BIP39 entropy as KeyOS Bitcoin Wallet.
//!
//! Hosted simulator builds keep a deterministic fallback behind an explicit
//! development feature. Hardware must always use the user's wallet seed.

security::use_api!();

/// Zeroizing BIP39 seed bytes used as the BIP32 master secret.
pub struct WalletSeed(ngwallet::bip39::Key);

impl WalletSeed {
    pub fn as_bytes(&self) -> &[u8] { &self.0 .0 }
}

/// Fetch and expand the device's BIP39 entropy exactly as KeyOS Bitcoin Wallet
/// does for its default (non-passphrase) wallet.
pub fn wallet_seed(passphrase: &str) -> anyhow::Result<WalletSeed> {
    let entropy = match Security::default().seed() {
        Ok(Some(seed)) => seed,
        Ok(None) => anyhow::bail!("no wallet seed is available"),
        #[cfg(all(not(keyos), feature = "dev-seed"))]
        Err(_) => {
            log::warn!("security.seed unavailable; using dev fallback entropy");
            security::Seed::TwentyFour([0x11; 32])
        }
        #[cfg(any(keyos, all(not(keyos), not(feature = "dev-seed"))))]
        Err(e) => return Err(e.into()),
    };

    let secp = ngwallet::bdk_wallet::bitcoin::secp256k1::Secp256k1::new();
    let master = ngwallet::bip39::MasterKey::from_entropy(
        &secp,
        ngwallet::bdk_wallet::bitcoin::Network::Bitcoin,
        entropy.bytes(),
        passphrase,
        None,
    )?;
    Ok(WalletSeed(master.key.clone()))
}
