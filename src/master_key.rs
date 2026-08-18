// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! App-isolated wallet key derived from the KeyOS per-app seed.
//!
//! Hosted simulator builds keep a deterministic fallback behind an explicit
//! development feature. Hardware must always use the app-scoped seed.

security::use_api!();

/// Zeroizing BIP39 seed bytes used as this app's BIP32 master secret.
pub struct AppWalletSeed(ngwallet::bip39::Key);

impl AppWalletSeed {
    pub fn as_bytes(&self) -> &[u8] { &self.0 .0 }
}

/// Fetch the KeyOS seed isolated to this app, then expand it as BIP39 entropy.
/// The app never requests or receives the device wallet's recovery seed.
pub fn app_wallet_seed() -> anyhow::Result<AppWalletSeed> {
    let app_seed = match Security::default().app_seed() {
        Ok(seed) => seed,
        #[cfg(all(not(keyos), feature = "dev-seed"))]
        Err(_) => {
            log::warn!("security.app_seed unavailable; using dev fallback app seed");
            security::AppSeed::new([0x11; 32])
        }
        #[cfg(any(keyos, all(not(keyos), not(feature = "dev-seed"))))]
        Err(e) => return Err(e.into()),
    };

    let secp = ngwallet::bdk_wallet::bitcoin::secp256k1::Secp256k1::new();
    let master = ngwallet::bip39::MasterKey::from_entropy(
        &secp,
        ngwallet::bdk_wallet::bitcoin::Network::Bitcoin,
        app_seed.as_bytes(),
        "",
        None,
    )?;
    Ok(AppWalletSeed(master.key.clone()))
}
