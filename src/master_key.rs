// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Device master key, backed by KeyOS `security.app_seed()`.
//!
//! On real hardware the 32-byte app seed is device-bound and only available
//! once the user is logged in. Hosted simulator builds keep a deterministic
//! fallback so local development remains usable without a hardware login.

security::use_api!();

/// Fetch the 32-byte app seed. Hardware must never fall back to a known key.
pub fn app_seed() -> Result<security::AppSeed, security::AccessDenied> {
    match Security::default().app_seed() {
        Ok(seed) => Ok(seed),
        #[cfg(all(not(keyos), feature = "dev-seed"))]
        Err(_) => {
            log::warn!("security.app_seed unavailable; using dev fallback seed");
            Ok(security::AppSeed::new([0x11; 32]))
        }
        #[cfg(any(keyos, all(not(keyos), not(feature = "dev-seed"))))]
        Err(e) => Err(e),
    }
}
