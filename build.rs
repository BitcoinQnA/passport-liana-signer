// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

fn main() {
    let themes_rust_dir = std::env::var("FOUNDATION_THEMES_RUST_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{home}/.foundation/themes/rust")
    });
    println!("cargo:rustc-env=FOUNDATION_THEMES_RUST_DIR={themes_rust_dir}");
    println!("cargo:rerun-if-env-changed=FOUNDATION_THEMES_RUST_DIR");

    slint_keyos_platform_build::compile_options(slint_keyos_platform_build::CompileOptions {
        module_path: "ui/app.slint",
        include_router: true,
        include_slint: true,
        include_translations: true,
        include_time_localization: false,
    });
}
