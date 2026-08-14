# Liana Signer SDK Setup

## Supported baseline

This project targets Foundation SDK 0.4.0 and KeyOS v1.4.0 or newer. The SDK installer verifies signed archives and selects the installed release through `~/.foundation/sdk/current`.

```bash
curl -fsSL https://foundation.xyz/sdk/install.sh | sh
foundation doctor
```

The app keeps its stable 16-byte app ID in `app-config.toml`, so version 0.2.0 upgrades the existing installation and retains app-scoped seed and policy storage identity.

## Build in KeyOS

Place this repository at `apps/gui-app-liana-signer/`, add it to the root workspace members, then run from the KeyOS root:

```bash
cargo test -p gui-app-liana-signer
nix develop .#build --command cargo xtask check gui-app-liana-signer
```

The `xtask check` command validates both `armv7a-unknown-xous-elf` and the hosted simulator. Taproot remains intentionally disabled; use a P2WSH Liana policy on Signet or mainnet.

## Signed bundle

KeyOS v1.4.0 requires a newer Rust toolchain than the one bundled with SDK 0.4.0. Build the app with the v1.4.0 workspace toolchain and sign it with the development identity created by the SDK:

```bash
nix develop .#build --command cargo xtask build-app gui-app-liana-signer \
  --cosign2 ~/.foundation/signing/passport-prime-dev/cosign2.toml \
  --archive
```

The command validates the manifest and permissions, builds the hardware ELF, writes a signed manifest with file hashes, and stages both the USB-debug bundle and `.app` archive under `target/armv7a-unknown-xous-elf/release/app-bundles/`.

The configured development signing identity is `passport-prime-dev`. Change `signing-identity` deliberately when producing a release under another publisher; never commit a private key.

## Sideload to Prime

Unlock Passport Prime, enable Developer Mode and USB app sideload/storage, then connect it over USB. Confirm both the `PRIME` mount and USB serial endpoint are present before running:

```bash
nix develop .#build --command cargo build -p passport-drive --release
target/release/passport-drive load_app \
  target/armv7a-unknown-xous-elf/release/app-bundles/6c69616e612d7369676e65722d617070
```

This installs the app bundle and launches it over USB debug. It does not replace the full KeyOS firmware image. Install or flash the desired KeyOS release through Foundation's firmware workflow first, then sideload the app built against that release.

## Development firmware

To include Liana Signer in a complete local KeyOS development image:

1. Add it to the root workspace and `DEFAULT_APPS_NORMAL`.
2. Add app ID `0x6c69616e612d7369676e65722d617070` to the launcher's `KNOWN_APPS` list and add `main.liana` to each launcher locale. KeyOS 1.4 hides non-removable built-in apps that are not allowlisted.
3. Generate the ignored local firmware key once, then build and flash from the KeyOS root:

```bash
scripts/generate-cosign2-dev-key.sh
nix develop .#build --command cargo xtask build-all
nix develop .#build --command cargo xtask flash
```

The resulting firmware is signed with the ignored local development key and has USB debug enabled. It is suitable for a Prime development unit, not for public release or production devices. Production firmware must be built and signed through Foundation's release infrastructure.

The SDK-standard `resources/icon.svg` is staged automatically for both built-in and sideloaded bundles. Do not add a separate launcher icon implementation.

## Permission constraint

Public SDK apps may use file-level `Flush` and `CloseFile`, but not filesystem-wide `FlushFs`, which is Foundation-only in current KeyOS. Keep the export order as write, file flush, close file, close directory. Adding `FileSystem::flush` will either fail SDK permission validation or be denied on a third-party-signed device.

## Simulator and Liana

For deterministic local Signet testing, configure the hosted app build with the `dev-seed` and `sim-bridge` features, then follow `SIGNET-TEST.md` and launch the workspace simulator:

```bash
cargo xtask run --hosted
```

Build the Liana wallet with the simulator's exported account. The signer correctly refuses policies whose complete xpub does not match its app seed.
<!-- SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
