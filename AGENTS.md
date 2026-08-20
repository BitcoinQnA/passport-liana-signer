# AGENTS.md

Guidance for coding agents working on this repository. Keep commands and claims
grounded in the checked-in files.

## Project

This is a standalone Foundation SDK application for Passport Prime: a
policy-aware Liana Miniscript signer. Liana builds the wallet and PSBT. The app
registers the policy and signs only a matching PSBT through a spend path for
which its app-scoped key is authorized.

The repository targets Foundation SDK 1.0 and KeyOS 1.4.0 or newer. Do not place
it inside a KeyOS checkout or add private KeyOS source dependencies.

## Setup

```bash
curl -fsSL https://foundation.xyz/sdk/install.sh | sh
foundation doctor
foundation build
```

The first SDK build creates the ignored `.foundation-sdk/current` mapping and
resource links used by Cargo and Slint. `app-config.toml` is the source of truth;
`manifest.toml` is generated and ignored.

## Layout

- `src/liana/`: host-testable descriptor, policy, PSBT, signing, and persistence
  logic.
- `src/main.rs`: app shell, KeyOS callbacks, launcher QR handoff, public file
  exchange, and app-seed key wiring.
- `ui/`: Slint pages and local UI2 compatibility components.
- `app-config.toml`: stable app ID, version, QR match rules, publisher, theme,
  and public permissions.
- `i18n/en.json`: user-facing strings.

## Commands

Run commands from this repository root:

```bash
cargo test
foundation build --release
foundation pack --release
foundation sim
foundation sideload --release
```

`foundation pack --release` creates
`target/keyos/gui-app-liana-signer.app`. `foundation sideload` requires an
unlocked device with USB debug enabled. A self-signed publisher must first be
allowed with `foundation cert install <identity>`.

Never use `cargo xtask`, edit a KeyOS workspace, or flash a full firmware image
for this app.

## Security constraints

- Never weaken the gate in `src/liana/signing.rs`. It must reject unmatched
  policies, unknown active paths, keys the app does not own, and immature
  timelocked paths.
- The only seed permission is `GetAppSeed`. Never add `GetSeed` or other
  elevated seed access. Third-party apps must remain isolated from the Passport
  master seed.
- Scanner input arrives through the public launcher navigation handoff and the
  QR match rules in `app-config.toml`. Do not reintroduce privileged scanner or
  file-picker APIs.
- File exports must call file-level `Flush` before `CloseFile`. Do not request
  or call filesystem-wide `FlushFs`.
- Preserve the stable 16-byte `app-id`; changing it changes the app seed and
  storage identity.

## Conventions

- Prefer existing code and UI patterns.
- Add user-facing strings to `i18n/en.json` and reference them through the Slint
  translation API.
- Do not use em dashes in user-facing copy.
- Keep SPDX headers on new source files. The project is GPL-3.0-or-later.
- Do not commit `.foundation-sdk`, generated SDK links, `manifest.toml`, build
  artifacts, signing keys, PSBTs, or wallet policy test data.

## Testing changes

Run host tests for Bitcoin logic and callbacks, then run a release SDK build.
For UI or flow changes, launch `foundation sim` and exercise every affected
screen. For transaction behavior, follow `SIGNET-TEST.md` with a P2WSH/SegWit
Liana policy. Taproot remains intentionally disabled.
<!-- SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
