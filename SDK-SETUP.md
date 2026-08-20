# Foundation SDK setup

## Supported baseline

Liana Signer targets Foundation SDK 1.0 and KeyOS 1.4.0 or newer. It is an
independent third-party app and does not need a KeyOS source checkout, workspace
registration, launcher allowlist change, or full firmware build.

Install the current SDK on Apple Silicon macOS or Linux x86_64:

```bash
curl -fsSL https://foundation.xyz/sdk/install.sh | sh
foundation doctor
foundation --version
```

The installer verifies the SDK release and manages it under
`~/.foundation/sdk/`. Run SDK commands from the repository root.

## Publisher certificate

Every installable app is signed. Generate a personal or organizational
development identity once:

```bash
foundation cert gen liana-signer-local \
  --publisher-name "Your Name" \
  --contact-email "you@example.com" \
  --support-url "https://example.com"
```

Signing material is stored under `~/.foundation/signing/`, outside this
repository. Back it up securely and never commit the private key. If several
identities exist, the SDK prompts for one in an interactive terminal. Automated
builds should explicitly configure their own identity outside the public source
tree.

A Prime must trust a self-signed publisher before it installs that publisher's
apps. On an unlocked KeyOS 1.4 beta device, enable USB debug, connect the Prime,
inspect the fingerprint, and approve it on the device:

```bash
foundation cert fingerprint liana-signer-local
foundation cert install liana-signer-local
```

Certificate installation is a one-time development step for that device and
publisher. It is separate from app installation.

## Build an installable app

From a clean clone:

```bash
foundation pack --release
```

This command prepares the project-local SDK mapping, validates
`app-config.toml`, compiles the ARM application, signs its manifest, and writes:

```text
target/keyos/gui-app-liana-signer.app
```

Copy the `.app` file to a USB drive or Airlock. On Passport, open
**Settings > Apps** and install it. Installing the archive does not require
Developer Mode or USB debug once the publisher is trusted.

For an iterative USB workflow, leave the unlocked device connected with USB
debug enabled and run:

```bash
foundation sideload --release
```

Use `--no-run` to upload without launching. This installs only the application;
it does not flash or replace KeyOS.

## Build and test commands

```bash
foundation build --release   # signed device bundle
foundation pack --release    # signed single-file .app archive
foundation sim               # hosted Passport simulator
cargo test                   # host tests after SDK project preparation
```

The SDK generates local compatibility paths during the first build:

- `.foundation-sdk/current/`
- `ui/ui`
- `resources/fonts`, `resources/icons`, and `resources/images`
- `manifest.toml`

These are ignored intentionally. Do not commit them or replace SDK paths with
paths to a local KeyOS checkout. `app-config.toml` is the manifest source of
truth.

## Public SDK boundaries

- The app requests `GetAppSeed`, never `GetSeed`. It receives only deterministic
  entropy scoped to this app ID and cannot access Passport's master seed.
- Independently signed apps cannot open the privileged scanner directly. The
  launcher scans QR codes and routes matching `crypto-psbt` and `bytes` payloads
  into the app using the navigation handoff declared in `app-config.toml`.
- File exchange uses public USB, Airlock, and User storage grants.
- Exports call file-level `Flush` before `CloseFile`. Do not add
  `FileSystem::flush`; the filesystem-wide `FlushFs` permission is reserved for
  Foundation apps.
- The signing checks in `src/liana/signing.rs` are a security boundary. Never
  bypass policy matching, active-path detection, ownership, or timelock checks.

## File fallback

QR is the normal Liana workflow. The app also looks in a `liana/` directory and
at the storage root for these interoperability files:

| File | Direction | Purpose |
|---|---|---|
| `import.txt`, `wallet-policy.json`, `wallet-policy.txt` | Liana to Passport | Wallet policy |
| `verify-address.txt`, `address-request.json` | Liana to Passport | Address verification request |
| `unsigned.psbt` | Liana to Passport | Unsigned PSBT |
| `passport-key.txt` | Passport to Liana | Passport public key |
| `signed.psbt` | Passport to Liana | Signed PSBT |

When testing removable FAT media on macOS, prevent Spotlight indexing on the
card to avoid misleading filesystem failures:

```bash
touch /Volumes/NAME/.metadata_never_index
```
<!-- SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
