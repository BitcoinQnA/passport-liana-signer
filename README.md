# Liana Signer for Passport Prime

A policy-aware [Liana](https://wizardsardine.com/liana/) Miniscript signer for
[Foundation Passport Prime](https://foundation.xyz), built as an independent
KeyOS application.

Liana remains the wallet and builds the transaction. Passport registers the
wallet policy and signs only when the PSBT matches that policy and uses a spend
path for which this app holds a key.

This repository is standalone. It does not require the private KeyOS source
tree. A clean clone can be built, signed, packed as a `.app`, simulated, or
sideloaded with Foundation SDK 1.0.

## Features

- **Connect to Liana**: export Passport's BIP48 key as an animated
  `ur:crypto-account` QR or a file.
- **Import a wallet policy**: receive Liana's versioned `ur:bytes` registration,
  review every spend path and signer, then save it to app-scoped storage.
- **Verify an address**: receive Liana's policy-bound request and derive the
  address independently on Passport.
- **Sign a transaction**: receive `ur:crypto-psbt`, match every input against the
  registered policy, review the active path, outputs, and fee, then slide to
  sign.
- **Return the signed PSBT**: display `ur:crypto-psbt` or export a binary BIP174
  `.psbt` file.
- **Manage policies**: rename policies and signer keys, export a policy backup,
  or permanently delete a policy behind confirmation.

Mainnet is the default network. Testnet and Signet are available from the app's
network menu. Taproot remains intentionally disabled; use a P2WSH/SegWit Liana
wallet policy.

## Security model

The signing gate in `src/liana/signing.rs` refuses to sign unless:

1. every PSBT input matches a registered policy,
2. the active spend path can be determined from the transaction, and
3. the app owns a key on a path that is currently spendable.

The app requests only the KeyOS **app seed** (`GetAppSeed`). It cannot request or
access Passport's master seed. Key derivation and persistent storage are scoped
to this app ID. The manifest uses public SDK permissions only.

## Requirements

- Passport Prime running the KeyOS 1.4 beta or a compatible newer release.
- Foundation SDK 1.0 or newer.
- Apple Silicon macOS or Linux x86_64.

Install the SDK and verify the host:

```bash
curl -fsSL https://foundation.xyz/sdk/install.sh | sh
foundation doctor
```

## Build and install

Clone this repository, then run all commands from its root:

```bash
git clone https://github.com/BitcoinQnA/passport-liana-signer.git
cd passport-liana-signer
```

Create a local publisher identity once. Use your own publisher details; the
private signing key remains under `~/.foundation/signing/` and must never be
committed:

```bash
foundation cert gen liana-signer-local \
  --publisher-name "Your Name" \
  --contact-email "you@example.com" \
  --support-url "https://example.com"
```

Build, sign, and create the installable archive:

```bash
foundation pack --release
```

The archive is written to `target/keyos/gui-app-liana-signer.app`. Copy it to a
USB drive or Airlock, then install it on Passport from **Settings > Apps**. This
archive workflow does not require Developer Mode or USB debug after its
publisher certificate has been trusted on the device.

For a self-signed development publisher, unlock the Prime, enable USB debug,
connect it, and approve the certificate once:

```bash
foundation cert install liana-signer-local
```

You can then build and launch directly over USB during development:

```bash
foundation sideload --release
```

Run the hosted simulator with:

```bash
foundation sim
```

See [SDK-SETUP.md](SDK-SETUP.md) for certificate trust, generated files, and
troubleshooting. See [SIGNET-TEST.md](SIGNET-TEST.md) for an end-to-end Liana
test.

## Architecture

- `src/liana/`: host-testable descriptor, policy, PSBT matching, signing, and
  persistence logic.
- `src/main.rs`: KeyOS app shell, public navigation handoff, app-seed key
  derivation, and USB/Airlock file exchange.
- `ui/`: Slint UI and SDK UI2 compatibility components.
- `app-config.toml`: app identity, version, QR match rules, theme, and public
  permissions.
- `i18n/en.json`: user-facing copy.

The SDK creates the ignored `.foundation-sdk/` mapping and generated resource
links during a build. `manifest.toml` is also generated from `app-config.toml`;
the app config is the source of truth.

## Development

After the SDK has prepared the project mapping, run the host tests with:

```bash
cargo test
```

The release package has also been validated with `foundation build --release`
and `foundation pack --release` against SDK 1.0.0.

## License

GPL-3.0-or-later. Copyright Foundation Devices, Inc. Source files carry SPDX
headers.
<!-- SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
