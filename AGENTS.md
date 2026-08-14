# AGENTS.md

Guidance for an AI coding agent (Codex, Cursor, and others) helping someone build, run, and extend this project. Keep answers grounded in the files here; do not invent commands.

## What this is

A KeyOS application: a policy-aware Liana Miniscript signer for Foundation Passport Prime. Liana desktop is the wallet and builds the PSBT; this app registers the descriptor, matches a PSBT against it, and signs only a matching PSBT on a spend path the device holds a key for. See [`README.md`](README.md) for the feature tour and [`src/liana/`](src/liana) for the Bitcoin logic.

## Can it be cloned and run today? (read this first)

Not standalone, yet. This is a KeyOS app: it depends on KeyOS crates (`slint_keyos_platform`, `gui_permissions`, `ngwallet`, the `@ui` widget library) that are not vendored here, so `cargo build` in a bare clone will fail. It needs a **KeyOS workspace** around it. Be honest with the user about this rather than attempting a build that cannot succeed.

Two ways to get a workspace, in order of preference:

1. **Foundation SDK** (the `foundation` CLI) — the intended path. Install:
   ```bash
   curl -fsSL https://foundation.xyz/sdk/install.sh | sh
   ```
   (Supported hosts: Apple Silicon macOS and Linux x86_64. The installer verifies a GPG signature and installs to `~/.foundation/sdk/`.) SDK 0.4.0 provides `build`, `sim`, and USB-debug `sideload`; check `foundation --help` for the installed surface. See [`SDK-SETUP.md`](SDK-SETUP.md).
2. **KeyOS source checkout** — clone the KeyOS repo and drop this app in at `apps/gui-app-liana-signer/`, register it in the launcher + workspace, then use `cargo xtask`. KeyOS is Foundation's OS and is not public; this route needs access.

If neither is available, the useful things an agent can still do here: read and explain the code, run the host unit tests (below), and edit the Rust/Slint sources.

## Layout

- `src/liana/` — host-testable Bitcoin logic: `descriptor` (parse/import), `policy` (spend-path model), `psbt` (match + active path), `signing` (the security gate + sign), `store` (persistence).
- `src/main.rs` — the app shell: Slint callbacks, the export/import file flows, device key wiring (app seed to master `Xpriv` to a BIP48 account).
- `ui/` — Slint UI. Pages live in `ui/pages/<name>/{props.slint,page.slint}`; `build.rs` generates the router in `ui/gen/*` from each page's `@rust-attr(route(...))`. To add a screen, add a `pages/<name>/` folder and rebuild.
- `app-config.toml` — the SDK source of truth for identity, version, publisher, and permissions. `manifest.toml` is its compile-time compatibility output. `app-id` must be exactly 16 bytes (`0x` + 32 hex).
- `i18n/en.json` — user-facing strings, referenced as `TR2.lookup(TrId.Xxx)` in Slint.

## Commands

Run these from the **KeyOS workspace root** (once the app is placed there), not from a bare clone.

```bash
# Host unit tests for the app logic (works in a workspace; the crate name is gui-app-liana-signer)
cargo test -p gui-app-liana-signer

# Compile-check for both device (ARM/xous) and simulator, no display needed
cargo xtask check gui-app-liana-signer

# Run the hosted simulator (opens the Passport window; app appears in the dev launcher)
cargo xtask run --hosted        # or: just sim
```

### Device build + flash

- **macOS:** prefix xtask build commands with `AR_armv7a_unknown_xous_elf=arm-none-eabi-ar` (and `RANLIB_...=arm-none-eabi-ranlib`) or you hit a uECC/secp link failure. The full flashable image has historically needed a Linux/Nix build host for the `rfal-sys` (NFC) crate; the SDK's `foundation sideload` is the intended way to push just the app bundle over USB without a full firmware rebuild.
- Flash is over USB via SAM-BA (`cargo xtask flash --system`). The **first flash attempt sometimes fails** with `Status after writing ... was 3` — just re-run it, it usually succeeds on the second try (not deterministic, no reseating needed).

## Simulator + real Liana test

To exercise signing against Liana desktop on the same machine, build the hosted app with the `dev-seed` and `sim-bridge` Cargo features and follow [`SIGNET-TEST.md`](SIGNET-TEST.md). Key point: build the Liana wallet with the simulator's own exported key (shown on the Export Xpub screen), or signing is correctly blocked. Use a **P2WSH / SegWit** inheritance template; Taproot is shelved for now.

## Conventions and gotchas

- **Signing is gated** (`src/liana/signing.rs`): never loosen it to sign an unmatched policy or a path the device does not own. That gate is the point of the app.
- **File exports** write through the picker and must call file-level `Flush` before `CloseFile` (`write_export` in `src/main.rs`) so the FAT directory entry commits. Do not add `FileSystem::flush`: its `FlushFs` permission is Foundation-only in current KeyOS and public SDK apps are denied it.
- When testing exports to a microSD on macOS, disable Spotlight on the card (`touch /Volumes/<CARD>/.metadata_never_index`) — Spotlight indexing can corrupt a removable FAT card and produce misleading results.
- No em dashes in user-facing copy.
- License is GPL-3.0-or-later; keep the SPDX headers on new source files.

## Good first tasks for an agent

- Read `src/liana/{signing,psbt,policy}.rs` and summarize the security model before changing anything.
- Add a UI string: add it to `i18n/en.json` and reference it via `TR2.lookup`.
- Add a page: create `ui/pages/<name>/{props.slint,page.slint}` and let `build.rs` regenerate the route.
