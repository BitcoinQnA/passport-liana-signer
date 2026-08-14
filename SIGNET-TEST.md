# Testing Liana Signer with real Liana on Signet

Liana is **file-based** (no QR/UR/BBQr import — verified against their repo). This
test runs the Passport **hosted simulator** and **Liana desktop** on the same Mac
and exchanges files through one shared host folder. Build/run the hosted app with
the `dev-seed` and `sim-bridge` Cargo features enabled for this convenience
path; release builds leave both disabled.

> **Sim vs device file transport.** In the hosted simulator the device file
> picker browses a *simulated* FAT disk (`xous/kernel/disk_system.dat`), which a
> host app like Liana can't see. So for this same-Mac test the bridge is the
> **host folder below** (the app reads/writes it directly). The file picker is
> the real-Passport-Prime mechanism (USB/Airlock) and is still wired in. Without
> the `sim-bridge` feature, the app ignores these host files. Without the
> `dev-seed` feature, a host build will not fall back to the deterministic
> simulator wallet entropy when `security.seed()` is unavailable.
>
> **You must build the Liana wallet with the SIM's own key.** Export Xpub in the
> sim shows the device fingerprint (e.g. `6ac68ab8`); use *that* key in Liana, or
> the sim won't hold the private key to sign. A descriptor built from any other
> key will import and display fine, but Sign will be blocked (correctly).

## Shared folder

```
~/.passport-liana-signer-keyos/
```
| File | Direction | What |
|------|-----------|------|
| `passport-key.txt`   | Passport → Liana | signer key `[fp/48'/1'/0'/2']tpub…` (also shown on the Export Xpub screen) |
| `import.txt`         | Liana → Passport | the wallet descriptor `wsh(...)#checksum` |
| `unsigned.psbt`      | Liana → Passport | PSBT to sign (binary or base64) |
| `signed.psbt`        | Passport → Liana | signed PSBT (binary) |
| `signed-psbt.b64.txt`| Passport → Liana | same, base64 (for paste) |

## Prerequisites

- Liana desktop in **Signet** mode (Settings → network, or run the Signet build).
- Passport hosted simulator running with `gui-app-liana-signer/dev-seed` and
  `gui-app-liana-signer/sim-bridge` enabled → open **Liana Signer**.
- **Important — P2WSH only.** This POC supports SegWit `wsh` miniscript, not
  Taproot. When creating the Liana wallet choose the **P2WSH / SegWit** script
  type and a **simple inheritance** template (one primary key + one recovery
  key with a relative timelock). If Liana only offers Taproot for that template,
  that descriptor won't import yet; Taproot is intentionally shelved for now.

## Steps

1. **Export Passport's key.** In the sim: Liana Signer → **Export Xpub**. Either
   copy the `[fp/48'/1'/0'/2']tpub…` string shown, or tap **Export to file** to
   pick a destination (USB / Airlock / User) via the file-browser overlay — the
   real Prime flow. A copy is also written to `passport-key.txt` in the shared
   folder for convenience on this same-Mac test.

2. **Create the Liana wallet (Signet, P2WSH).** New wallet → simple inheritance →
   for the **primary** key choose *"Enter / import an extended public key"* and
   paste Passport's key. For the **recovery** key, let Liana generate a hot key
   (or paste any other xpub). Set the recovery timelock.

3. **Export the descriptor.** After creation, copy Liana's full descriptor
   (`wsh(or_d(...))#checksum`) and save it to `import.txt`.

4. **Register it on Passport.** Save Liana's descriptor as `import.txt` in the
   shared folder, then Liana Signer → **Import Policy** (in the sim it reads
   `import.txt`; on real Prime it opens the file picker). Open the new policy →
   confirm the **Primary path** shows your key as **"This Passport"** (green) —
   this only happens if the wallet used the sim's exported key.

5. **Fund it.** In Liana, get a receive address and send Signet coins from a
   faucet. Wait for a confirmation.

6. **Build + export a spend.** In Liana, create a send. At signing, Passport is
   not a USB device, so **export the PSBT to a file** → save as `unsigned.psbt`.

7. **Sign on Passport.** Open the policy → **Sign PSBT**. It loads
   `unsigned.psbt`, matches it, and shows the review (active path = Primary,
   outputs, fee). Tap **Sign** → it signs, then the **file picker** opens to
   choose where to save `signed.psbt` (a copy is also written to the shared
   folder + `signed-psbt.b64.txt`). Passport signs only; it does **not**
   finalize (that's Liana's job).

8. **Finalize + broadcast.** In Liana, **import** `signed.psbt` (or paste the
   base64). Liana combines, finalizes, and broadcasts.

## Notes / current limits

- The sim's device key is derived deterministically from the app seed, so it's
  stable across restarts — re-importing works.
- First test exercises the **primary** (owner-now) path. Testing a **recovery**
  spend needs Passport to own the recovery key + the timelock to have elapsed.
- Network is hardcoded to **Signet** (`tpub`). Liana must be in Signet too.
- On real hardware, the same files move via microSD / USB mass-storage instead of
  the shared folder (device bring-up is a later milestone).
<!-- SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
