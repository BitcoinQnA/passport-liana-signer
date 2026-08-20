# End-to-end Liana test on Signet

Use this procedure to validate policy registration, address verification, and
PSBT signing against the local Liana desktop QR fork or a compatible Liana
release. Use a P2WSH/SegWit wallet policy; Taproot is intentionally disabled.

## Prerequisites

- Passport Prime on KeyOS 1.4 beta or newer with Liana Signer installed.
- Liana desktop running in Signet mode.
- Signet coins for the test wallet.
- The same network selected in both applications.

The normal transport is QR. USB or Airlock files can be used as a fallback with
the names documented in `SDK-SETUP.md`.

## Register the policy

1. Open **Connect to Liana** on Passport and leave Mainnet only if Liana is set
   to Signet.
2. In Liana, create a P2WSH/SegWit inheritance wallet and add a hardware wallet
   key.
3. Scan Passport's animated key QR in Liana. The key fingerprint shown by Liana
   must match Passport.
4. Export the completed wallet policy from Liana as a registration QR.
5. Scan it with the Passport launcher. KeyOS routes the matching wallet payload
   into Liana Signer.
6. Review every spending path and signer. Confirm the immediate path identifies
   this Passport before registering the policy.

Importing a policy built with another key is allowed for review, but signing is
correctly unavailable when this app does not own a key on the active path.

## Verify an address

1. Generate a receive address in Liana and choose hardware-wallet verification.
2. Scan Liana's address request with the Passport launcher.
3. Confirm Passport opens Liana Signer and displays the same receive index,
   address, network, and policy checksum.
4. Compare the grouped address on both screens before accepting it.

## Sign a transaction

1. Fund the Liana receive address and wait for confirmation.
2. Create a Signet spend in Liana and choose Passport as a signer.
3. Scan Liana's animated `crypto-psbt` QR with the Passport launcher.
4. Review the active spending path, outputs, fee, and policy identity on
   Passport.
5. Slide to sign only after every detail matches.
6. Scan Passport's signed `crypto-psbt` QR back into Liana.
7. Let Liana combine, finalize, and broadcast the transaction.

Passport signs but does not finalize or broadcast. Liana remains responsible
for wallet state and transaction publication.

## File fallback

For a file test, place `unsigned.psbt` in the `liana/` directory on USB or
Airlock storage. The signed result is exported as `signed.psbt`. Policy and
address-request fallback names are listed in `SDK-SETUP.md`.

## Expected refusals

Repeat negative tests before release. The app must refuse:

- a PSBT whose inputs do not derive from the registered policy,
- a PSBT for a different network,
- a path for which this app owns no signer key,
- a recovery path before its relative timelock has matured,
- malformed or unsupported wallet registrations and PSBTs.
<!-- SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
