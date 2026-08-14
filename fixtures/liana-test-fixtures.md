# Liana Miniscript Test Fixtures

These fixtures are for the KeyOS Liana Signer POC.

They are deterministic, public, test-only fixtures. Never use these seeds or descriptors for real funds.

The descriptors use Liana-style formatting:

- Native SegWit Miniscript: `wsh(...)`.
- Primary branch: `or_d(pk(...), ...)` or `or_d(multi(...), ...)`.
- Recovery branch: `and_v(...,older(n))`.
- Key origins: `[fingerprint/48'/1'/0'/2']tpub...`.
- Receive/change multipath suffixes: `/<0;1>/*`.
- Expanding multisig reused signer suffixes: `/<2;3>/*`.
- Descriptor checksum suffix: `#xxxxxxxx`.

Generated with:

```bash
cargo run -p gui-app-liana-signer --example generate_test_fixtures
```

Validation performed by the generator:

- Parses each descriptor with `miniscript::Descriptor<DescriptorPublicKey>`.
- Imports through `liana_signer_core::descriptor::import`.
- Builds a registered policy through `liana_signer_core::policy::build_registered_policy`.

## Network And Derivation

- Network: Signet/testnet-style extended keys.
- Account derivation: `m/48'/1'/0'/2'`.
- Extended public keys use `tpub`.
- Seeds below are raw BIP32 master seed bytes, not BIP39 mnemonic phrases.

## Test Seeds

### Signer A: Passport Primary

```text
seed_hex: 1111111111111111111111111111111111111111111111111111111111111111
fingerprint: 71348c8a
account_path: m/48'/1'/0'/2'
account_xpub: tpubDETqQA3MT5x9re3TS6pqNojJ1oKSJJnTZBkkBip2tayerCPF3JtvnuBzrTWRTXsTs3dWcYwKi8BNwu6WPXNqsQFvpXpLT82eQD6dKiZrZ95
```

### Signer B: Recovery

```text
seed_hex: 2222222222222222222222222222222222222222222222222222222222222222
fingerprint: 0ebce71a
account_path: m/48'/1'/0'/2'
account_xpub: tpubDFctNo6HmnmRWwqT8RENV3dxMKBv9TsENuaLaHzdWJsMzkaEk1q9GcDMbaeN8XwBRv3YT82igkaoWUsvtEMNWngJhVLT3HTDBgKJ6rjmpPx
```

### Signer C: Additional Recovery

```text
seed_hex: 3333333333333333333333333333333333333333333333333333333333333333
fingerprint: 08adc525
account_path: m/48'/1'/0'/2'
account_xpub: tpubDEBbc4DHf8iYsD7sDEbhPE6pnde322fTTYcNUMrFz49cRSk9QA8WiCdzZSBVW5pqMHrSR4yxhXm6E5xCBqyqo93T3Z67JkbeL3bPxsebx8r
```

## Fixture 1: Simple Inheritance, 36 Blocks

Purpose:

- Short timelock for local tests.
- Primary path: Signer A can spend immediately.
- Recovery path: Signer B can spend after 36 blocks.

Policy paths detected by the generator:

```text
Primary: 1 of 1, older=None, signers=["71348c8a"]
Recovery: 1 of 1, older=36, signers=["0ebce71a"]
```

Descriptor:

```text
wsh(or_d(pk([71348c8a/48'/1'/0'/2']tpubDETqQA3MT5x9re3TS6pqNojJ1oKSJJnTZBkkBip2tayerCPF3JtvnuBzrTWRTXsTs3dWcYwKi8BNwu6WPXNqsQFvpXpLT82eQD6dKiZrZ95/<0;1>/*),and_v(v:pkh([0ebce71a/48'/1'/0'/2']tpubDFctNo6HmnmRWwqT8RENV3dxMKBv9TsENuaLaHzdWJsMzkaEk1q9GcDMbaeN8XwBRv3YT82igkaoWUsvtEMNWngJhVLT3HTDBgKJ6rjmpPx/<0;1>/*),older(36))))#zp9e2yrx
```

Checksum:

```text
zp9e2yrx
```

## Fixture 2: Simple Inheritance, 52,560 Blocks

Purpose:

- Approximate 12-month Liana-style inheritance policy.
- Primary path: Signer A can spend immediately.
- Recovery path: Signer B can spend after 52,560 blocks.

Policy paths detected by the generator:

```text
Primary: 1 of 1, older=None, signers=["71348c8a"]
Recovery: 1 of 1, older=52560, signers=["0ebce71a"]
```

Descriptor:

```text
wsh(or_d(pk([71348c8a/48'/1'/0'/2']tpubDETqQA3MT5x9re3TS6pqNojJ1oKSJJnTZBkkBip2tayerCPF3JtvnuBzrTWRTXsTs3dWcYwKi8BNwu6WPXNqsQFvpXpLT82eQD6dKiZrZ95/<0;1>/*),and_v(v:pkh([0ebce71a/48'/1'/0'/2']tpubDFctNo6HmnmRWwqT8RENV3dxMKBv9TsENuaLaHzdWJsMzkaEk1q9GcDMbaeN8XwBRv3YT82igkaoWUsvtEMNWngJhVLT3HTDBgKJ6rjmpPx/<0;1>/*),older(52560))))#qeppxl7t
```

Checksum:

```text
qeppxl7t
```

## Fixture 3: Expanding Multisig, 2-of-2 To 2-of-3, 36 Blocks

Purpose:

- Short-timelock expanding multisig test.
- Primary path: Signers A and B spend as 2-of-2 immediately.
- Recovery path: Signers A, B, and C expand to 2-of-3 after 36 blocks.
- A and B are reused in the recovery branch with Liana-style `/<2;3>/*` paths.
- C enters only in the recovery branch with `/<0;1>/*`.

Policy paths detected by the generator:

```text
Primary: 2 of 2, older=None, signers=["71348c8a", "0ebce71a"]
Recovery: 2 of 3, older=36, signers=["71348c8a", "0ebce71a", "08adc525"]
```

Descriptor:

```text
wsh(or_d(multi(2,[71348c8a/48'/1'/0'/2']tpubDETqQA3MT5x9re3TS6pqNojJ1oKSJJnTZBkkBip2tayerCPF3JtvnuBzrTWRTXsTs3dWcYwKi8BNwu6WPXNqsQFvpXpLT82eQD6dKiZrZ95/<0;1>/*,[0ebce71a/48'/1'/0'/2']tpubDFctNo6HmnmRWwqT8RENV3dxMKBv9TsENuaLaHzdWJsMzkaEk1q9GcDMbaeN8XwBRv3YT82igkaoWUsvtEMNWngJhVLT3HTDBgKJ6rjmpPx/<0;1>/*),and_v(v:thresh(2,pkh([71348c8a/48'/1'/0'/2']tpubDETqQA3MT5x9re3TS6pqNojJ1oKSJJnTZBkkBip2tayerCPF3JtvnuBzrTWRTXsTs3dWcYwKi8BNwu6WPXNqsQFvpXpLT82eQD6dKiZrZ95/<2;3>/*),a:pkh([0ebce71a/48'/1'/0'/2']tpubDFctNo6HmnmRWwqT8RENV3dxMKBv9TsENuaLaHzdWJsMzkaEk1q9GcDMbaeN8XwBRv3YT82igkaoWUsvtEMNWngJhVLT3HTDBgKJ6rjmpPx/<2;3>/*),a:pkh([08adc525/48'/1'/0'/2']tpubDEBbc4DHf8iYsD7sDEbhPE6pnde322fTTYcNUMrFz49cRSk9QA8WiCdzZSBVW5pqMHrSR4yxhXm6E5xCBqyqo93T3Z67JkbeL3bPxsebx8r/<0;1>/*)),older(36))))#a0r0lmfx
```

Checksum:

```text
a0r0lmfx
```

## References

- Liana restore documentation includes a Signet P2WSH inheritance descriptor with `wsh(or_d(pk(.../<0;1>/*),and_v(v:pkh(.../<0;1>/*),older(n))))`: https://wizardsardine.com/liana/support/howtorestore/
- Bitcoin Core's descriptor documentation covers descriptor checksums, `wsh`, `multi`, `thresh`, and multipath descriptor syntax: https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md
<!-- SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz> -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
