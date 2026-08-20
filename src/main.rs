// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

#![allow(clippy::crate_in_macro_def)] // Emitted by KeyOS's generated translation macro.

//! Liana Signer — a policy-aware signer for Liana-shaped Miniscript policies.
//!
//! Passport is NOT the wallet: Liana desktop builds the PSBT. This app
//! registers the policy, matches a PSBT against it, shows the active spend
//! branch, and signs only when the PSBT matches and Passport owns a key on
//! that branch. All policy/PSBT/signing logic lives in `src/liana`.

mod liana;
mod master_key;
mod theme;

use std::{
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use foundation_urtypes::value::Value as UrValue;
// Bitcoin types used only by the test fixtures (seed_sample / build_owner_psbt).
#[cfg(test)]
use liana::bitcoin::{
    absolute::LockTime,
    psbt::{Input, Output},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use liana::{
    bitcoin::{
        bip32::{DerivationPath, Fingerprint, Xpriv, Xpub},
        psbt::Psbt,
        secp256k1::{All, Secp256k1},
        Address, Network,
    },
    descriptor,
    miniscript::ForEachKey,
    policy, psbt as lpsbt, signing, store, transport, RegisteredPolicy, SpendPathKind,
};
use slint_keyos_platform::{
    app_ui2,
    gui_server_api::{
        navigation::qrscanner::{MatchedQrResult, ScanQrResult},
        InputMessage,
    },
    slint::{ComponentHandle, ModelRc, VecModel},
    spawn_local, spawn_worker,
};

app_ui2!("Liana");
include!(concat!(env!("OUT_DIR"), "/tr.rs"));

const DEFAULT_NETWORK: Network = Network::Bitcoin;
const LIANA_ACCOUNT: u32 = 0;
#[cfg(test)]
const TEST_ACCOUNT_PATH: &str = "m/48'/1'/0'/2'";
#[cfg(test)]
const RECOVERY_BLOCKS: u32 = 52_560; // ~12 months (test fixtures only)
const DATA_SUBDIR: &str = ".passport-liana-signer-keyos";
const MAX_PSBT_BYTES: u64 = 8 * 1_048_576;
const MAX_DESCRIPTOR_BYTES: u64 = transport::MAX_DESCRIPTOR_BYTES as u64;
const MAX_POLICY_STORAGE_BYTES: u64 = 32 * 1024;
const HIGH_FEE_WARNING_PERCENT: u64 = 25;
const ADDRESS_SEARCH_LIMIT: u32 = 50;

// Optional host-bridge paths used only by explicit simulator test features.
const IMPORT_DESCRIPTOR_FILE: &str = "import.txt"; // host-bridge descriptor (sim test)
const UNSIGNED_PSBT_FILE: &str = "unsigned.psbt"; // Liana's exported PSBT (base64 or binary)
const SIGNED_PSBT_FILE: &str = "signed.psbt"; // binary BIP174 returned to Liana
const EXPORT_KEY_FILE: &str = "passport-key.txt"; // key-with-origin for Liana signer import
const VERIFY_ADDRESS_FILE: &str = "verify-address.txt"; // sim bridge for address verification
const NETWORK_PREFERENCE_FILE: &str = "network.txt";
const EXPORT_DIR: &str = "liana"; // subdir used when the user picks a location root

/// Live app state shared across UI callbacks.
struct AppState {
    secp: Secp256k1<All>,
    seed: master_key::AppWalletSeed,
    fp: Fingerprint,
    data_dir: PathBuf,
    policies: store::PolicyStore,
    xpub_network: Network,
    pending: Option<Pending>,
    /// A parsed-but-not-yet-committed policy awaiting the user's confirmation in
    /// the guided import-review flow.
    pending_import: Option<RegisteredPolicy>,
    /// The most recently signed PSBT (serialized), kept in memory so "Save to
    /// file" can export it via the file picker without a std::fs round-trip
    /// (which doesn't work on device).
    last_signed: Option<Vec<u8>>,
    /// Bound address-verification JSON returned to Liana as `ur:bytes`.
    last_address_response: Option<Vec<u8>>,
    /// Inputs delivered by the launcher's universal QR scanner. Independent
    /// SDK applications receive matching scans through NavigationFocused.
    incoming_policy: Option<String>,
    incoming_psbt: Option<Psbt>,
    incoming_address: Option<AddressScan>,
}

/// A PSBT awaiting the user's sign/reject decision, with the policy + match it
/// was reviewed against (so the signing gate is re-checked at approve time).
struct Pending {
    psbt: Psbt,
    policy: RegisteredPolicy,
}

enum AddressScan {
    Request(Vec<u8>),
    Address(String),
}

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Starting Liana Signer");

    theme::init(&ui);
    init_tr!(ui);
    ui.global::<Utils>()
        .on_qrcode(slint_keyos_platform::qrcode::render);

    let secp = Secp256k1::new();
    let seed = match master_key::app_wallet_seed() {
        Ok(seed) => seed,
        Err(_) => {
            show_startup_error(&ui, tr::lookup_id(TrId::ErrorSeedUnavailable));
            ui.run().expect("UI running");
            return;
        }
    };
    let master = master_for_network(seed.as_bytes(), DEFAULT_NETWORK).expect("master xpriv");
    let fp = master.fingerprint(&secp);

    let data_dir = data_dir();
    #[cfg(not(keyos))]
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log::error!("cannot create data dir {}: {e}", data_dir.display());
    }

    let selected_network = load_network_preference(&data_dir).unwrap_or(DEFAULT_NETWORK);

    // Load only the policies the user has actually imported (no placeholder seed).
    let policies = load_policies(&data_dir, seed.as_bytes(), &secp, fp);

    let state = Arc::new(Mutex::new(AppState {
        secp,
        seed,
        fp,
        data_dir,
        policies,
        xpub_network: selected_network,
        pending: None,
        pending_import: None,
        last_signed: None,
        last_address_response: None,
        incoming_policy: None,
        incoming_psbt: None,
        incoming_address: None,
    }));

    refresh_home(&ui, &state);
    set_status(&ui, tr::lookup_id(TrId::StatusReady));

    // -- select policy -> populate detail -----------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_select_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let st = state.lock().unwrap();
            if let Some(reg) = st.policies.find_by_checksum(id.as_str()) {
                populate_detail(&ui, reg);
            }
        });
    }

    // -- export xpub --------------------------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_xpub(move || {
            let Some(ui) = weak.upgrade() else { return };
            let network = state.lock().unwrap().xpub_network;
            set_xpub_export(&ui, &state, network);
        });
    }

    // -- switch exported key network ---------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_set_xpub_network(move |network| {
                let Some(ui) = weak.upgrade() else { return };
                set_xpub_export(
                    &ui,
                    &state,
                    network_from_label(network.as_str()).unwrap_or(DEFAULT_NETWORK),
                );
            });
    }

    // -- animated crypto-account QR ----------------------------------------
    {
        let state = state.clone();
        ui.global::<Callbacks>().on_xpub_qr_parts(move |density| {
            let st = state.lock().unwrap();
            let result = account_xpub(st.seed.as_bytes(), &st.secp, st.xpub_network, LIANA_ACCOUNT)
                .and_then(|xpub| {
                    transport::encode_crypto_account(
                        st.fp,
                        xpub.parent_fingerprint,
                        &xpub,
                        st.xpub_network,
                        LIANA_ACCOUNT,
                    )
                    .map_err(|e| anyhow::anyhow!(e.to_string()))
                });
            match result {
                Ok(cbor) => slint_keyos_platform::qrcode::encode_qr_parts(
                    "crypto-account",
                    cbor,
                    density.max(100),
                ),
                Err(e) => {
                    log::error!("could not encode Liana crypto-account: {e}");
                    Default::default()
                }
            }
        });
    }

    // -- export key to a chosen location via the file picker ----------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_key_file(move || {
            let Some(ui) = weak.upgrade() else { return };
            let key = {
                let st = state.lock().unwrap();
                key_with_origin(
                    st.seed.as_bytes(),
                    &st.secp,
                    st.fp,
                    st.xpub_network,
                    LIANA_ACCOUNT,
                )
                .unwrap_or_else(|_| String::new())
            };
            let cb = ui.global::<Callbacks>();
            cb.set_export_ok(false);
            if key.is_empty() {
                cb.set_export_error(tr::lookup_id(TrId::ErrorXpubDeriveFailed).into());
                return;
            }
            match export_exchange_file(EXPORT_KEY_FILE, key.as_bytes()) {
                Ok(dest) => {
                    cb.set_export_error("".into());
                    cb.set_export_done_title(tr::lookup_id(TrId::ExportKeySavedTitle).into());
                    cb.set_export_done_detail(
                        format!(
                            "{}\n{}",
                            format_saved_to(&dest),
                            tr::lookup_id(TrId::ExportKeySavedDetail)
                        )
                        .into(),
                    );
                    cb.set_export_ok(true);
                }
                Err(e) => {
                    let msg = format!("{e}");
                    // A user cancel is not an error to surface.
                    cb.set_export_error(if msg.contains("cancelled") {
                        "".into()
                    } else {
                        msg.into()
                    });
                }
            }
        });
    }

    // -- sign psbt: build a demo owner-path PSBT, match, show review --------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_sign_psbt(move |_id| {
            let Some(ui) = weak.upgrade() else { return };
            // Gate navigation: the home button only opens the review screen when
            // this is set, so a cancelled picker stays on home (no stale screen).
            {
                let cb = ui.global::<Callbacks>();
                cb.set_review_ready(false);
                cb.set_psbt_loading(false);
                review_message(&ui, "");
                let mut st = state.lock().unwrap();
                st.pending = None;
                st.last_signed = None;
            }

            // Load the PSBT. The sim bridge (DATA_SUBDIR/unsigned.psbt) wins if
            // present; otherwise scan Liana's animated `crypto-psbt` QR. The
            // scanner's file button keeps binary microSD as the large-PSBT fallback.
            let incoming = { state.lock().unwrap().incoming_psbt.take() };
            let bridge = { sim_bridge_file(&state.lock().unwrap().data_dir, UNSIGNED_PSBT_FILE) };
            let psbt = if let Some(psbt) = incoming {
                psbt
            } else if let Some(bridge) = bridge {
                match read_psbt_file(&bridge) {
                    Ok(p) => p,
                    Err(e) => {
                        let err = format!("{e}");
                        review_message(
                            &ui,
                            &trfmt(TrId::ErrorReadNamedFile, &[UNSIGNED_PSBT_FILE, &err]),
                        );
                        ui.global::<Callbacks>().set_review_ready(true);
                        return;
                    }
                }
            } else {
                match read_psbt_exchange_file() {
                    Ok(p) => p,
                    Err(e) => {
                        // A user cancel is not an error: stay on home silently.
                        let msg = format!("{e}");
                        if !msg.contains("cancelled") {
                            review_message(&ui, &trfmt(TrId::ErrorReadPsbt, &[&msg]));
                            ui.global::<Callbacks>().set_review_ready(true);
                        }
                        return;
                    }
                }
            };

            // The PSBT itself identifies its wallet (scriptPubKeys), so we match
            // across every registered policy — no need to pre-select one.
            // Matching reconstructs the exact policy branch/index from the
            // PSBT's derivation maps. Run it on a worker so descriptor and EC
            // validation cannot stall the UI.
            let (policies, fp) = {
                let st = state.lock().unwrap();
                (signable_policies(&st.policies), st.fp)
            };
            {
                let cb = ui.global::<Callbacks>();
                cb.set_psbt_loading(true);
                cb.set_review_ready(true); // navigate to the review (loading) screen
            }
            let weak2 = ui.as_weak();
            let state2 = state.clone();
            spawn_local(async move {
                // Heavy work off the UI thread; returns the psbt back with the match.
                let res = spawn_worker(async move {
                    let m = match_owned(&psbt, &policies, fp);
                    (psbt, m)
                })
                .await;
                let Some(ui) = weak2.upgrade() else { return };
                let (psbt, matched) = res;
                match matched {
                    Ok(Some((reg, m))) => {
                        populate_review(&ui, &reg, &psbt, &m);
                        state2.lock().unwrap().pending = Some(Pending { psbt, policy: reg });
                        set_status(&ui, tr::lookup_id(TrId::StatusLoadedPsbt));
                    }
                    Ok(None) => review_message(&ui, tr::lookup_id(TrId::ReviewNoMatch)),
                    Err(e) => {
                        review_message(&ui, &trfmt(TrId::ErrorMatchFailed, &[&e.to_string()]))
                    }
                }
                ui.global::<Callbacks>().set_psbt_loading(false);
            })
            .detach();
        });
    }

    // -- verify address: answer Liana's policy-bound QR request --------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_verify_address(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let expected_checksum = id.to_string();
            clear_verify(&ui);
            state.lock().unwrap().last_address_response = None;
            let incoming = { state.lock().unwrap().incoming_address.take() };
            let bridge = {
                let st = state.lock().unwrap();
                sim_bridge_file(&st.data_dir, VERIFY_ADDRESS_FILE)
            };
            let scan = if let Some(scan) = incoming {
                Ok(scan)
            } else if let Some(bridge) = bridge {
                read_bytes_path_limited(
                    &bridge,
                    transport::MAX_JSON_BYTES as u64,
                    "address request",
                )
                .map(AddressScan::Request)
            } else {
                read_address_exchange_file()
            };
            let scan = match scan {
                Ok(scan) => scan,
                Err(error) => {
                    if error.to_string().contains("cancelled") {
                        return;
                    }
                    show_verify_error(
                        &ui,
                        &trfmt(TrId::VerifyRequestInvalid, &[&error.to_string()]),
                    );
                    return;
                }
            };
            if let AddressScan::Address(address) = scan {
                let result = {
                    let st = state.lock().unwrap();
                    find_registered_address(
                        st.policies.all(),
                        &expected_checksum,
                        &address,
                        st.seed.as_bytes(),
                        &st.secp,
                        st.fp,
                    )
                };
                match result {
                    Ok((policy, branch, index, address)) => {
                        let cb = ui.global::<Callbacks>();
                        cb.set_verify_ready(true);
                        cb.set_verify_matched(true);
                        cb.set_verify_response_required(false);
                        cb.set_verify_addr(address.into());
                        cb.set_verify_checksum(policy.descriptor_checksum.clone().into());
                        cb.set_verify_title(tr::lookup_id(TrId::VerifySuccessTitle).into());
                        let kind = if branch == 1 {
                            tr::lookup_id(TrId::VerifyChangeKind)
                        } else {
                            tr::lookup_id(TrId::VerifyReceiveKind)
                        };
                        cb.set_verify_detail(
                            trfmt(
                                TrId::VerifySuccessDetail,
                                &[&policy.name, kind, &index.to_string()],
                            )
                            .into(),
                        );
                    }
                    Err(error) => show_verify_error(&ui, &error.to_string()),
                }
                return;
            }
            let AddressScan::Request(request_bytes) = scan else {
                return;
            };
            let request = match transport::AddressVerificationRequest::from_json(&request_bytes) {
                Ok(request) => request,
                Err(error) => {
                    show_verify_error(
                        &ui,
                        &trfmt(TrId::VerifyRequestInvalid, &[&error.to_string()]),
                    );
                    return;
                }
            };
            let result = {
                let mut st = state.lock().unwrap();
                st.policies
                    .all()
                    .iter()
                    .find(|policy| {
                        (expected_checksum.is_empty()
                            || policy.descriptor_checksum == expected_checksum)
                            && policy.policy_id == request.policy_id
                            && policy
                                .descriptor_checksum
                                .eq_ignore_ascii_case(&request.descriptor_checksum)
                            && network_from_policy(policy).and_then(|network| {
                                transport::PolicyNetwork::from_network(network).ok()
                            }) == Some(request.network)
                            && policy_is_signable(policy)
                    })
                    .cloned()
                    .context("wallet policy is not registered")
                    .and_then(|policy| {
                        verify_registered_key(&policy, st.seed.as_bytes(), &st.secp, st.fp)?;
                        let network = network_from_policy(&policy)
                            .context("wallet policy network is unsupported")?;
                        let address = derive_policy_address(
                            &policy.descriptor,
                            request.branch,
                            request.index,
                            network,
                        )?;
                        let response = transport::AddressVerificationResponse::new(
                            &request,
                            address.clone(),
                            st.fp,
                        )
                        .to_json()
                        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                        st.last_address_response = Some(response);
                        Ok((policy.name, address))
                    })
            };
            let cb = ui.global::<Callbacks>();
            cb.set_verify_ready(true);
            match result {
                Ok((name, address)) => {
                    cb.set_verify_addr(address.into());
                    cb.set_verify_matched(true);
                    cb.set_verify_response_required(true);
                    cb.set_verify_has_response(false);
                    cb.set_verify_checksum(request.descriptor_checksum.clone().into());
                    cb.set_verify_title(tr::lookup_id(TrId::VerifySuccessTitle).into());
                    let kind = if request.branch == 1 {
                        tr::lookup_id(TrId::VerifyChangeKind)
                    } else {
                        tr::lookup_id(TrId::VerifyReceiveKind)
                    };
                    cb.set_verify_detail(
                        trfmt(
                            TrId::VerifySuccessDetail,
                            &[&name, kind, &request.index.to_string()],
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    cb.set_verify_matched(false);
                    cb.set_verify_title(tr::lookup_id(TrId::VerifyNotRegisteredTitle).into());
                    cb.set_verify_detail(
                        trfmt(TrId::VerifyNotRegisteredDetail, &[&error.to_string()]).into(),
                    );
                }
            }
        });
    }

    // -- user confirms the independently derived address before response QR -
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_confirm_address(move || {
            let Some(ui) = weak.upgrade() else { return };
            let ready = state.lock().unwrap().last_address_response.is_some();
            ui.global::<Callbacks>().set_verify_has_response(ready);
        });
    }

    // -- approve: sign + finalize the pending PSBT --------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_approve(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Sign while holding the lock; then DROP it before opening the
            // modal picker (the picker blocks and other callbacks need the lock).
            let signed_bytes: Option<Vec<u8>> = {
                let mut st = state.lock().unwrap();
                let Some(pending) = st.pending.take() else {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(&ui, tr::lookup_id(TrId::StatusNothingToSign));
                    return;
                };
                // Security gate (defence-in-depth beyond the UI flag): refuse
                // unless the PSBT matched the policy and Passport owns a key on
                // the active path.
                let current_policy = st
                    .policies
                    .find_by_checksum(&pending.policy.descriptor_checksum)
                    .cloned();
                let Some(current_policy) = current_policy.filter(policy_is_signable) else {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(&ui, tr::lookup_id(TrId::ErrorPolicyNotFound));
                    return;
                };
                if let Err(error) =
                    verify_registered_key(&current_policy, st.seed.as_bytes(), &st.secp, st.fp)
                {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(
                        &ui,
                        &trfmt(TrId::ErrorSigningRefused, &[&error.to_string()]),
                    );
                    return;
                }
                let matched = match lpsbt::match_psbt(&pending.psbt, &current_policy, st.fp) {
                    Ok(matched) => matched,
                    Err(error) => {
                        ui.global::<Callbacks>().set_signing(false);
                        set_status(
                            &ui,
                            &trfmt(TrId::ErrorSigningRefused, &[&error.to_string()]),
                        );
                        return;
                    }
                };
                if let signing::SignDecision::Refuse(reason) =
                    signing::decide(&matched, &current_policy)
                {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(&ui, &trfmt(TrId::ErrorRefused, &[&reason]));
                    return;
                }
                let network = network_from_policy(&current_policy).unwrap_or(DEFAULT_NETWORK);
                let master = match master_for_network(st.seed.as_bytes(), network) {
                    Ok(master) => master,
                    Err(e) => {
                        ui.global::<Callbacks>().set_signing(false);
                        set_status(&ui, &trfmt(TrId::ErrorSigningRefused, &[&format!("{e}")]));
                        return;
                    }
                };
                // Sign only — Liana (the coordinator) combines + finalizes.
                match signing::sign(pending.psbt, &master, &st.secp, matched.expected_signatures) {
                    Ok(signed) => {
                        // Keep an app-data copy (handy for the same-Mac sim test).
                        write_bridge_file(&st.data_dir, SIGNED_PSBT_FILE, &signed.serialize());
                        write_bridge_file(
                            &st.data_dir,
                            "signed-psbt.b64.txt",
                            psbt_base64(&signed).as_bytes(),
                        );
                        // Keep the bytes in memory so "Save to file" works on
                        // device (std::fs read-back doesn't).
                        st.last_signed = Some(signed.serialize());
                        Some(signed.serialize())
                    }
                    Err(e) => {
                        ui.global::<Callbacks>().set_signing(false);
                        set_status(&ui, &trfmt(TrId::ErrorSigningRefused, &[&format!("{e}")]));
                        None
                    }
                }
            };

            if let Some(bytes) = signed_bytes {
                // Clear, in-screen success — no auto file-picker (the user can
                // choose to save to a device location via "Save to file…").
                let cb = ui.global::<Callbacks>();
                cb.set_signing(false);
                cb.set_review_signed(true);
                cb.set_review_saved(false);
                cb.set_review_qr_available(registry_bytes_cbor(&bytes).is_ok());
                cb.set_review_signed_detail(
                    tr::lookup_id(if cb.get_review_qr_available() {
                        TrId::ReviewSignedDetail
                    } else {
                        TrId::ReviewQrUnavailable
                    })
                    .into(),
                );
                set_status(&ui, tr::lookup_id(TrId::StatusPsbtSigned));
            }
        });
    }

    // -- export signed PSBT to a chosen location via the file picker --------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_signed(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Use the in-memory signed bytes (set at sign time), then offer the
            // picker. Avoids a std::fs read-back that doesn't work on device.
            let bytes = { state.lock().unwrap().last_signed.clone() };
            let cb = ui.global::<Callbacks>();
            cb.set_export_ok(false);
            let Some(bytes) = bytes else {
                cb.set_review_signed_detail(tr::lookup_id(TrId::ErrorNoSignedPsbtToExport).into());
                return;
            };
            // Name the file by txid: unique per transaction and identifiable when
            // loaded back into Liana.
            let filename = match parse_psbt_bytes(&bytes) {
                Ok(p) => format!("{}.psbt", p.unsigned_tx.compute_txid()),
                Err(_) => SIGNED_PSBT_FILE.to_string(),
            };
            // Save to a chosen location via the picker. On success route to the
            // shared full-screen success; on failure surface the reason inline.
            match export_exchange_file(&filename, &bytes) {
                Ok(dest) => {
                    cb.set_review_saved(true);
                    cb.set_review_signed_detail("".into());
                    cb.set_export_done_title(
                        tr::lookup_id(TrId::ExportTransactionSignedTitle).into(),
                    );
                    cb.set_export_done_detail(
                        format!(
                            "{}\n{}",
                            format_saved_to(&dest),
                            tr::lookup_id(TrId::ExportTransactionSignedDetail)
                        )
                        .into(),
                    );
                    cb.set_export_ok(true);
                }
                Err(e) => {
                    cb.set_review_saved(false);
                    let msg = format!("{e}");
                    // A user cancel is not an error to surface.
                    cb.set_review_signed_detail(if msg.contains("cancelled") {
                        "".into()
                    } else {
                        trfmt(TrId::ErrorSaveFailed, &[&msg]).into()
                    });
                }
            }
        });
    }

    // -- animated signed-PSBT response -------------------------------------
    {
        let state = state.clone();
        ui.global::<Callbacks>()
            .on_signed_psbt_qr_parts(move |density| {
                let Some(bytes) = state.lock().unwrap().last_signed.clone() else {
                    return Default::default();
                };
                match registry_bytes_cbor(&bytes) {
                    Ok(cbor) => {
                        slint_keyos_platform::qrcode::encode_qr_parts("crypto-psbt", cbor, density)
                    }
                    Err(error) => {
                        log::error!("could not encode signed PSBT QR: {error}");
                        Default::default()
                    }
                }
            });
    }

    // -- animated bound address response -----------------------------------
    {
        let state = state.clone();
        ui.global::<Callbacks>()
            .on_address_response_qr_parts(move |density| {
                let Some(bytes) = state.lock().unwrap().last_address_response.clone() else {
                    return Default::default();
                };
                match registry_bytes_cbor(&bytes) {
                    Ok(cbor) => {
                        slint_keyos_platform::qrcode::encode_qr_parts("bytes", cbor, density)
                    }
                    Err(error) => {
                        log::error!("could not encode address response QR: {error}");
                        Default::default()
                    }
                }
            });
    }

    // -- import policy: pick a descriptor file via the file-browser overlay -
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_import_policy(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Host-bridge for the hosted sim test: if Liana (same Mac) dropped a
            // descriptor in the app-data folder, use it. Otherwise open the
            // device file picker (the real-Prime path). Don't hold the lock
            // across the modal picker.
            let incoming = { state.lock().unwrap().incoming_policy.take() };
            let bridge = {
                let st = state.lock().unwrap();
                sim_bridge_file(&st.data_dir, IMPORT_DESCRIPTOR_FILE)
            };
            {
                let cb = ui.global::<Callbacks>();
                cb.set_import_error("".into());
                cb.set_import_committed(false);
                cb.set_import_path_index(0);
                cb.set_import_signer_index(0);
            }
            let text = if let Some(text) = incoming {
                text
            } else if let Some(bridge) = bridge {
                match read_text_path_limited(&bridge, MAX_DESCRIPTOR_BYTES, "descriptor") {
                    Ok(t) => t,
                    Err(e) => {
                        ui.global::<Callbacks>().set_import_error(
                            trfmt(TrId::ErrorReadFile, &[&format!("{e}")]).into(),
                        );
                        return;
                    }
                }
            } else {
                match import_policy_exchange_file() {
                    Ok(t) => t,
                    Err(e) => {
                        // "cancelled" is a normal user action, not an error to show.
                        let msg = format!("{e}");
                        if !msg.contains("cancelled") {
                            ui.global::<Callbacks>()
                                .set_import_error(trfmt(TrId::ErrorReadFile, &[&msg]).into());
                        }
                        return;
                    }
                }
            };
            // Parse + classify the descriptor, but DON'T commit yet — stage it
            // for the guided review screen. Reject a duplicate up front.
            let parsed = {
                let mut st = state.lock().unwrap();
                match register_policy_payload(
                    text.as_str(),
                    st.seed.as_bytes(),
                    &st.secp,
                    st.fp,
                    st.xpub_network,
                ) {
                    Ok(reg) => {
                        if st
                            .policies
                            .find_by_checksum(&reg.descriptor_checksum)
                            .is_some()
                        {
                            Err(trfmt(
                                TrId::ImportErrorDuplicate,
                                &[&reg.descriptor_checksum],
                            ))
                        } else {
                            st.pending_import = Some(reg.clone());
                            Ok(reg)
                        }
                    }
                    Err(e) => Err(format!("{e}")),
                }
            };
            let cb = ui.global::<Callbacks>();
            match parsed {
                Ok(reg) => {
                    // Fill the detail-* fields so the review screen can explain it.
                    populate_detail(&ui, &reg);
                    // Pre-fill an editable default name for the review screen.
                    cb.set_import_name(reg.name.clone().into());
                    cb.set_import_path_index(0);
                    cb.set_import_signer_index(0);
                    cb.set_import_error("".into());
                    cb.set_import_parsed(true);
                }
                Err(e) => {
                    cb.set_import_parsed(false);
                    cb.set_import_error(trfmt(TrId::ImportErrorReadDescriptor, &[&e]).into());
                }
            }
        });
    }

    // -- confirm import: commit the staged policy ---------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_confirm_import(move || {
            let Some(ui) = weak.upgrade() else { return };
            // Apply the user-chosen name (fall back to the default if blank).
            let chosen = ui
                .global::<Callbacks>()
                .get_import_name()
                .trim()
                .to_string();
            let chosen = match validate_policy_name(&chosen) {
                Ok(name) => name,
                Err(error) => {
                    ui.global::<Callbacks>()
                        .set_import_error(error.to_string().into());
                    return;
                }
            };
            let result = {
                let mut st = state.lock().unwrap();
                match st.pending_import.take() {
                    Some(mut reg) => {
                        reg.name = chosen;
                        match save_policy(&st.data_dir, &reg) {
                            Ok(()) => st
                                .policies
                                .add(reg.clone())
                                .map(|_| reg)
                                .map_err(|e| anyhow::anyhow!("{e}")),
                            Err(e) => {
                                st.pending_import = Some(reg);
                                Err(e)
                            }
                        }
                    }
                    None => Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorNothingToImport))),
                }
            };
            let cb = ui.global::<Callbacks>();
            cb.set_import_committed(false);
            match result {
                Ok(reg) => {
                    populate_detail(&ui, &reg);
                    cb.set_import_parsed(false);
                    cb.set_import_error("".into());
                    cb.set_import_committed(true);
                    cb.set_import_path_index(0);
                    cb.set_import_signer_index(0);
                    refresh_home(&ui, &state);
                    set_status(&ui, tr::lookup_id(TrId::StatusPolicyAdded));
                }
                Err(e) => {
                    cb.set_import_error(format!("{e}").into());
                    set_status(&ui, &format!("{e}"));
                }
            }
        });
    }

    // -- cancel import: discard the staged policy ---------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_cancel_import(move || {
            let Some(ui) = weak.upgrade() else { return };
            state.lock().unwrap().pending_import = None;
            let cb = ui.global::<Callbacks>();
            cb.set_import_parsed(false);
            cb.set_import_committed(false);
            cb.set_import_path_index(0);
            cb.set_import_signer_index(0);
        });
    }

    // -- local labels for external signer keys -----------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_set_pending_signer_name(move |id, name| {
                let Some(ui) = weak.upgrade() else { return };
                let name = match validate_signer_name(name.as_str()) {
                    Ok(name) => name,
                    Err(error) => {
                        ui.global::<Callbacks>()
                            .set_import_error(error.to_string().into());
                        return;
                    }
                };
                let updated = {
                    let mut st = state.lock().unwrap();
                    st.pending_import.as_mut().and_then(|policy| {
                        let signer = policy.signers.iter_mut().find(|signer| {
                            signer.xpub == id.as_str() && !signer.owned_by_passport
                        })?;
                        signer.name = name;
                        Some(policy.clone())
                    })
                };
                if let Some(policy) = updated {
                    ui.global::<Callbacks>().set_import_error("".into());
                    populate_detail(&ui, &policy);
                }
            });
    }

    // -- rename policy ------------------------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_rename_policy(move |id, name| {
            let Some(ui) = weak.upgrade() else { return };
            let name = match validate_policy_name(name.as_str()) {
                Ok(name) => name,
                Err(error) => {
                    set_status(&ui, &error.to_string());
                    return;
                }
            };
            {
                let result = {
                    let mut st = state.lock().unwrap();
                    let dir = st.data_dir.clone();
                    match st.policies.set_name(id.as_str(), &name) {
                        Some(updated) => save_policy(&dir, &updated).map(|_| updated),
                        None => Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorPolicyNotFound))),
                    }
                };
                // Refresh the open detail view so the new name shows immediately.
                match result {
                    Ok(updated) => populate_detail(&ui, &updated),
                    Err(e) => set_status(&ui, &format!("{e}")),
                }
            }
            refresh_home(&ui, &state);
        });
    }
    // -- rename an external signer label -----------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>()
            .on_rename_signer(move |policy_id, signer_id, name| {
                let Some(ui) = weak.upgrade() else { return };
                let name = match validate_signer_name(name.as_str()) {
                    Ok(name) => name,
                    Err(error) => {
                        set_status(&ui, &error.to_string());
                        return;
                    }
                };
                let result = {
                    let mut st = state.lock().unwrap();
                    let dir = st.data_dir.clone();
                    match st
                        .policies
                        .set_signer_name(policy_id.as_str(), signer_id.as_str(), &name)
                    {
                        Some(updated) => save_policy(&dir, &updated).map(|_| updated),
                        None => Err(anyhow::anyhow!("External signer was not found.")),
                    }
                };
                match result {
                    Ok(updated) => {
                        populate_detail(&ui, &updated);
                        set_status(&ui, tr::lookup_id(TrId::StatusSignerNameSaved));
                    }
                    Err(error) => set_status(&ui, &error.to_string()),
                }
            });
    }
    // -- delete policy: store + disk ----------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_delete_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let removed = {
                let mut st = state.lock().unwrap();
                let dir = st.data_dir.clone();
                let ok = st.policies.remove(id.as_str());
                if ok {
                    if let Err(e) = delete_policy_file(&dir, id.as_str()) {
                        log::warn!("failed to delete policy backing file #{id}: {e}");
                    }
                    true
                } else {
                    false
                }
            };
            refresh_home(&ui, &state);
            if removed {
                set_status(&ui, &trfmt(TrId::StatusDeletedPolicy, &[id.as_str()]));
            } else {
                set_status(&ui, tr::lookup_id(TrId::ErrorPolicyNotFound));
            }
        });
    }

    // -- export descriptor (advanced): save the miniscript to a file --------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_descriptor(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            ui.global::<Callbacks>().set_export_ok(false);
            // Build descriptor + bridge path, then drop the lock before the modal.
            let (descriptor, bridge, filename) = {
                let st = state.lock().unwrap();
                match st.policies.find_by_checksum(id.as_str()) {
                    Some(reg) => {
                        let filename = format!("liana-descriptor-{id}.txt");
                        (
                            reg.descriptor.clone(),
                            st.data_dir.join(&filename),
                            filename,
                        )
                    }
                    None => {
                        set_status(&ui, tr::lookup_id(TrId::ErrorPolicyNotFound));
                        return;
                    }
                }
            };
            // Always write to the app-data bridge (hosted sim / dev).
            write_bridge_path(&bridge, descriptor.as_bytes());
            // On device, save to a chosen location via the picker.
            let cb = ui.global::<Callbacks>();
            cb.set_export_ok(false);
            match export_exchange_file(&filename, descriptor.as_bytes()) {
                Ok(dest) => {
                    cb.set_export_error("".into());
                    cb.set_export_done_title(
                        tr::lookup_id(TrId::ExportDescriptorSavedTitle).into(),
                    );
                    cb.set_export_done_detail(
                        format!(
                            "{}\n{}",
                            format_saved_to(&dest),
                            tr::lookup_id(TrId::ExportDescriptorSavedDetail)
                        )
                        .into(),
                    );
                    cb.set_export_ok(true);
                }
                Err(e) => {
                    let msg = format!("{e}");
                    cb.set_export_error(if msg.contains("cancelled") {
                        "".into()
                    } else {
                        msg.into()
                    });
                }
            }
        });
    }

    // -- canonical wallet-policy backup QR ---------------------------------
    {
        let state = state.clone();
        ui.global::<Callbacks>()
            .on_policy_qr_parts(move |id, density| {
                let bytes = {
                    let st = state.lock().unwrap();
                    st.policies
                        .find_by_checksum(id.as_str())
                        .and_then(|policy| {
                            transport::PolicyRegistration::from_registered(policy).ok()
                        })
                        .and_then(|registration| transport::encode_json(&registration).ok())
                };
                let Some(bytes) = bytes else {
                    return Default::default();
                };
                match registry_bytes_cbor(&bytes) {
                    Ok(cbor) => slint_keyos_platform::qrcode::encode_qr_parts(
                        "bytes",
                        cbor,
                        density.max(100),
                    ),
                    Err(error) => {
                        log::error!("could not encode wallet-policy backup QR: {error}");
                        Default::default()
                    }
                }
            });
    }

    // -- canonical wallet-policy backup file -------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_export_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let result = {
                let st = state.lock().unwrap();
                let policy = st
                    .policies
                    .find_by_checksum(id.as_str())
                    .context("wallet policy was not found");
                policy.and_then(|policy| {
                    let registration = transport::PolicyRegistration::from_registered(policy)
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    let bytes = transport::encode_json(&registration)
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    Ok((
                        format!("{}-policy.json", safe_filename(&policy.name)),
                        bytes,
                    ))
                })
            };
            let cb = ui.global::<Callbacks>();
            cb.set_export_ok(false);
            match result.and_then(|(filename, bytes)| export_exchange_file(&filename, &bytes)) {
                Ok(dest) => {
                    cb.set_export_error("".into());
                    cb.set_export_done_title(tr::lookup_id(TrId::ExportPolicySavedTitle).into());
                    cb.set_export_done_detail(
                        format!(
                            "{}\n{}",
                            format_saved_to(&dest),
                            tr::lookup_id(TrId::ExportPolicySavedDetail)
                        )
                        .into(),
                    );
                    cb.set_export_ok(true);
                }
                Err(error) => {
                    let message = error.to_string();
                    cb.set_export_error(if message.contains("cancelled") {
                        "".into()
                    } else {
                        message.into()
                    });
                }
            }
        });
    }

    // Universal-QR handoff from the KeyOS launcher. Public SDK applications
    // cannot open the privileged scanner directly; matching scans arrive here
    // after the launcher focuses this app.
    cx.set_input_handler({
        let gui = cx.gui.clone();
        let weak = ui.as_weak();
        let state = state.clone();
        move |input| {
            if input.msg != InputMessage::NavigationFocused {
                return;
            }
            let Some(ui) = weak.upgrade() else { return };
            let Ok(Some(bytes)) = gui.navigate_pending() else {
                log::warn!("launcher focused Liana without a pending QR handoff");
                return;
            };
            let Some(result) = MatchedQrResult::from_slice(&bytes) else {
                set_status(&ui, "Could not read the launcher QR handoff.");
                return;
            };
            match launcher_input(result) {
                Ok(LauncherInput::Psbt(psbt)) => {
                    state.lock().unwrap().incoming_psbt = Some(psbt);
                    ui.global::<Callbacks>().invoke_sign_psbt("".into());
                    ui.global::<Navigate>().invoke_review_page(NavigateOptions {
                        replace: false,
                        animate: Animate::None,
                    });
                }
                Ok(LauncherInput::Policy(policy)) => {
                    state.lock().unwrap().incoming_policy = Some(policy);
                    ui.global::<Callbacks>().invoke_import_policy();
                    if state.lock().unwrap().pending_import.is_some() {
                        ui.global::<Navigate>()
                            .invoke_import_review_page(NavigateOptions {
                                replace: false,
                                animate: Animate::None,
                            });
                    }
                }
                Ok(LauncherInput::Address(request)) => {
                    let checksum = transport::AddressVerificationRequest::from_json(&request)
                        .map(|request| request.descriptor_checksum)
                        .unwrap_or_default();
                    state.lock().unwrap().incoming_address = Some(AddressScan::Request(request));
                    ui.global::<Callbacks>()
                        .invoke_verify_address(checksum.into());
                    ui.global::<Navigate>().invoke_verify_page(NavigateOptions {
                        replace: false,
                        animate: Animate::None,
                    });
                }
                Err(error) => set_status(&ui, &error.to_string()),
            }
        }
    });

    ui.run().expect("UI running");
}

// ---------------------------------------------------------------------------
// UI population
// ---------------------------------------------------------------------------

fn policy_row(p: &RegisteredPolicy) -> PolicyRow {
    let network = network_from_policy(p)
        .map(network_display)
        .unwrap_or(p.network.as_str());
    PolicyRow {
        id: p.descriptor_checksum.clone().into(),
        name: p.name.clone().into(),
        checksum: format!("#{}", p.descriptor_checksum).into(),
        network: network.into(),
        summary: policy_summary(p).into(),
    }
}

fn refresh_home(ui: &AppWindow, state: &Arc<Mutex<AppState>>) {
    let st = state.lock().unwrap();
    let policies: Vec<PolicyRow> = st.policies.all().iter().map(policy_row).collect();
    let cb = ui.global::<Callbacks>();
    cb.set_policy_count(policies.len() as i32);
    cb.set_policies(ModelRc::new(VecModel::from(policies)));
}

fn populate_detail(ui: &AppWindow, reg: &RegisteredPolicy) {
    let cb = ui.global::<Callbacks>();
    cb.set_detail_id(reg.descriptor_checksum.clone().into());
    cb.set_detail_name(reg.name.clone().into());
    // Keep the rename field in sync with the selected policy's current name.
    cb.set_rename_value(reg.name.clone().into());
    cb.set_detail_checksum(format!("#{}", reg.descriptor_checksum).into());
    cb.set_detail_network(
        network_from_policy(reg)
            .map(network_display)
            .unwrap_or(reg.network.as_str())
            .into(),
    );
    cb.set_detail_descriptor(reg.descriptor.clone().into());

    // Number recovery tiers when there is more than one (a decaying policy), so
    // "Recovery path 1 / 2 / 3" disambiguate the cards; a lone recovery stays
    // just "Recovery path".
    let recovery_total = reg
        .paths
        .iter()
        .filter(|p| matches!(p.kind, SpendPathKind::Recovery))
        .count();
    let mut recovery_seen = 0usize;
    let mut paths: Vec<PathRow> = Vec::with_capacity(reg.paths.len());
    for p in &reg.paths {
        let is_recovery = matches!(p.kind, SpendPathKind::Recovery);
        // Does Passport own a key on this path?
        let owned = p.signer_fingerprints.iter().any(|fp| {
            reg.signers
                .iter()
                .any(|s| &s.fingerprint == fp && s.owned_by_passport)
        });
        // Natural phrasing, avoiding "1 key(s)". Singular keys get "the key";
        // all-of-N gets "all N keys"; thresholds get "M of N keys".
        let who = if p.total_keys == 1 {
            tr::lookup_id(TrId::PathTheKey).to_string()
        } else if p.threshold == p.total_keys {
            trfmt(TrId::PathAllKeys, &[&p.total_keys.to_string()])
        } else {
            trfmt(
                TrId::PathThresholdKeys,
                &[&p.threshold.to_string(), &p.total_keys.to_string()],
            )
        };
        let (headline, detail) = if is_recovery {
            let n = p.relative_timelock_blocks.unwrap_or(0);
            let months = n / 4380;
            let blocks = commas(n);
            let months = months.to_string();
            let sig = if owned {
                tr::lookup_id(TrId::PathThisPassportHoldsOne).to_string()
            } else {
                String::new()
            };
            (
                trfmt(TrId::PathAfterMonths, &[&months]),
                trfmt(TrId::PathRecoveryDetail, &[&blocks, &months, &who, &sig]),
            )
        } else {
            let detail = if owned && p.total_keys == 1 {
                tr::lookup_id(TrId::PathPrimaryDetailOwned).to_string()
            } else if owned {
                trfmt(TrId::PathPrimaryDetailOwnedThreshold, &[&who])
            } else {
                trfmt(TrId::PathPrimaryDetailExternal, &[&who])
            };
            (tr::lookup_id(TrId::PathSpendAnytime).to_string(), detail)
        };
        let kind_label = if is_recovery {
            recovery_seen += 1;
            if recovery_total > 1 {
                trfmt(TrId::PathRecoveryNumbered, &[&recovery_seen.to_string()])
            } else {
                tr::lookup_id(TrId::PathRecovery).to_string()
            }
        } else {
            tr::lookup_id(TrId::PathPrimary).to_string()
        };
        paths.push(PathRow {
            kind_label: kind_label.into(),
            is_recovery,
            headline: headline.into(),
            detail: detail.into(),
        });
    }
    cb.set_detail_paths(ModelRc::new(VecModel::from(paths)));

    let signers: Vec<SignerRow> = reg
        .signers
        .iter()
        .map(|s| SignerRow {
            id: s.xpub.clone().into(),
            name: s.name.clone().into(),
            fingerprint: s.fingerprint.clone().into(),
            owned: s.owned_by_passport,
            detail: if s.owned_by_passport {
                tr::lookup_id(TrId::PathThisPassport).into()
            } else {
                tr::lookup_id(TrId::PathExternalKey).into()
            },
        })
        .collect();
    cb.set_detail_signers(ModelRc::new(VecModel::from(signers)));
}

fn populate_review(ui: &AppWindow, reg: &RegisteredPolicy, psbt: &Psbt, m: &lpsbt::MatchResult) {
    let cb = ui.global::<Callbacks>();
    let is_recovery = matches!(m.active_path, Some(SpendPathKind::Recovery));
    let network = network_from_policy(reg).unwrap_or(DEFAULT_NETWORK);
    cb.set_review_matched(m.matched);
    cb.set_review_can_sign(m.passport_can_sign);
    cb.set_review_is_recovery(is_recovery);
    cb.set_review_wallet_name(reg.name.clone().into());
    // Fresh review: clear any prior success state.
    cb.set_signing(false);
    cb.set_review_signed(false);
    cb.set_review_saved(false);
    cb.set_review_qr_available(false);
    cb.set_review_signed_detail("".into());

    let path_label = match m.active_path {
        Some(SpendPathKind::Primary) => tr::lookup_id(TrId::ReviewPathPrimary).to_string(),
        Some(SpendPathKind::Recovery) => trfmt(
            TrId::ReviewPathRecovery,
            &[&m.active_timelock_blocks.unwrap_or(0).to_string()],
        ),
        None => tr::lookup_id(TrId::ReviewPathUnknown).to_string(),
    };
    cb.set_review_path_label(path_label.into());

    // Outputs + fee. Build one row per output, flagging the ones that pay back
    // into this wallet (change) vs the ones actually leaving (destinations), so
    // the UI can separate them visually and we can total what's truly sent.
    let out_sum: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let in_sum: u64 = psbt
        .inputs
        .iter()
        .filter_map(|i| i.witness_utxo.as_ref().map(|u| u.value.to_sat()))
        .sum();

    let mut rows: Vec<OutputRow> = Vec::new();
    let mut leaving: u64 = 0;
    for (index, o) in psbt.unsigned_tx.output.iter().enumerate() {
        let sats = o.value.to_sat();
        let (address, is_change) = match Address::from_script(&o.script_pubkey, network) {
            Ok(addr) => (addr.to_string(), m.change_outputs.contains(&index)),
            Err(_) if o.script_pubkey.is_op_return() => (
                format!(
                    "{} {}",
                    tr::lookup_id(TrId::ReviewOpReturn),
                    hex::encode(o.script_pubkey.as_bytes().get(1..).unwrap_or_default())
                ),
                false,
            ),
            Err(_) => (
                format!(
                    "{} {}",
                    tr::lookup_id(TrId::ReviewNonStandardScript),
                    hex::encode(o.script_pubkey.as_bytes())
                ),
                false,
            ),
        };
        if !is_change {
            leaving += sats;
        }
        rows.push(OutputRow {
            address: address.into(),
            amount: format!("{} sats", commas(sats)).into(),
            is_change,
        });
    }
    // Destinations first, change last (de-emphasized at the bottom).
    rows.sort_by_key(|r| r.is_change);
    cb.set_review_output_rows(ModelRc::new(VecModel::from(rows)));

    let fee = in_sum.saturating_sub(out_sum);
    cb.set_review_fee(format!("{} sats", commas(fee)).into());
    // What actually leaves the wallet's control = amount sent + miner fee.
    // Change returns to the wallet, so it is excluded.
    let total_leaving = leaving.saturating_add(fee);
    cb.set_review_total_out(format!("{} sats", commas(total_leaving)).into());

    let mut warnings = Vec::new();
    if is_recovery {
        warnings.push(tr::lookup_id(TrId::ReviewRecoveryWarning).to_string());
    }
    if total_leaving > 0 && fee > 0 {
        let fee_percent = ((fee as u128) * 100 / (total_leaving as u128)) as u64;
        if fee_percent >= HIGH_FEE_WARNING_PERCENT {
            warnings.push(trfmt(
                TrId::ReviewHighFeeWarning,
                &[&fee_percent.to_string()],
            ));
        }
    }
    cb.set_review_warning(warnings.join("\n").into());

    let status = if !m.matched {
        tr::lookup_id(TrId::ReviewNotPolicy).to_string()
    } else if !m.passport_can_sign {
        let reason = match signing::decide(m, reg) {
            signing::SignDecision::Refuse(reason) => reason,
            signing::SignDecision::Allow { .. } => {
                tr::lookup_id(TrId::ReviewNoKeyOnPath).to_string()
            }
        };
        trfmt(TrId::ReviewBlockedReason, &[&reason])
    } else {
        String::new()
    };
    cb.set_review_status(status.into());
}

/// Put the review screen into a clean refusal/empty state with a message (used
/// when there is no PSBT to load or it matches no policy).
fn review_message(ui: &AppWindow, msg: &str) {
    let cb = ui.global::<Callbacks>();
    cb.set_review_ready(false);
    cb.set_signing(false);
    cb.set_review_signed(false);
    cb.set_review_saved(false);
    cb.set_review_qr_available(false);
    cb.set_review_signed_detail("".into());
    cb.set_review_matched(false);
    cb.set_review_can_sign(false);
    cb.set_review_is_recovery(false);
    cb.set_review_wallet_name("".into());
    cb.set_review_path_label("".into());
    cb.set_review_output_rows(ModelRc::new(VecModel::from(Vec::<OutputRow>::new())));
    cb.set_review_total_out("".into());
    cb.set_review_fee("".into());
    cb.set_review_warning("".into());
    cb.set_review_status(msg.into());
}

fn clear_verify(ui: &AppWindow) {
    let cb = ui.global::<Callbacks>();
    cb.set_verify_ready(false);
    cb.set_verify_matched(false);
    cb.set_verify_has_response(false);
    cb.set_verify_title("".into());
    cb.set_verify_addr("".into());
    cb.set_verify_detail("".into());
    cb.set_verify_checksum("".into());
    cb.set_verify_response_required(false);
}

fn show_verify_error(ui: &AppWindow, error: &str) {
    let cb = ui.global::<Callbacks>();
    cb.set_verify_ready(true);
    cb.set_verify_matched(false);
    cb.set_verify_response_required(false);
    cb.set_verify_title(tr::lookup_id(TrId::VerifyNotRegisteredTitle).into());
    cb.set_verify_detail(trfmt(TrId::VerifyNotRegisteredDetail, &[error]).into());
}

fn set_status(ui: &AppWindow, msg: &str) {
    ui.global::<Callbacks>().set_status(msg.to_string().into());
}

fn trfmt(id: TrId, args: &[&str]) -> String {
    let mut text = tr::lookup_id(id).to_string();
    for (idx, arg) in args.iter().enumerate() {
        text = text.replace(&format!("{{{idx}}}"), arg);
    }
    text
}

fn format_saved_to(dest: &str) -> String {
    format!("{} {dest}", tr::lookup_id(TrId::ExportSavedTo))
}

fn safe_filename(name: &str) -> String {
    let safe = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "liana".into()
    } else {
        safe
    }
}

fn validate_policy_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > transport::MAX_NAME_BYTES
        || !name.is_ascii()
        || name.bytes().any(|byte| !(32..=126).contains(&byte))
    {
        anyhow::bail!("Wallet policy name must be 1 to 20 printable ASCII characters.");
    }
    Ok(name.to_owned())
}

fn validate_signer_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    if name.is_empty()
        || name.len() > transport::MAX_NAME_BYTES
        || !name.is_ascii()
        || name.bytes().any(|byte| !(32..=126).contains(&byte))
    {
        anyhow::bail!("Signer name must be 1 to 20 printable ASCII characters.");
    }
    Ok(name.to_owned())
}

// ---------------------------------------------------------------------------
// Policy building / persistence
// ---------------------------------------------------------------------------

/// Owned-result PSBT match, for running on a worker thread (no borrows escape).
fn match_owned(
    psbt: &Psbt,
    policies: &[RegisteredPolicy],
    fp: Fingerprint,
) -> std::result::Result<Option<(RegisteredPolicy, lpsbt::MatchResult)>, String> {
    match lpsbt::match_against_all(psbt, policies, fp) {
        Ok(Some((p, m))) => Ok(Some((p.clone(), m))),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("{e}")),
    }
}

fn master_for_network(seed: &[u8], network: Network) -> anyhow::Result<Xpriv> {
    Xpriv::new_master(network, seed).map_err(|e| anyhow::anyhow!("master xpriv: {e}"))
}

fn account_path(network: Network, account: u32) -> anyhow::Result<DerivationPath> {
    let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
    if account >= (1 << 31) {
        anyhow::bail!("Account is outside the BIP32 range.");
    }
    DerivationPath::from_str(&format!("m/48'/{coin_type}'/{account}'/2'"))
        .map_err(|e| anyhow::anyhow!("invalid account path: {e}"))
}

fn account_xpub(
    seed: &[u8],
    secp: &Secp256k1<All>,
    network: Network,
    account: u32,
) -> anyhow::Result<Xpub> {
    let master = master_for_network(seed, network)?;
    let acct = account_path(network, account)?;
    Ok(Xpub::from_priv(secp, &master.derive_priv(secp, &acct)?))
}

fn key_with_origin(
    seed: &[u8],
    secp: &Secp256k1<All>,
    fp: Fingerprint,
    network: Network,
    account: u32,
) -> anyhow::Result<String> {
    let path = account_path(network, account)?;
    let xpub = account_xpub(seed, secp, network, account)?;
    Ok(format!(
        "[{}/{}]{}",
        fp,
        path.to_string().trim_start_matches("m/"),
        xpub
    ))
}

fn set_xpub_export(ui: &AppWindow, state: &Arc<Mutex<AppState>>, network: Network) {
    let result = {
        let mut st = state.lock().unwrap();
        st.xpub_network = network;
        if let Err(error) = save_network_preference(&st.data_dir, network) {
            log::warn!("could not save Liana network preference: {error}");
        }
        key_with_origin(st.seed.as_bytes(), &st.secp, st.fp, network, LIANA_ACCOUNT).and_then(
            |key| {
                let path = account_path(network, LIANA_ACCOUNT)?.to_string();
                let fp = st.fp.to_string();
                write_bridge_file(&st.data_dir, EXPORT_KEY_FILE, key.as_bytes());
                Ok((key, path, fp))
            },
        )
    };
    let cb = ui.global::<Callbacks>();
    cb.set_export_ok(false);
    cb.set_export_error("".into());
    cb.set_xpub_network(network_label(network).into());
    match result {
        Ok((key, path, fp)) => {
            cb.set_xpub_fingerprint(fp.into());
            cb.set_xpub_path(path.into());
            cb.set_xpub_value(key.into());
        }
        Err(e) => {
            cb.set_xpub_value("".into());
            cb.set_export_error(format!("{e}").into());
        }
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "bitcoin",
        Network::Signet => "signet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
    }
}

fn network_display(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "Bitcoin",
        Network::Signet => "Signet",
        Network::Testnet => "Testnet",
        Network::Testnet4 => "Testnet4",
        Network::Regtest => "Regtest",
    }
}

fn is_public_network(network: Network) -> bool {
    matches!(
        network,
        Network::Bitcoin | Network::Signet | Network::Testnet
    )
}

fn network_from_label(label: &str) -> Option<Network> {
    match label {
        "bitcoin" | "mainnet" | "Bitcoin" | "Mainnet" => Some(Network::Bitcoin),
        "signet" | "Signet" => Some(Network::Signet),
        "testnet" | "Testnet" => Some(Network::Testnet),
        "testnet4" | "Testnet4" => Some(Network::Testnet4),
        "regtest" | "Regtest" => Some(Network::Regtest),
        _ => None,
    }
}

fn network_from_policy(policy: &RegisteredPolicy) -> Option<Network> {
    network_from_label(policy.network.as_str())
}

#[cfg(test)]
fn network_from_descriptor(descriptor: &str) -> anyhow::Result<Network> {
    network_from_descriptor_with_hint(descriptor, Network::Signet)
}

fn network_from_descriptor_with_hint(
    descriptor: &str,
    selected_test_network: Network,
) -> anyhow::Result<Network> {
    let has_mainnet_key = ["xpub", "ypub", "zpub"]
        .iter()
        .any(|prefix| descriptor.contains(prefix));
    let has_testnet_key = ["tpub", "upub", "vpub"]
        .iter()
        .any(|prefix| descriptor.contains(prefix));

    match (has_mainnet_key, has_testnet_key) {
        (true, false) => Ok(Network::Bitcoin),
        (false, true) => {
            // Extended keys encode only mainnet vs test-family. Use the network
            // selected while connecting to Liana to distinguish Signet from
            // Testnet, matching Passport Core's active-network behavior.
            Ok(match selected_test_network {
                Network::Signet | Network::Testnet => selected_test_network,
                _ => Network::Signet,
            })
        }
        (true, true) => anyhow::bail!("Wallet policy mixes mainnet and testnet extended keys."),
        (false, false) => {
            anyhow::bail!("Unable to determine the wallet-policy network from its extended keys.")
        }
    }
}

fn register_policy_payload(
    text: &str,
    seed: &[u8],
    secp: &Secp256k1<All>,
    passport_fp: Fingerprint,
    selected_test_network: Network,
) -> anyhow::Result<RegisteredPolicy> {
    if text.trim_start().starts_with('{') {
        let registration = transport::PolicyRegistration::from_json(text.as_bytes())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let canonical = registration
            .canonical_descriptor()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let network = registration.network.bitcoin(selected_test_network);
        let mut registered =
            register_descriptor_for_network(&canonical, seed, secp, passport_fp, network)?;
        registered.name = registration.name.clone();
        registration.apply_to(&mut registered);
        return Ok(registered);
    }
    let network = network_from_descriptor_with_hint(text, selected_test_network)?;
    register_descriptor_for_network(text, seed, secp, passport_fp, network)
}

#[cfg(test)]
fn register_descriptor(
    text: &str,
    seed: &[u8],
    secp: &Secp256k1<All>,
    passport_fp: Fingerprint,
) -> anyhow::Result<RegisteredPolicy> {
    let network = network_from_descriptor(text)?;
    register_descriptor_for_network(text, seed, secp, passport_fp, network)
}

fn register_descriptor_for_network(
    text: &str,
    seed: &[u8],
    secp: &Secp256k1<All>,
    passport_fp: Fingerprint,
    network: Network,
) -> anyhow::Result<RegisteredPolicy> {
    let parsed = descriptor::import(text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let id = parsed.checksum.clone();
    let inferred = network_from_descriptor_with_hint(&parsed.canonical, network)?;
    if transport::PolicyNetwork::from_network(inferred)?
        != transport::PolicyNetwork::from_network(network)?
    {
        anyhow::bail!("Wallet-policy network does not match its extended keys.");
    }
    let mut reg = policy::build_registered_policy(
        id,
        "Imported policy",
        network_label(network),
        &parsed,
        passport_fp,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !reg.signers.iter().any(|s| s.owned_by_passport) {
        anyhow::bail!("{}", tr::lookup_id(TrId::ImportErrorNoPassportKey));
    }
    verify_registered_key(&reg, seed, secp, passport_fp)?;
    let passport_fingerprint = passport_fp.to_string();
    if reg.paths.iter().any(|path| {
        path.signer_fingerprints
            .iter()
            .filter(|fingerprint| fingerprint.as_str() == passport_fingerprint.as_str())
            .count()
            > 1
    }) {
        anyhow::bail!("A spending path cannot require more than one signature from this Passport.");
    }
    let registration =
        transport::PolicyRegistration::from_descriptor(&reg.name, network, &reg.descriptor)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    registration.apply_to(&mut reg);
    Ok(reg)
}

fn verify_registered_key(
    policy: &RegisteredPolicy,
    seed: &[u8],
    secp: &Secp256k1<All>,
    passport_fp: Fingerprint,
) -> anyhow::Result<()> {
    let network = network_from_policy(policy).context("unsupported registered policy network")?;
    let master = master_for_network(seed, network)?;
    let parsed =
        descriptor::import(&policy.descriptor).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut owned_keys = std::collections::HashSet::new();
    let mut mismatch = None;
    parsed.descriptor.for_each_key(|key| {
        let (origin, xkey) = match key {
            liana::miniscript::DescriptorPublicKey::XPub(public) => (&public.origin, &public.xkey),
            liana::miniscript::DescriptorPublicKey::MultiXPub(public) => {
                (&public.origin, &public.xkey)
            }
            liana::miniscript::DescriptorPublicKey::Single(_) => return true,
        };
        let Some((fingerprint, path)) = origin else {
            return true;
        };
        if *fingerprint != passport_fp {
            return true;
        }
        match master.derive_priv(secp, path) {
            Ok(private) if Xpub::from_priv(secp, &private) == *xkey => {
                owned_keys.insert(xkey.to_string());
            }
            Ok(_) => {
                mismatch =
                    Some("fingerprint matches but the complete Passport xpub does not".to_owned())
            }
            Err(error) => {
                mismatch = Some(format!("could not derive registered Passport key: {error}"))
            }
        }
        true
    });
    if let Some(reason) = mismatch {
        anyhow::bail!(reason);
    }
    if owned_keys.len() != 1 {
        anyhow::bail!(
            "Wallet policy must contain exactly one extended key belonging to this Passport."
        );
    }
    Ok(())
}

// Test-only fixtures (no longer seeded into the app — placeholder policy removed).
#[cfg(test)]
fn seed_sample(
    secp: &Secp256k1<All>,
    device_account_xpub: &Xpub,
    device_fp: Fingerprint,
) -> anyhow::Result<RegisteredPolicy> {
    let desc = sample_descriptor(secp, device_account_xpub, device_fp);
    let parsed = descriptor::import(&desc).map_err(|e| anyhow::anyhow!("{e}"))?;
    let reg = policy::build_registered_policy(
        parsed.checksum.clone(),
        "Inheritance (demo)",
        "signet",
        &parsed,
        device_fp,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(reg)
}

#[cfg(test)]
fn descriptor_with_checksum(raw: &str) -> String {
    liana::miniscript::Descriptor::<liana::miniscript::DescriptorPublicKey>::from_str(raw)
        .expect("test descriptor parses")
        .to_string()
}

#[cfg(test)]
fn sample_descriptor(
    secp: &Secp256k1<All>,
    device_account_xpub: &Xpub,
    device_fp: Fingerprint,
) -> String {
    let rec_master = Xpriv::new_master(Network::Signet, &[0x22; 32]).unwrap();
    let rec_fp = rec_master.fingerprint(secp);
    let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
    let rec_xpub = Xpub::from_priv(secp, &rec_master.derive_priv(secp, &acct).unwrap());
    let p = TEST_ACCOUNT_PATH.trim_start_matches("m/");
    descriptor_with_checksum(&format!(
        "wsh(or_d(pk([{device_fp}/{p}]{device_account_xpub}/<0;1>/*),and_v(v:pkh([{rec_fp}/{p}]{rec_xpub}/<0;1>/*),older({RECOVERY_BLOCKS}))))"
    ))
}

/// Build a demo owner-path PSBT spending the policy's index-0 output (test only).
#[cfg(test)]
fn build_owner_psbt(
    _secp: &Secp256k1<All>,
    reg: &RegisteredPolicy,
    _device_account_xpub: &Xpub,
    _device_fp: Fingerprint,
) -> anyhow::Result<Psbt> {
    use liana::miniscript::psbt::PsbtInputExt;

    let parsed = descriptor::import(&reg.descriptor).map_err(|e| anyhow::anyhow!("{e}"))?;
    let singles = parsed
        .descriptor
        .into_single_descriptors()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let def = singles[0]
        .at_derivation_index(0)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let spk = def.script_pubkey();

    let value = Amount::from_sat(100_000);
    let prevout = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap(),
        vout: 0,
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: ScriptBuf::from_hex("0014000000000000000000000000000000000000dead")
                .unwrap(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut input = Input {
        witness_utxo: Some(TxOut {
            value,
            script_pubkey: spk,
        }),
        ..Default::default()
    };
    input
        .update_with_descriptor_unchecked(&def)
        .map_err(|e| anyhow::anyhow!("populate PSBT input: {e}"))?;
    psbt.inputs[0] = input;
    Ok(psbt)
}

fn policy_summary(p: &RegisteredPolicy) -> String {
    let network = network_from_policy(p)
        .map(network_display)
        .unwrap_or(p.network.as_str());
    let recovery = p
        .paths
        .iter()
        .find(|x| matches!(x.kind, SpendPathKind::Recovery))
        .and_then(|x| x.relative_timelock_blocks);
    match recovery {
        Some(n) => trfmt(
            TrId::SummaryRecoveryAfterMonths,
            &[network, &(n / 4380).to_string()],
        ),
        None => trfmt(TrId::SummarySinglePath, &[network]),
    }
}

fn policy_is_signable(policy: &RegisteredPolicy) -> bool {
    !policy.archived
        && network_from_policy(policy)
            .map(is_public_network)
            .unwrap_or(false)
}

fn signable_policies(store: &store::PolicyStore) -> Vec<RegisteredPolicy> {
    store
        .all()
        .iter()
        .filter(|p| policy_is_signable(p))
        .cloned()
        .collect()
}

fn load_policies(
    dir: &Path,
    seed: &[u8],
    secp: &Secp256k1<All>,
    fingerprint: Fingerprint,
) -> store::PolicyStore {
    load_policies_impl(dir, seed, secp, fingerprint)
}

#[cfg(not(keyos))]
fn load_policies_impl(
    dir: &Path,
    seed: &[u8],
    secp: &Secp256k1<All>,
    fingerprint: Fingerprint,
) -> store::PolicyStore {
    let mut s = store::PolicyStore::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return s;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(text) = read_text_path_limited(&path, MAX_POLICY_STORAGE_BYTES, "policy") {
            if let Ok(reg) = store::from_json(&text) {
                match validate_loaded_policy(reg, seed, secp, fingerprint) {
                    Ok(mut reg) => {
                        // Archive was removed from the product flow. Revive
                        // records created by older builds so they remain usable.
                        reg.archived = false;
                        let _ = s.add(reg);
                    }
                    Err(error) => {
                        log::warn!("ignored invalid wallet policy {}: {error}", path.display());
                    }
                }
            }
        }
    }
    s
}

#[cfg(keyos)]
fn load_policies_impl(
    _dir: &Path,
    seed: &[u8],
    secp: &Secp256k1<All>,
    fingerprint: Fingerprint,
) -> store::PolicyStore {
    let fs = FileSystem::default();
    let mut s = store::PolicyStore::new();
    let Ok(dir) = fs.open_dir("", fs::Location::AppData) else {
        return s;
    };
    while let Ok(Some(entry)) = dir.next_entry() {
        if !entry.name.starts_with("policy_") || !entry.name.ends_with(".json") || entry.is_dir {
            continue;
        }
        let Ok(text) = read_text_fs_limited(
            &fs,
            &entry.name,
            fs::Location::AppData,
            MAX_POLICY_STORAGE_BYTES,
            "policy",
        ) else {
            continue;
        };
        if let Ok(reg) = store::from_json(&text) {
            match validate_loaded_policy(reg, seed, secp, fingerprint) {
                Ok(mut reg) => {
                    // Archive was removed from the product flow. Revive
                    // records created by older builds so they remain usable.
                    reg.archived = false;
                    let _ = s.add(reg);
                }
                Err(error) => log::warn!("ignored invalid wallet policy {}: {error}", entry.name),
            }
        }
    }
    s
}

fn validate_loaded_policy(
    mut stored: RegisteredPolicy,
    seed: &[u8],
    secp: &Secp256k1<All>,
    fingerprint: Fingerprint,
) -> anyhow::Result<RegisteredPolicy> {
    migrate_policy_metadata(&mut stored);
    let network = network_from_policy(&stored).context("unsupported stored policy network")?;
    let registration = transport::PolicyRegistration::from_registered(&stored)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let canonical = registration
        .canonical_descriptor()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if canonical != stored.descriptor
        || registration.descriptor_checksum()? != stored.descriptor_checksum
        || registration.policy_id != stored.policy_id
    {
        anyhow::bail!("stored wallet-policy identity does not match its descriptor");
    }
    let mut rebuilt =
        register_descriptor_for_network(&canonical, seed, secp, fingerprint, network)?;
    rebuilt.name = registration.name;
    rebuilt.archived = stored.archived;
    for signer in &mut rebuilt.signers {
        if let Some(saved) = stored
            .signers
            .iter()
            .find(|saved| saved.xpub == signer.xpub && saved.fingerprint == signer.fingerprint)
        {
            if let Ok(name) = validate_signer_name(&saved.name) {
                signer.name = name;
            }
        }
    }
    Ok(rebuilt)
}

fn migrate_policy_metadata(policy: &mut RegisteredPolicy) {
    if policy.schema_version >= liana::POLICY_SCHEMA_VERSION
        && !policy.policy_id.is_empty()
        && !policy.policy_template.is_empty()
        && !policy.policy_keys.is_empty()
    {
        return;
    }
    match transport::PolicyRegistration::from_registered(policy) {
        Ok(registration) => registration.apply_to(policy),
        Err(error) => log::warn!(
            "could not migrate Liana policy #{}: {}",
            policy.descriptor_checksum,
            error
        ),
    }
}

fn save_policy(dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> {
    save_policy_impl(dir, reg)
}

#[cfg(not(keyos))]
fn save_policy_impl(dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> {
    let json = store::to_json(reg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = dir.join(format!("policy_{}.json", reg.descriptor_checksum));
    let tmp_path = dir.join(format!("policy_{}.json.tmp", reg.descriptor_checksum));
    let _ = std::fs::remove_file(&tmp_path);
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

#[cfg(keyos)]
fn save_policy_impl(_dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let json = store::to_json(reg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = format!("policy_{}.json", reg.descriptor_checksum);
    let tmp_path = format!("{path}.tmp");
    let fs = FileSystem::default();
    let _ = fs.remove(&tmp_path, fs::Location::AppData);
    {
        let mut file = fs
            .open_file(
                &tmp_path,
                fs::Location::AppData,
                fs::OpenFlags {
                    read: true,
                    write: true,
                    create: true,
                },
            )
            .map_err(|e| anyhow::anyhow!("open {tmp_path}: {e:?}"))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.truncate()
            .map_err(|e| anyhow::anyhow!("truncate {tmp_path}: {e:?}"))?;
        file.flush()?;
    }
    match fs.rename(&tmp_path, &path, fs::Location::AppData) {
        Ok(()) => {}
        Err(fs::Error::FileAlreadyExists) => {
            fs.remove(&path, fs::Location::AppData)
                .map_err(|e| anyhow::anyhow!("remove existing {path}: {e:?}"))?;
            fs.rename(&tmp_path, &path, fs::Location::AppData)
                .map_err(|e| anyhow::anyhow!("rename {tmp_path} to {path}: {e:?}"))?;
        }
        Err(e) => anyhow::bail!("rename {tmp_path} to {path}: {e:?}"),
    }
    Ok(())
}

fn delete_policy_file(dir: &Path, checksum: &str) -> anyhow::Result<()> {
    delete_policy_file_impl(dir, checksum)
}

#[cfg(not(keyos))]
fn delete_policy_file_impl(dir: &Path, checksum: &str) -> anyhow::Result<()> {
    std::fs::remove_file(dir.join(format!("policy_{checksum}.json")))?;
    Ok(())
}

#[cfg(keyos)]
fn delete_policy_file_impl(_dir: &Path, checksum: &str) -> anyhow::Result<()> {
    let path = format!("policy_{checksum}.json");
    FileSystem::default()
        .remove(&path, fs::Location::AppData)
        .map_err(|e| anyhow::anyhow!("remove {path}: {e:?}"))
}

fn data_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(DATA_SUBDIR)
}

fn load_network_preference(dir: &Path) -> Option<Network> {
    load_network_preference_impl(dir)
        .ok()
        .and_then(|value| network_from_label(value.trim()))
        .filter(|network| is_public_network(*network))
}

#[cfg(not(keyos))]
fn load_network_preference_impl(dir: &Path) -> anyhow::Result<String> {
    read_text_path_limited(&dir.join(NETWORK_PREFERENCE_FILE), 16, "network preference")
}

#[cfg(keyos)]
fn load_network_preference_impl(_dir: &Path) -> anyhow::Result<String> {
    read_text_fs_limited(
        &FileSystem::default(),
        NETWORK_PREFERENCE_FILE,
        fs::Location::AppData,
        16,
        "network preference",
    )
}

fn save_network_preference(dir: &Path, network: Network) -> anyhow::Result<()> {
    if !is_public_network(network) {
        anyhow::bail!("unsupported public network");
    }
    save_network_preference_impl(dir, network_label(network).as_bytes())
}

#[cfg(not(keyos))]
fn save_network_preference_impl(dir: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(dir.join(NETWORK_PREFERENCE_FILE), bytes)?;
    Ok(())
}

#[cfg(keyos)]
fn save_network_preference_impl(_dir: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let filesystem = FileSystem::default();
    let mut file = filesystem
        .open_file(
            NETWORK_PREFERENCE_FILE,
            fs::Location::AppData,
            fs::OpenFlags {
                read: true,
                write: true,
                create: true,
            },
        )
        .map_err(|error| anyhow::anyhow!("open network preference: {error:?}"))?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(bytes)?;
    file.truncate()
        .map_err(|error| anyhow::anyhow!("truncate network preference: {error:?}"))?;
    file.flush()?;
    Ok(())
}

#[cfg(all(not(keyos), feature = "sim-bridge"))]
fn sim_bridge_file(dir: &Path, filename: &str) -> Option<PathBuf> {
    let path = dir.join(filename);
    path.exists().then_some(path)
}

#[cfg(any(keyos, not(feature = "sim-bridge")))]
fn sim_bridge_file(_dir: &Path, _filename: &str) -> Option<PathBuf> {
    None
}

#[cfg(all(not(keyos), feature = "sim-bridge"))]
fn write_bridge_file(dir: &Path, filename: &str, bytes: &[u8]) {
    write_bridge_path(&dir.join(filename), bytes);
}

#[cfg(any(keyos, not(feature = "sim-bridge")))]
fn write_bridge_file(_dir: &Path, _filename: &str, _bytes: &[u8]) {}

#[cfg(all(not(keyos), feature = "sim-bridge"))]
fn write_bridge_path(path: &Path, bytes: &[u8]) {
    if let Err(e) = std::fs::write(path, bytes) {
        log::warn!("failed to write sim bridge file {}: {e}", path.display());
    }
}

#[cfg(any(keyos, not(feature = "sim-bridge")))]
fn write_bridge_path(_path: &Path, _bytes: &[u8]) {}

fn show_startup_error(ui: &AppWindow, msg: &str) {
    let cb = ui.global::<Callbacks>();
    cb.set_policy_count(0);
    cb.set_import_error(msg.into());
}

enum LauncherInput {
    Psbt(Psbt),
    Policy(String),
    Address(Vec<u8>),
}

fn launcher_input(result: MatchedQrResult) -> anyhow::Result<LauncherInput> {
    match result.scan_result {
        ScanQrResult::Ur2 { ur_type, data, .. } if ur_type.eq_ignore_ascii_case("crypto-psbt") => {
            let bytes = decode_ur_psbt(&ur_type, &data)?;
            parse_psbt_bytes(&bytes).map(LauncherInput::Psbt)
        }
        ScanQrResult::Ur2 { ur_type, data, .. } if ur_type.eq_ignore_ascii_case("bytes") => {
            let bytes = decode_ur_bytes(&ur_type, &data, "bytes")?;
            if transport::AddressVerificationRequest::from_json(&bytes).is_ok() {
                Ok(LauncherInput::Address(bytes))
            } else {
                decode_policy_text(bytes).map(LauncherInput::Policy)
            }
        }
        ScanQrResult::Ur2 { ur_type, .. } => {
            anyhow::bail!("Unsupported Liana QR type: ur:{ur_type}.")
        }
        ScanQrResult::Qr { data, .. } => decode_policy_text(data).map(LauncherInput::Policy),
        ScanQrResult::LeftClicked | ScanQrResult::RightClicked | ScanQrResult::ButtonClicked => {
            anyhow::bail!("The launcher did not return QR data.")
        }
    }
}

fn decode_policy_text(bytes: Vec<u8>) -> anyhow::Result<String> {
    if bytes.is_empty() || bytes.len() > transport::MAX_DESCRIPTOR_BYTES {
        anyhow::bail!(
            "Wallet-policy QR is empty or exceeds {} bytes.",
            transport::MAX_DESCRIPTOR_BYTES
        );
    }
    String::from_utf8(bytes).context("wallet-policy QR is not UTF-8")
}

fn decode_bitcoin_address_qr(data: &[u8]) -> anyhow::Result<String> {
    let text = std::str::from_utf8(data)
        .context("Address QR is not UTF-8")?
        .trim();
    let value = text
        .strip_prefix("bitcoin:")
        .or_else(|| text.strip_prefix("BITCOIN:"))
        .unwrap_or(text)
        .split('?')
        .next()
        .unwrap_or_default();
    if value.is_empty() {
        anyhow::bail!("Address QR is empty.");
    }
    Address::from_str(value)
        .map_err(|_| anyhow::anyhow!("Scan Liana's verification QR or a Bitcoin address QR."))?;
    Ok(value.to_owned())
}

fn decode_ur_bytes(ur_type: &str, cbor: &[u8], expected_type: &str) -> anyhow::Result<Vec<u8>> {
    if ur_type != expected_type {
        anyhow::bail!("Expected ur:{expected_type}, received ur:{ur_type}.");
    }
    if cbor.len() > transport::MAX_REGISTRY_CBOR_BYTES {
        anyhow::bail!(
            "decoded registry CBOR exceeds {} bytes",
            transport::MAX_REGISTRY_CBOR_BYTES
        );
    }
    match UrValue::from_ur(ur_type, cbor).context("invalid UR registry value")? {
        UrValue::Bytes(bytes) => {
            let bytes = bytes.to_vec();
            if bytes.len() > transport::MAX_JSON_BYTES {
                anyhow::bail!(
                    "decoded JSON envelope exceeds {} bytes",
                    transport::MAX_JSON_BYTES
                );
            }
            Ok(bytes)
        }
        _ => anyhow::bail!("ur:{ur_type} does not contain a bytes registry value."),
    }
}

fn decode_ur_psbt(ur_type: &str, cbor: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ur_type != "crypto-psbt" {
        anyhow::bail!("Expected ur:crypto-psbt, received ur:{ur_type}.");
    }
    if cbor.len() > transport::MAX_REGISTRY_CBOR_BYTES {
        anyhow::bail!(
            "decoded registry CBOR exceeds {} bytes",
            transport::MAX_REGISTRY_CBOR_BYTES
        );
    }
    match UrValue::from_ur(ur_type, cbor).context("invalid crypto-psbt registry value")? {
        UrValue::Psbt(bytes) => Ok(bytes.to_vec()),
        _ => anyhow::bail!("ur:crypto-psbt does not contain a PSBT registry value."),
    }
}

fn registry_bytes_cbor(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    if bytes.len() > transport::MAX_REGISTRY_CBOR_BYTES {
        anyhow::bail!(
            "QR payload exceeds {} bytes. Use a file instead.",
            transport::MAX_REGISTRY_CBOR_BYTES
        );
    }
    let encoded = minicbor::to_vec(minicbor::bytes::ByteVec::from(bytes.to_vec()))
        .map_err(|e| anyhow::anyhow!("encode UR registry bytes: {e}"))?;
    if encoded.len() > transport::MAX_REGISTRY_CBOR_BYTES {
        anyhow::bail!(
            "Encoded QR payload exceeds {} bytes. Use a file instead.",
            transport::MAX_REGISTRY_CBOR_BYTES
        );
    }
    Ok(encoded)
}

fn read_bytes_path_limited(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        anyhow::bail!(
            "The {label} file is {} bytes. Maximum size: {max_bytes} bytes.",
            meta.len()
        );
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("The {label} file is too large. Maximum size: {max_bytes} bytes.");
    }
    Ok(bytes)
}

fn read_text_path_limited(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<String> {
    String::from_utf8(read_bytes_path_limited(path, max_bytes, label)?)
        .map_err(|_| anyhow::anyhow!("The {label} file is not valid UTF-8 text."))
}

fn read_bytes_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let meta = filesystem
        .metadata(path, location)
        .map_err(|e| anyhow::anyhow!("metadata {path}: {e:?}"))?;
    if meta.size > max_bytes {
        anyhow::bail!(
            "The {label} file is {} bytes. Maximum size: {max_bytes} bytes.",
            meta.size
        );
    }
    let file = filesystem
        .open_file(
            path,
            location,
            fs::OpenFlags {
                read: true,
                write: false,
                create: false,
            },
        )
        .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
    let mut bytes = Vec::with_capacity(meta.size as usize);
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow::anyhow!("read {path}: {e:?}"))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("The {label} file is too large. Maximum size: {max_bytes} bytes.");
    }
    Ok(bytes)
}

#[cfg(keyos)]
fn read_text_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<String> {
    String::from_utf8(read_bytes_fs_limited(
        filesystem, path, location, max_bytes, label,
    )?)
    .map_err(|_| anyhow::anyhow!("The {label} file is not valid UTF-8 text."))
}

fn derive_policy_address(
    descriptor_str: &str,
    branch: u32,
    index: u32,
    network: Network,
) -> anyhow::Result<String> {
    if branch > 1 || index >= (1 << 31) {
        anyhow::bail!("Address derivation is outside the supported range.");
    }
    let parsed = descriptor::import(descriptor_str).map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let singles = parsed
        .descriptor
        .into_single_descriptors()
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let descriptor = singles
        .get(branch as usize)
        .context("wallet policy does not contain the requested branch")?;
    descriptor
        .at_derivation_index(index)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .address(network)
        .map(|address| address.to_string())
        .map_err(|e| anyhow::anyhow!("derive address: {e}"))
}

fn find_registered_address(
    policies: &[RegisteredPolicy],
    expected_checksum: &str,
    scanned_address: &str,
    seed: &[u8],
    secp: &Secp256k1<All>,
    passport_fp: Fingerprint,
) -> anyhow::Result<(RegisteredPolicy, u32, u32, String)> {
    let mut matched = None;
    let mut saw_policy = false;
    let mut saw_matching_network = false;
    for policy in policies.iter().filter(|policy| {
        (expected_checksum.is_empty() || policy.descriptor_checksum == expected_checksum)
            && policy_is_signable(policy)
    }) {
        saw_policy = true;
        let network =
            network_from_policy(policy).context("wallet policy network is unsupported")?;
        let checked = match Address::from_str(scanned_address)
            .map_err(|_| anyhow::anyhow!("The scanned code is not a Bitcoin address."))?
            .require_network(network)
        {
            Ok(address) => {
                saw_matching_network = true;
                address.to_string()
            }
            Err(_) if expected_checksum.is_empty() => continue,
            Err(_) => anyhow::bail!("The address is for a different Bitcoin network."),
        };
        verify_registered_key(policy, seed, secp, passport_fp)?;
        let parsed =
            descriptor::import(&policy.descriptor).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let branches = parsed
            .descriptor
            .into_single_descriptors()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        for branch in 0..=1u32 {
            let descriptor = branches
                .get(branch as usize)
                .context("wallet policy does not contain both receive and change branches")?;
            for index in 0..ADDRESS_SEARCH_LIMIT {
                let derived = descriptor
                    .at_derivation_index(index)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?
                    .address(network)
                    .map_err(|e| anyhow::anyhow!("derive address: {e}"))?
                    .to_string();
                if derived == checked {
                    if matched.is_some() {
                        anyhow::bail!(
                            "The address matches more than one registered wallet policy."
                        );
                    }
                    matched = Some((policy.clone(), branch, index, checked.clone()));
                }
            }
        }
    }
    if !saw_policy {
        anyhow::bail!("Wallet policy is not registered.");
    }
    if !saw_matching_network {
        anyhow::bail!("The address is for a different Bitcoin network.");
    }
    matched.with_context(|| {
        format!(
            "Address not found in the first {ADDRESS_SEARCH_LIMIT} receive or change addresses for this wallet policy"
        )
    })
}

/// Format an integer with thousands separators (52596 -> "52,596").
fn commas(n: impl Into<u64>) -> String {
    let s = n.into().to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Read a PSBT from a file, accepting raw binary (BIP-174) or base64 text
/// (Liana can export either).
/// Parse a PSBT from raw bytes — accepts either binary or base64-encoded.
fn parse_psbt_bytes(bytes: &[u8]) -> anyhow::Result<Psbt> {
    use base64::Engine;
    if let Ok(psbt) = Psbt::deserialize(bytes) {
        return Ok(psbt);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(text.trim()) {
            if let Ok(psbt) = Psbt::deserialize(&raw) {
                return Ok(psbt);
            }
        }
    }
    Err(anyhow::anyhow!("not a valid PSBT (binary or base64)"))
}

fn read_psbt_file(path: &Path) -> anyhow::Result<Psbt> {
    parse_psbt_bytes(&read_bytes_path_limited(path, MAX_PSBT_BYTES, "PSBT")?)
}

fn read_psbt_exchange_file() -> anyhow::Result<Psbt> {
    let bytes = read_exchange_file(&[UNSIGNED_PSBT_FILE], MAX_PSBT_BYTES, "PSBT")?;
    parse_psbt_bytes(&bytes)
}

fn import_policy_exchange_file() -> anyhow::Result<String> {
    let bytes = read_exchange_file(
        &[
            IMPORT_DESCRIPTOR_FILE,
            "wallet-policy.json",
            "wallet-policy.txt",
        ],
        MAX_DESCRIPTOR_BYTES,
        "wallet policy",
    )?;
    decode_policy_text(bytes)
}

fn read_address_exchange_file() -> anyhow::Result<AddressScan> {
    let bytes = read_exchange_file(
        &[VERIFY_ADDRESS_FILE, "address-request.json"],
        transport::MAX_JSON_BYTES as u64,
        "address request",
    )?;
    if transport::AddressVerificationRequest::from_json(&bytes).is_ok() {
        Ok(AddressScan::Request(bytes))
    } else {
        decode_bitcoin_address_qr(&bytes).map(AddressScan::Address)
    }
}

fn read_exchange_file(filenames: &[&str], max_bytes: u64, label: &str) -> anyhow::Result<Vec<u8>> {
    let filesystem = FileSystem::default();
    for location in [fs::Location::Airlock, fs::Location::Usb, fs::Location::User] {
        for filename in filenames {
            for path in [format!("{EXPORT_DIR}/{filename}"), (*filename).to_owned()] {
                if filesystem.metadata(&path, location).is_err() {
                    continue;
                }
                return read_bytes_fs_limited(&filesystem, &path, location, max_bytes, label);
            }
        }
    }
    anyhow::bail!(
        "No {label} file found. Scan it from the Passport launcher, or place {} in the liana folder on removable storage.",
        filenames.first().copied().unwrap_or("the expected file")
    )
}

/// Open the file-browser picker (directory-selection) so the user chooses where
/// to save, then write `filename` with `bytes` into that folder + location.
/// Returns a "location:path" string for the status. Requires the per-location
/// access grants in manifest.toml (USB / Airlock / User), else "Access Denied".
/// Open the file picker in folder-selection mode, then write `filename` into the
/// chosen folder/location. Mirrors the Bitcoin app's save flow exactly: open with
/// `{ read: false, write: true, create: true }` and a single `overwrite` — no
/// `set_len` (which errors on the FAT/SD path and aborts the write). `overwrite`
/// Write `bytes` to a fresh file inside `dir` at `location`, committing it in the
/// order that survives card removal on FAT media: chunked write -> `File::flush`
/// (which writes the directory entry: size / first_cluster / mtime) -> close the
/// file. KeyOS commits the file and directory entry through the grantable,
/// file-level `Flush` and `CloseFile` operations.
///
/// The directory-entry flush on close is the critical step (see SFT-7122): in
/// rust-fatfs the FAT and data bytes hit the block cache during the write, but the
/// directory entry only persists on `File::flush` / close.
fn write_export(
    filename: &str,
    bytes: &[u8],
    location: fs::Location,
    dir: &str,
) -> anyhow::Result<String> {
    use std::io::Write;
    let filesystem = FileSystem::default();
    let directory = filesystem.create_dir(dir, location).map_err(|e| {
        if matches!(e, fs::Error::NoMedia) {
            match location {
                // Airlock is owned by the host while Passport is plugged in over USB.
                fs::Location::Airlock => anyhow::anyhow!(
                    "Disconnect Passport from your computer first, then save (Airlock is in use while connected)"
                ),
                fs::Location::Usb => anyhow::anyhow!("No SD card or USB drive found"),
                _ => anyhow::anyhow!("Storage not available"),
            }
        } else {
            anyhow::anyhow!("open {dir}: {e:?}")
        }
    })?;
    let unique = directory
        .pick_next_filename(filename, None)
        .map_err(|e| anyhow::anyhow!("pick filename: {e:?}"))?;
    let path = format!("{dir}/{unique}");
    {
        let mut file = filesystem
            .open_file(
                path.clone(),
                location,
                fs::OpenFlags {
                    read: false,
                    write: true,
                    create: true,
                },
            )
            .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
        let mut written = 0usize;
        while written < bytes.len() {
            let end = (written + 512).min(bytes.len());
            let n = file
                .write(&bytes[written..end])
                .map_err(|e| anyhow::anyhow!("write {path} @{written}: {e:?}"))?;
            if n == 0 {
                anyhow::bail!("write returned 0 at offset {written} of {}", bytes.len());
            }
            written += n;
        }
        // Commit the directory entry (NOT done by FileSystem::flush alone).
        file.flush()
            .map_err(|e| anyhow::anyhow!("flush {path}: {e:?}"))?;
    } // drop file -> CloseFile (re-commits the directory entry)
    drop(directory); // CloseDir
    Ok(format!("{}{}", loc_label(location), path))
}

/// Write to the first public exchange location currently available. Airlock is
/// preferred, followed by removable storage and the app's user-storage grant.
fn export_exchange_file(filename: &str, bytes: &[u8]) -> anyhow::Result<String> {
    let mut last_error = None;
    for location in [fs::Location::Airlock, fs::Location::Usb, fs::Location::User] {
        match write_export(filename, bytes, location, EXPORT_DIR) {
            Ok(destination) => return Ok(destination),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No writable exchange storage is available.")))
}

fn loc_label(loc: fs::Location) -> &'static str {
    match loc {
        fs::Location::Usb => "usb:/",
        fs::Location::Airlock => "airlock:/",
        fs::Location::User => "user:/",
        _ => "",
    }
}

/// Base64-encode a PSBT (Liana's import-from-text / paste format).
fn psbt_base64(psbt: &Psbt) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

// ---------------------------------------------------------------------------
// Tests for the app-specific glue (no GUI). The policy/PSBT/signing logic
// itself is covered by liana-signer-core's own test suite.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use liana::bitcoin::sighash::EcdsaSighashType;

    use super::*;

    #[test]
    fn xpub_network_defaults_to_mainnet_and_labels_round_trip() {
        assert_eq!(DEFAULT_NETWORK, Network::Bitcoin);
        for network in [Network::Bitcoin, Network::Signet, Network::Testnet] {
            assert_eq!(network_from_label(network_label(network)), Some(network));
        }
    }

    #[test]
    fn selected_test_network_persists_for_tbtc_imports() {
        let dir = std::env::temp_dir().join("liana-signer-test-network");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load_network_preference(&dir), None);
        save_network_preference(&dir, Network::Testnet).unwrap();
        assert_eq!(load_network_preference(&dir), Some(Network::Testnet));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn device() -> (Secp256k1<All>, Xpub, Fingerprint) {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Signet, &[0x11; 32]).unwrap();
        let fp = master.fingerprint(&secp);
        let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
        let xpub = Xpub::from_priv(&secp, &master.derive_priv(&secp, &acct).unwrap());
        (secp, xpub, fp)
    }

    // Regression: a REAL descriptor exported by Liana (Signet, P2WSH simple
    // inheritance) parses, our recomputed checksum matches Liana's exactly, and
    // the paths/timelock/signers classify correctly. (Ported from the retired
    // liana-signer-core reference crate.)
    #[test]
    fn real_liana_descriptor_parses_and_matches_checksum() {
        const REAL: &str = "wsh(or_d(pk([22663c8a/48'/1'/0'/2']tpubDDz15PcqAurpydRu3ZD7EB9nGRFEttDcbge8sPTqBo2fGXQkdoLjwAkoHjKFkqBFpkrZ8dS6DSDB5bG5EC5XcbJ5LuTRbgtgoCugm7puBAX/<0;1>/*),and_v(v:pkh([22663c8a/48'/1'/0'/2']tpubDDz15PcqAurpydRu3ZD7EB9nGRFEttDcbge8sPTqBo2fGXQkdoLjwAkoHjKFkqBFpkrZ8dS6DSDB5bG5EC5XcbJ5LuTRbgtgoCugm7puBAX/<2;3>/*),older(52596))))#9xtyycfv";
        let parsed = descriptor::import(REAL).expect("real Liana descriptor imports");
        assert_eq!(
            parsed.checksum, "9xtyycfv",
            "our checksum must match Liana's"
        );
        let fp = Fingerprint::from_str("22663c8a").unwrap();
        let reg = policy::build_registered_policy("real", "Real", "signet", &parsed, fp).unwrap();
        assert_eq!(reg.paths.len(), 2);
        let recovery = reg
            .paths
            .iter()
            .find(|p| matches!(p.kind, SpendPathKind::Recovery))
            .unwrap();
        assert_eq!(recovery.relative_timelock_blocks, Some(52596));
        assert!(reg
            .signers
            .iter()
            .all(|s| s.fingerprint == "22663c8a" && s.owned_by_passport));
    }

    #[test]
    fn liana_desktop_multisig_fixture_matches_core_policy_identity() {
        let source = include_str!("../fixtures/liana-multisig-testnet.descriptor").trim();
        let parsed = descriptor::import(source).expect("shared Liana descriptor imports");
        assert_eq!(parsed.checksum, "u768v50p");
        let registration = transport::PolicyRegistration::from_descriptor(
            "Family Vault",
            Network::Signet,
            &parsed.canonical,
        )
        .unwrap();
        assert_eq!(
            registration.policy_id,
            "54c9de390dd71ce7f500cac1b20b3ec2bbea26fd31dea892f936e78b61833151"
        );
    }

    #[test]
    fn sample_descriptor_is_valid_liana_p2wsh() {
        let (secp, xpub, fp) = device();
        let desc = sample_descriptor(&secp, &xpub, fp);
        assert!(desc.starts_with("wsh("));
        let parsed = descriptor::import(&desc).expect("imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 2);
        assert!(paths
            .iter()
            .any(|p| matches!(p.kind, SpendPathKind::Primary)));
        let rec = paths
            .iter()
            .find(|p| matches!(p.kind, SpendPathKind::Recovery))
            .unwrap();
        assert_eq!(rec.relative_timelock_blocks, Some(RECOVERY_BLOCKS));
    }

    // A key-with-origin string (`[fp/path]xpub`) from a deterministic seed, for
    // building descriptors in tests without hardcoding xpubs.
    fn test_key(seed: u8) -> String {
        let secp = Secp256k1::new();
        let m = Xpriv::new_master(Network::Signet, &[seed; 32]).unwrap();
        let fp = m.fingerprint(&secp);
        let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
        let xpub = Xpub::from_priv(&secp, &m.derive_priv(&secp, &acct).unwrap());
        format!("[{fp}/48'/1'/0'/2']{xpub}")
    }

    fn import_error(desc: &str) -> String {
        match descriptor::import(desc) {
            Ok(_) => panic!("descriptor unexpectedly imported"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn descriptor_without_checksum_is_rejected() {
        let (secp, xpub, fp) = device();
        let desc = sample_descriptor(&secp, &xpub, fp);
        let without_checksum = desc.rsplit_once('#').map(|(body, _)| body).unwrap_or(&desc);
        let err = import_error(without_checksum);
        assert!(err.contains("checksum is required"), "got: {err}");
    }

    // A decaying policy (primary + two recovery tiers at different timelocks)
    // must flatten into three distinct spend paths, not merge the nested
    // recovery branches into one.
    #[test]
    fn decaying_policy_flattens_into_distinct_tiers() {
        let (a, b, c) = (test_key(0x21), test_key(0x22), test_key(0x23));
        let desc = descriptor_with_checksum(&format!(
            "wsh(or_d(pk({a}/<0;1>/*),or_i(and_v(v:pkh({b}/<0;1>/*),older(1000)),and_v(v:pkh({c}/<0;1>/*),older(2000)))))"
        ));
        let parsed = descriptor::import(&desc).expect("decaying descriptor imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 3, "primary + 2 recovery tiers");
        assert_eq!(
            paths
                .iter()
                .filter(|p| matches!(p.kind, SpendPathKind::Primary))
                .count(),
            1
        );
        let mut tls: Vec<u32> = paths
            .iter()
            .filter(|p| matches!(p.kind, SpendPathKind::Recovery))
            .filter_map(|p| p.relative_timelock_blocks)
            .collect();
        tls.sort();
        assert_eq!(tls, vec![1000, 2000], "each tier keeps its own timelock");
    }

    // Taproot is shelved for this release: fail clearly instead of importing a
    // descriptor whose PSBT flow is not fully verified yet.
    #[test]
    fn taproot_liana_descriptor_is_rejected_for_now() {
        let (a, b) = (test_key(0x31), test_key(0x32));
        let desc = descriptor_with_checksum(&format!(
            "tr({a}/<0;1>/*,and_v(v:pk({b}/<0;1>/*),older(4032)))"
        ));
        let err = import_error(&desc);
        assert!(err.contains("Taproot"), "got: {err}");
    }

    #[test]
    fn absolute_timelock_descriptor_is_rejected_for_now() {
        let a = test_key(0x33);
        let desc = descriptor_with_checksum(&format!("wsh(and_v(v:pk({a}/<0;1>/*),after(100)))"));
        let err = import_error(&desc);
        assert!(err.contains("absolute locktimes"), "got: {err}");
    }

    #[test]
    fn time_based_csv_descriptor_is_rejected_for_now() {
        let (a, b) = (test_key(0x34), test_key(0x35));
        let time_based_csv = (1 << 22) + 144;
        let desc = descriptor_with_checksum(&format!(
            "wsh(or_d(pk({a}/<0;1>/*),and_v(v:pkh({b}/<0;1>/*),older({time_based_csv}))))"
        ));
        let err = import_error(&desc);
        assert!(err.contains("block-based"), "got: {err}");
    }

    #[test]
    fn seeded_policy_is_owned_by_device() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).expect("seed");
        // Exactly one signer, the device, owns a key.
        let owned = reg.signers.iter().filter(|s| s.owned_by_passport).count();
        assert_eq!(owned, 1);
        assert!(reg
            .signers
            .iter()
            .any(|s| s.fingerprint == fp.to_string() && s.owned_by_passport));
    }

    #[test]
    fn owner_psbt_matches_and_signs_with_device_key() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");

        let m = lpsbt::match_psbt(&psbt, &reg, fp).expect("match");
        assert!(m.matched, "demo PSBT must match the seeded policy");
        assert_eq!(m.active_path, Some(SpendPathKind::Primary));
        assert!(m.passport_can_sign);
        assert_eq!(m.expected_signatures, 1);

        // The decision gate must allow, and signing must finalize.
        assert!(matches!(
            signing::decide(&m, &reg),
            signing::SignDecision::Allow {
                path: SpendPathKind::Primary,
                ..
            }
        ));
        let master = Xpriv::new_master(Network::Signet, &[0x11; 32]).unwrap();
        let finalized =
            signing::sign_and_finalize(psbt, &master, &secp, m.expected_signatures).expect("sign");
        assert!(finalized.inputs[0].final_script_witness.is_some());
    }

    #[test]
    fn psbt_matching_uses_declared_index_without_a_gap_limit() {
        use liana::miniscript::psbt::PsbtInputExt;

        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).unwrap();
        let parsed = descriptor::import(&reg.descriptor).unwrap();
        let definite = parsed.descriptor.into_single_descriptors().unwrap()[0]
            .at_derivation_index(5_000)
            .unwrap();
        let mut input = Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: definite.script_pubkey(),
            }),
            ..Input::default()
        };
        input.update_with_descriptor_unchecked(&definite).unwrap();
        psbt.inputs[0] = input;

        let matched = lpsbt::match_psbt(&psbt, &reg, fp).unwrap();
        assert!(matched.matched);
        assert!(matched.passport_can_sign);
    }

    #[test]
    fn repeated_passport_key_in_exclusive_paths_adds_both_signatures() {
        let (secp, xpub, fp) = device();
        let key = format!("[{fp}/48'/1'/0'/2']{xpub}");
        let descriptor = descriptor_with_checksum(&format!(
            "wsh(or_d(pk({key}/<0;1>/*),and_v(v:pkh({key}/<2;3>/*),older(100))))"
        ));
        let reg = register_descriptor(&descriptor, &[0x11; 32], &secp, fp).unwrap();
        let psbt = build_owner_psbt(&secp, &reg, &xpub, fp).unwrap();
        let matched = lpsbt::match_psbt(&psbt, &reg, fp).unwrap();
        assert_eq!(matched.expected_signatures, 2);

        let master = Xpriv::new_master(Network::Signet, &[0x11; 32]).unwrap();
        let signed = signing::sign(psbt, &master, &secp, matched.expected_signatures).unwrap();
        assert_eq!(signed.inputs[0].partial_sigs.len(), 2);
    }

    #[test]
    fn two_passport_signatures_on_one_spend_path_are_rejected() {
        let (secp, xpub, fp) = device();
        let key = format!("[{fp}/48'/1'/0'/2']{xpub}");
        let descriptor = descriptor_with_checksum(&format!(
            "wsh(and_v(v:pk({key}/<0;1>/*),pk({key}/<2;3>/*)))"
        ));
        let error = register_descriptor(&descriptor, &[0x11; 32], &secp, fp)
            .unwrap_err()
            .to_string();
        assert!(error.contains("more than one signature"), "got: {error}");
    }

    #[test]
    fn change_requires_exact_output_script_and_derivations() {
        use liana::miniscript::psbt::PsbtOutputExt;

        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).unwrap();
        let parsed = descriptor::import(&reg.descriptor).unwrap();
        let definite = parsed.descriptor.into_single_descriptors().unwrap()[1]
            .at_derivation_index(5_000)
            .unwrap();
        psbt.unsigned_tx.output[0].script_pubkey = definite.script_pubkey();
        let mut output = Output::default();
        output.update_with_descriptor_unchecked(&definite).unwrap();
        // Liana may omit PSBT_OUT_WITNESS_SCRIPT; the exact script and complete
        // derivation map are still sufficient.
        output.witness_script = None;
        psbt.outputs[0] = output;

        let matched = lpsbt::match_psbt(&psbt, &reg, fp).unwrap();
        assert!(matched.passport_can_sign);
        assert!(matched.change_outputs.contains(&0));

        psbt.unsigned_tx.output[0].script_pubkey =
            ScriptBuf::from_hex("0014000000000000000000000000000000000000dead").unwrap();
        let fraudulent = lpsbt::match_psbt(&psbt, &reg, fp).unwrap();
        assert!(fraudulent.matched);
        assert!(!fraudulent.passport_can_sign);
        assert!(fraudulent
            .reasons
            .iter()
            .any(|reason| reason.contains("output 0")));
    }

    #[test]
    fn textual_policy_qr_and_testnet_selection_are_supported() {
        let text = decode_policy_text(b"wsh(pk(example))#12345678".to_vec()).unwrap();
        assert_eq!(text, "wsh(pk(example))#12345678");
        assert!(decode_policy_text(vec![b'x'; transport::MAX_DESCRIPTOR_BYTES + 1]).is_err());

        let (secp, xpub, fp) = device();
        let descriptor = sample_descriptor(&secp, &xpub, fp);
        let registered =
            register_descriptor_for_network(&descriptor, &[0x11; 32], &secp, fp, Network::Testnet)
                .unwrap();
        assert_eq!(registered.network, "testnet");
        let envelope = transport::PolicyRegistration::from_descriptor(
            "Testnet wallet",
            Network::Testnet,
            &descriptor,
        )
        .unwrap();
        let restored = register_policy_payload(
            std::str::from_utf8(&transport::encode_json(&envelope).unwrap()).unwrap(),
            &[0x11; 32],
            &secp,
            fp,
            Network::Testnet,
        )
        .unwrap();
        assert_eq!(restored.network, "testnet");
        assert_eq!(
            transport::PolicyNetwork::from_network(Network::Testnet).unwrap(),
            transport::PolicyNetwork::Tbtc
        );
    }

    #[test]
    fn launcher_handoff_accepts_plain_policy_qr() {
        let result = MatchedQrResult {
            scan_result: ScanQrResult::new_qr(b"wsh(pk(example))#12345678"),
            matched_rules: Vec::new(),
        };
        let serialized = result.serialize();
        let decoded = MatchedQrResult::from_slice(&serialized).expect("launcher handoff decodes");
        match launcher_input(decoded).expect("policy handoff is accepted") {
            LauncherInput::Policy(policy) => {
                assert_eq!(policy, "wsh(pk(example))#12345678");
            }
            _ => panic!("expected a wallet-policy handoff"),
        }
    }

    #[test]
    fn launcher_handoff_rejects_unregistered_ur_type() {
        let result = MatchedQrResult {
            scan_result: ScanQrResult::new_ur2("crypto-seed".into(), b"not-a-seed"),
            matched_rules: Vec::new(),
        };
        let error = match launcher_input(result) {
            Ok(_) => panic!("unsupported UR type must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Unsupported Liana QR type"), "got: {error}");
    }

    fn add_second_policy_input_without_passport_derivation(psbt: &mut Psbt) {
        let mut second_input = psbt.inputs[0].clone();
        second_input.bip32_derivation.clear();
        psbt.unsigned_tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000002",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        psbt.inputs.push(second_input);
    }

    #[test]
    fn psbt_with_passport_derivation_on_only_some_inputs_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        add_second_policy_input_without_passport_derivation(&mut psbt);

        let m = lpsbt::match_psbt(&psbt, &reg, fp).expect("match");
        assert!(
            !m.matched,
            "incomplete derivation metadata must fail exact matching"
        );
        assert_eq!(m.expected_signatures, 0);
        assert!(
            !m.passport_can_sign,
            "partial Passport derivations must block signing"
        );
        assert!(
            m.reasons
                .iter()
                .any(|r| r.contains("missing unhardened policy derivations")),
            "{:?}",
            m.reasons
        );
        assert!(matches!(
            signing::decide(&m, &reg),
            signing::SignDecision::Refuse(_)
        ));
    }

    #[test]
    fn psbt_with_outputs_exceeding_inputs_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.unsigned_tx.output[0].value = Amount::from_sat(110_000);

        let m = lpsbt::match_psbt(&psbt, &reg, fp).expect("match");
        assert!(
            m.matched,
            "the script still belongs to the registered policy"
        );
        assert!(!m.passport_can_sign, "invalid amounts must block signing");
        assert!(m
            .reasons
            .iter()
            .any(|r| r.contains("outputs exceed verified inputs")));
        assert!(matches!(
            signing::decide(&m, &reg),
            signing::SignDecision::Refuse(_)
        ));
    }

    #[test]
    fn psbt_matching_multiple_policies_is_refused() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut duplicate = reg.clone();
        duplicate.id = "duplicate".into();
        duplicate.descriptor_checksum = "duplicate".into();
        let psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        let policies = vec![reg, duplicate];

        let err = lpsbt::match_against_all(&psbt, &policies, fp)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("more than one registered policy"),
            "got: {err}"
        );
    }

    #[test]
    fn psbt_with_unsafe_sighash_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());

        let m = lpsbt::match_psbt(&psbt, &reg, fp).expect("match");
        assert!(
            m.matched,
            "the script still belongs to the registered policy"
        );
        assert!(!m.passport_can_sign, "unsafe sighash must block signing");
        assert!(
            m.reasons.iter().any(|r| r.contains("unsupported sighash")),
            "{:?}",
            m.reasons
        );
    }

    #[test]
    fn psbt_with_mismatched_witness_script_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.inputs[0].witness_script = Some(ScriptBuf::from_hex("51").unwrap());

        let m = lpsbt::match_psbt(&psbt, &reg, fp).expect("match");
        assert!(
            !m.matched,
            "witness script is part of exact policy matching"
        );
        assert!(
            !m.passport_can_sign,
            "mismatched witness_script must block signing"
        );
        assert!(
            m.reasons
                .iter()
                .any(|r| r.contains("scripts and derivations")),
            "{:?}",
            m.reasons
        );
    }

    #[test]
    fn psbt_with_inconsistent_non_witness_utxo_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        let witness_utxo = psbt.inputs[0].witness_utxo.clone().unwrap();
        psbt.inputs[0].non_witness_utxo = Some(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![witness_utxo],
        });

        let m = lpsbt::match_psbt(&psbt, &reg, fp).expect("match");
        assert!(
            m.matched,
            "the witness_utxo still belongs to the registered policy"
        );
        assert!(
            !m.passport_can_sign,
            "inconsistent non_witness_utxo must block signing"
        );
        assert!(
            m.reasons.iter().any(|r| r.contains("non_witness_utxo")),
            "{:?}",
            m.reasons
        );
    }

    #[test]
    fn version_one_transaction_can_still_use_immediate_path() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.unsigned_tx.version = Version::ONE;
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(RECOVERY_BLOCKS as u16);

        let m = lpsbt::match_psbt(&psbt, &reg, fp).expect("match");
        assert!(
            m.matched,
            "the input still belongs to the registered policy"
        );
        assert!(m.passport_can_sign, "the immediate path remains valid");
        assert_eq!(m.active_path, Some(SpendPathKind::Primary));
    }

    #[test]
    fn register_descriptor_rejects_garbage() {
        let (secp, _, fp) = device();
        assert!(
            register_descriptor("definitely not a descriptor", &[0x11; 32], &secp, fp).is_err()
        );
    }

    #[test]
    fn network_detection_rejects_mixed_extended_key_families() {
        assert_eq!(
            network_from_descriptor("wsh(pk(xpubabc))").unwrap(),
            Network::Bitcoin
        );
        assert_eq!(
            network_from_descriptor("wsh(pk(tpubabc))").unwrap(),
            Network::Signet
        );

        let mixed = network_from_descriptor("wsh(sortedmulti(2,xpubabc,tpubabc))")
            .unwrap_err()
            .to_string();
        assert!(mixed.contains("mixes mainnet and testnet"), "got: {mixed}");
    }

    #[test]
    fn register_descriptor_rejects_policy_without_passport_key() {
        let (secp, xpub, fp) = device();
        let desc = sample_descriptor(&secp, &xpub, fp);
        let wrong_fp = Fingerprint::from_str("deadbeef").unwrap();
        let err = register_descriptor(&desc, &[0x11; 32], &secp, wrong_fp)
            .unwrap_err()
            .to_string();
        assert!(err.contains("belonging to this Passport"), "got: {err}");
    }

    #[test]
    fn save_then_load_roundtrips() {
        let (secp, xpub, fp) = device();
        let mut reg = seed_sample(&secp, &xpub, fp).unwrap();
        if let Some(external) = reg
            .signers
            .iter_mut()
            .find(|signer| !signer.owned_by_passport)
        {
            external.name = "Family Recovery".into();
        }
        reg.archived = true; // Legacy records are reactivated now that archive is removed.

        let dir = std::env::temp_dir().join("liana-signer-test-store");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        save_policy(&dir, &reg).expect("save");
        let saved =
            std::fs::read_to_string(dir.join(format!("policy_{}.json", reg.descriptor_checksum)))
                .unwrap();
        assert!(saved.contains("\"schema_version\": 3"), "got: {saved}");
        let store = load_policies(&dir, &[0x11; 32], &secp, fp);
        assert_eq!(store.len(), 1);
        let loaded = store.find_by_checksum(&reg.descriptor_checksum).unwrap();
        assert!(!loaded.archived);
        assert!(loaded
            .signers
            .iter()
            .any(|signer| signer.name == "Family Recovery"));

        let mut legacy: serde_json::Value = serde_json::from_str(&saved).unwrap();
        legacy.as_object_mut().unwrap().remove("schema_version");
        let loaded_legacy = store::from_json(&serde_json::to_string(&legacy).unwrap()).unwrap();
        assert_eq!(loaded_legacy.schema_version, liana::POLICY_SCHEMA_VERSION);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupted_stored_policy_is_quarantined() {
        let (secp, xpub, fp) = device();
        let mut reg = seed_sample(&secp, &xpub, fp).unwrap();
        let registration = transport::PolicyRegistration::from_descriptor(
            &reg.name,
            Network::Signet,
            &reg.descriptor,
        )
        .unwrap();
        registration.apply_to(&mut reg);

        let dir = std::env::temp_dir().join("liana-signer-test-corrupt-store");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        save_policy(&dir, &reg).unwrap();
        let path = dir.join(format!("policy_{}.json", reg.descriptor_checksum));
        let mut record: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        record["policy_id"] = ("00".repeat(32)).into();
        std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();

        let loaded = load_policies(&dir, &[0x11; 32], &secp, fp);
        assert!(loaded.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signable_policies_excludes_archived_and_unsupported_networks() {
        let (secp, xpub, fp) = device();
        let mut active = seed_sample(&secp, &xpub, fp).unwrap();
        active.descriptor_checksum = "active".into();

        let mut archived = active.clone();
        archived.descriptor_checksum = "archived".into();
        archived.archived = true;

        let mut unsupported = active.clone();
        unsupported.descriptor_checksum = "unsupported".into();
        unsupported.network = "regtest".into();

        let mut store = store::PolicyStore::new();
        store.add(active).unwrap();
        store.add(archived).unwrap();
        store.add(unsupported).unwrap();

        let signable = signable_policies(&store);
        assert_eq!(signable.len(), 1);
        assert_eq!(signable[0].descriptor_checksum, "active");
    }

    #[cfg(all(not(keyos), not(feature = "sim-bridge")))]
    #[test]
    fn sim_bridge_is_disabled_without_feature() {
        let dir = std::env::temp_dir().join("liana-signer-test-bridge-disabled");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(UNSIGNED_PSBT_FILE), b"not used").unwrap();

        assert!(sim_bridge_file(&dir, UNSIGNED_PSBT_FILE).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(all(not(keyos), feature = "sim-bridge"))]
    #[test]
    fn sim_bridge_is_enabled_with_feature() {
        let dir = std::env::temp_dir().join("liana-signer-test-bridge-enabled");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(UNSIGNED_PSBT_FILE), b"used").unwrap();

        assert!(sim_bridge_file(&dir, UNSIGNED_PSBT_FILE).is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn psbt_file_roundtrip_binary_and_base64() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let psbt = build_owner_psbt(&secp, &reg, &xpub, fp).unwrap();

        let dir = std::env::temp_dir().join("liana-signer-test-psbt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // binary
        let bin = dir.join("a.psbt");
        std::fs::write(&bin, psbt.serialize()).unwrap();
        assert_eq!(read_psbt_file(&bin).unwrap(), psbt);

        // base64 text
        let b64 = dir.join("b.psbt");
        std::fs::write(&b64, psbt_base64(&psbt)).unwrap();
        assert_eq!(read_psbt_file(&b64).unwrap(), psbt);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qr_registry_limit_includes_the_cbor_wrapper() {
        assert!(registry_bytes_cbor(&vec![0; transport::MAX_REGISTRY_CBOR_BYTES - 3]).is_ok());
        assert!(registry_bytes_cbor(&vec![0; transport::MAX_REGISTRY_CBOR_BYTES - 2]).is_err());
    }

    #[test]
    fn policy_summary_mentions_recovery_months() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let summary = policy_summary(&reg);
        assert!(
            summary.contains("Recovery after about 12 months"),
            "got: {summary}"
        );
    }

    #[test]
    fn bound_address_derivation_uses_requested_branch_and_index() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let receive = derive_policy_address(&reg.descriptor, 0, 7, Network::Signet).unwrap();
        let change = derive_policy_address(&reg.descriptor, 1, 7, Network::Signet).unwrap();
        assert_ne!(receive, change);
        assert!(receive.starts_with("tb1"));
        assert!(derive_policy_address(&reg.descriptor, 2, 7, Network::Signet).is_err());
        assert!(derive_policy_address(&reg.descriptor, 0, 1 << 31, Network::Signet).is_err());
    }

    #[test]
    fn plain_address_qr_matches_registered_policy() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let address = derive_policy_address(&reg.descriptor, 1, 12, Network::Signet).unwrap();
        let bip21 = format!("bitcoin:{address}?label=Liana");
        let scanned = decode_bitcoin_address_qr(bip21.as_bytes()).unwrap();
        let (matched, branch, index, normalized) = find_registered_address(
            &[reg.clone()],
            &reg.descriptor_checksum,
            &scanned,
            &[0x11; 32],
            &secp,
            fp,
        )
        .unwrap();
        assert_eq!(matched.descriptor_checksum, reg.descriptor_checksum);
        assert_eq!((branch, index), (1, 12));
        assert_eq!(normalized, address);
    }

    #[test]
    fn plain_address_qr_rejects_non_address_data() {
        let error = decode_bitcoin_address_qr(b"not an address")
            .unwrap_err()
            .to_string();
        assert!(error.contains("Bitcoin address QR"), "got: {error}");
    }

    #[test]
    fn plain_address_search_skips_other_networks() {
        let (secp, xpub, fp) = device();
        let signet = seed_sample(&secp, &xpub, fp).unwrap();
        let mut mainnet = signet.clone();
        mainnet.network = "bitcoin".into();
        let address = derive_policy_address(&signet.descriptor, 0, 3, Network::Signet).unwrap();
        let (_, branch, index, _) =
            find_registered_address(&[mainnet, signet], "", &address, &[0x11; 32], &secp, fp)
                .unwrap();
        assert_eq!((branch, index), (0, 3));
    }
}
