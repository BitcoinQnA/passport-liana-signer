// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Liana Signer — a policy-aware signer for Liana-shaped Miniscript policies.
//!
//! Passport is NOT the wallet: Liana desktop builds the PSBT. This app
//! registers the policy, matches a PSBT against it, shows the active spend
//! branch, and signs only when the PSBT matches and Passport owns a key on
//! that branch. All policy/PSBT/signing logic lives in `src/liana`.

mod liana;
mod master_key;

use std::{
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
};

use gui_permissions::GuiPermissions;
// Bitcoin types used only by the test fixtures (seed_sample / build_owner_psbt).
#[cfg(test)]
use liana::bitcoin::{
    absolute::LockTime, psbt::Input, transaction::Version, Amount, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
};
use liana::{
    bitcoin::{
        bip32::{DerivationPath, Fingerprint, Xpriv, Xpub},
        psbt::Psbt,
        secp256k1::{All, Secp256k1},
        Address, Network,
    },
    descriptor, policy, psbt as lpsbt, signing, store, RegisteredPolicy, SpendPathKind,
};
use slint_keyos_platform::{
    app,
    gui_server_api::navigation::{
        filepicker::{AllowedExtensions, AllowedLocations, Location as PickLocation, SelectFileOptions},
        qrscanner::{ScanQrOptions, ScanQrResult},
    },
    navigation::{open_qr_scanner, select_file},
    slint::{ComponentHandle, ModelRc, VecModel},
    spawn_local, spawn_worker,
};

app!("Liana");

const DEFAULT_NETWORK: Network = Network::Signet;
const MAINNET_ACCOUNT_PATH: &str = "m/48'/0'/0'/2'";
const TEST_ACCOUNT_PATH: &str = "m/48'/1'/0'/2'";
#[cfg(test)]
const RECOVERY_BLOCKS: u32 = 52_560; // ~12 months (test fixtures only)
const GAP: u32 = 100; // address indices to check when matching a PSBT / address
const DATA_SUBDIR: &str = ".passport-liana-signer-keyos";
const MAX_PSBT_BYTES: u64 = 1_048_576;
const MAX_DESCRIPTOR_BYTES: u64 = 131_072;

// File-exchange paths inside DATA_SUBDIR (Liana on the same host reads/writes
// these for the Signet test). No QR: Liana is file-only (no UR/BBQr/scanner).
const IMPORT_DESCRIPTOR_FILE: &str = "import.txt"; // host-bridge descriptor (sim test)
const UNSIGNED_PSBT_FILE: &str = "unsigned.psbt"; // Liana's exported PSBT (base64 or binary)
const SIGNED_PSBT_FILE: &str = "signed.psbt"; // we write base64 for Liana to load
const EXPORT_KEY_FILE: &str = "passport-key.txt"; // key-with-origin for Liana signer import
const VERIFY_ADDRESS_FILE: &str = "verify-address.txt"; // sim bridge for address verification
const EXPORT_DIR: &str = "liana"; // subdir used when the user picks a location root

/// Live app state shared across UI callbacks.
struct AppState {
    secp: Secp256k1<All>,
    seed: [u8; 32],
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
}

/// A PSBT awaiting the user's sign/reject decision, with the policy + match it
/// was reviewed against (so the signing gate is re-checked at approve time).
struct Pending {
    psbt: Psbt,
    policy: RegisteredPolicy,
    matched: lpsbt::MatchResult,
}

fn app_main(_cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    log::info!("Starting Liana Signer");

    let secp = Secp256k1::new();
    let seed = match master_key::app_seed() {
        Ok(seed) => seed,
        Err(_) => {
            show_startup_error(&ui, tr::lookup_id(TrId::ErrorSeedUnavailable));
            ui.run().expect("UI running");
            return;
        }
    };
    let master = master_for_network(&seed, DEFAULT_NETWORK).expect("master xpriv");
    let fp = master.fingerprint(&secp);

    let data_dir = data_dir();
    #[cfg(not(keyos))]
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        log::error!("cannot create data dir {}: {e}", data_dir.display());
    }

    // Load only the policies the user has actually imported (no placeholder seed).
    let policies = load_policies(&data_dir);

    let state = Arc::new(Mutex::new(AppState {
        secp,
        seed,
        fp,
        data_dir,
        policies,
        xpub_network: DEFAULT_NETWORK,
        pending: None,
        pending_import: None,
        last_signed: None,
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
            set_xpub_export(&ui, &state, DEFAULT_NETWORK);
        });
    }

    // -- switch exported key network ---------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_set_xpub_network(move |network| {
            let Some(ui) = weak.upgrade() else { return };
            set_xpub_export(&ui, &state, network_from_label(network.as_str()).unwrap_or(DEFAULT_NETWORK));
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
                key_with_origin(&st.seed, &st.secp, st.fp, st.xpub_network).unwrap_or_else(|_| String::new())
            };
            let cb = ui.global::<Callbacks>();
            cb.set_export_ok(false);
            if key.is_empty() {
                cb.set_export_error(tr::lookup_id(TrId::ErrorXpubDeriveFailed).into());
                return;
            }
            match export_via_picker(EXPORT_KEY_FILE, key.as_bytes()) {
                Ok(dest) => {
                    cb.set_export_error("".into());
                    cb.set_export_done_title(tr::lookup_id(TrId::ExportKeySavedTitle).into());
                    cb.set_export_done_detail(
                        format!("{}\n{}", format_saved_to(&dest), tr::lookup_id(TrId::ExportKeySavedDetail))
                            .into(),
                    );
                    cb.set_export_ok(true);
                }
                Err(e) => {
                    let msg = format!("{e}");
                    // A user cancel is not an error to surface.
                    cb.set_export_error(if msg.contains("cancelled") { "".into() } else { msg.into() });
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
            // present; otherwise open the file picker so the user can choose any
            // .psbt from USB / Airlock / internal. Don't hold the lock across the
            // modal picker.
            let bridge = { sim_bridge_file(&state.lock().unwrap().data_dir, UNSIGNED_PSBT_FILE) };
            let psbt = if let Some(bridge) = bridge {
                match read_psbt_file(&bridge) {
                    Ok(p) => p,
                    Err(e) => {
                        let err = format!("{e}");
                        review_message(&ui, &trfmt(TrId::ErrorReadNamedFile, &[UNSIGNED_PSBT_FILE, &err]));
                        ui.global::<Callbacks>().set_review_ready(true);
                        return;
                    }
                }
            } else {
                match read_psbt_via_picker() {
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
            // Matching derives up to GAP addresses per policy path — seconds of
            // EC work. Show a spinner and run it on a worker thread so the UI stays
            // responsive, then post the result back to the event loop.
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
                    let m = match_owned(&psbt, &policies, fp, GAP);
                    (psbt, m)
                })
                .await;
                let Some(ui) = weak2.upgrade() else { return };
                let (psbt, matched) = res;
                match matched {
                    Ok(Some((reg, m))) => {
                        populate_review(&ui, &reg, &psbt, &m);
                        state2.lock().unwrap().pending = Some(Pending { psbt, policy: reg, matched: m });
                        set_status(&ui, tr::lookup_id(TrId::StatusLoadedPsbt));
                    }
                    Ok(None) => review_message(&ui, tr::lookup_id(TrId::ReviewNoMatch)),
                    Err(e) => review_message(&ui, &trfmt(TrId::ErrorMatchFailed, &[&format!("{e}")])),
                }
                ui.global::<Callbacks>().set_psbt_loading(false);
            })
            .detach();
        });
    }

    // -- verify address: scan a QR (or read the sim bridge file) and check
    //    whether the address is derived from the registered policy -----------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_verify_address(move |_id| {
            let Some(ui) = weak.upgrade() else { return };
            // Gate navigation: the Verify screen only opens when a code was
            // actually scanned, so cancelling the scan stays put (no stale result).
            clear_verify(&ui);
            // Snapshot every policy's descriptor + name, then DROP the lock
            // before any modal scan.
            let (policies, bridge) = {
                let st = state.lock().unwrap();
                let ps: Vec<(String, String, Network)> = st
                    .policies
                    .all()
                    .iter()
                    .filter(|r| policy_is_signable(r))
                    .map(|r| {
                        (
                            r.descriptor.clone(),
                            r.name.clone(),
                            network_from_policy(r).unwrap_or(DEFAULT_NETWORK),
                        )
                    })
                    .collect();
                (ps, sim_bridge_file(&st.data_dir, VERIFY_ADDRESS_FILE))
            };

            // Sim bridge: a verify-address.txt in the data folder wins; else scan a QR.
            let scanned = if let Some(bridge) = bridge {
                read_text_path_limited(&bridge, MAX_DESCRIPTOR_BYTES, "address")
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                scan_address_qr()
            };
            let Some(raw) = scanned.filter(|s| !s.is_empty()) else {
                set_status(&ui, tr::lookup_id(TrId::StatusAddressScanCancelled));
                return;
            };
            let addr = normalize_address(&raw);

            // Check the address against every registered wallet; report which.
            let hit = policies.iter().find_map(|(desc, name, network)| {
                verify_address_in_policy(desc, &addr, *network).map(|(k, i)| (name, k, i))
            });

            let cb = ui.global::<Callbacks>();
            cb.set_verify_ready(true);
            cb.set_verify_addr(addr.clone().into());
            match hit {
                Some((name, kind, index)) => {
                    cb.set_verify_matched(true);
                    cb.set_verify_title(tr::lookup_id(TrId::VerifySuccessTitle).into());
                    let kind = match kind.as_str() {
                        "change" => tr::lookup_id(TrId::VerifyChangeKind).to_string(),
                        _ => tr::lookup_id(TrId::VerifyReceiveKind).to_string(),
                    };
                    cb.set_verify_detail(
                        trfmt(TrId::VerifySuccessDetail, &[name, &kind, &index.to_string()]).into(),
                    );
                }
                None => {
                    cb.set_verify_matched(false);
                    cb.set_verify_title(tr::lookup_id(TrId::VerifyNotRegisteredTitle).into());
                    cb.set_verify_detail(tr::lookup_id(TrId::VerifyNotRegisteredDetail).into());
                }
            }
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
                let still_signable = st
                    .policies
                    .find_by_checksum(&pending.policy.descriptor_checksum)
                    .map(policy_is_signable)
                    .unwrap_or(false);
                if !still_signable {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(&ui, tr::lookup_id(TrId::ErrorPolicyNotFound));
                    return;
                }
                if let signing::SignDecision::Refuse(reason) =
                    signing::decide(&pending.matched, &pending.policy)
                {
                    ui.global::<Callbacks>().set_signing(false);
                    set_status(&ui, &trfmt(TrId::ErrorRefused, &[&reason]));
                    return;
                }
                let network = network_from_policy(&pending.policy).unwrap_or(DEFAULT_NETWORK);
                let master = match master_for_network(&st.seed, network) {
                    Ok(master) => master,
                    Err(e) => {
                        ui.global::<Callbacks>().set_signing(false);
                        set_status(&ui, &trfmt(TrId::ErrorSigningRefused, &[&format!("{e}")]));
                        return;
                    }
                };
                // Sign only — Liana (the coordinator) combines + finalizes.
                match signing::sign(pending.psbt, &master, &st.secp) {
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

            if signed_bytes.is_some() {
                // Clear, in-screen success — no auto file-picker (the user can
                // choose to save to a device location via "Save to file…").
                let cb = ui.global::<Callbacks>();
                cb.set_signing(false);
                cb.set_review_signed(true);
                cb.set_review_saved(false);
                cb.set_review_signed_detail(tr::lookup_id(TrId::ReviewSignedDetail).into());
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
            // Liana imports a PSBT file as TEXT (base64), so export base64, not
            // the raw binary serialization (binary fails Liana's UTF-8 read).
            let b64 = {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(&bytes)
            };
            // Save to a chosen location via the picker. On success route to the
            // shared full-screen success; on failure surface the reason inline.
            match export_via_picker(&filename, b64.as_bytes()) {
                Ok(dest) => {
                    cb.set_review_saved(true);
                    cb.set_review_signed_detail("".into());
                    cb.set_export_done_title(tr::lookup_id(TrId::ExportTransactionSignedTitle).into());
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
            let bridge = {
                let st = state.lock().unwrap();
                sim_bridge_file(&st.data_dir, IMPORT_DESCRIPTOR_FILE)
            };
            {
                let cb = ui.global::<Callbacks>();
                cb.set_import_error("".into());
                cb.set_import_committed(false);
            }
            let text = if let Some(bridge) = bridge {
                match read_text_path_limited(&bridge, MAX_DESCRIPTOR_BYTES, "descriptor") {
                    Ok(t) => t,
                    Err(e) => {
                        ui.global::<Callbacks>()
                            .set_import_error(trfmt(TrId::ErrorReadFile, &[&format!("{e}")]).into());
                        return;
                    }
                }
            } else {
                match import_via_picker() {
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
                match register_descriptor(&text, st.fp) {
                    Ok(reg) => {
                        if st.policies.find_by_checksum(&reg.descriptor_checksum).is_some() {
                            Err(trfmt(TrId::ImportErrorDuplicate, &[&reg.descriptor_checksum]))
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
                    cb.set_import_name(tr::lookup_id(TrId::ImportDefaultWalletName).into());
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
            let chosen = ui.global::<Callbacks>().get_import_name().trim().to_string();
            let result = {
                let mut st = state.lock().unwrap();
                match st.pending_import.take() {
                    Some(mut reg) => {
                        if !chosen.is_empty() {
                            reg.name = chosen;
                        }
                        match save_policy(&st.data_dir, &reg) {
                            Ok(()) => {
                                st.policies.add(reg.clone()).map(|_| reg).map_err(|e| anyhow::anyhow!("{e}"))
                            }
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
        });
    }

    // -- archive / restore policy (reversible) ------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_archive_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let result = {
                let mut st = state.lock().unwrap();
                let dir = st.data_dir.clone();
                if let Some(updated) = st.policies.set_archived(id.as_str(), true) {
                    save_policy(&dir, &updated)
                } else {
                    Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorPolicyNotFound)))
                }
            };
            match result {
                Ok(()) => {
                    refresh_home(&ui, &state);
                    set_status(&ui, &trfmt(TrId::StatusArchivedPolicy, &[id.as_str()]));
                }
                Err(e) => set_status(&ui, &format!("{e}")),
            }
        });
    }
    // -- rename policy ------------------------------------------------------
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_rename_policy(move |id, name| {
            let Some(ui) = weak.upgrade() else { return };
            let name = name.trim().to_string();
            if !name.is_empty() {
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
    {
        let state = state.clone();
        let weak = ui.as_weak();
        ui.global::<Callbacks>().on_restore_policy(move |id| {
            let Some(ui) = weak.upgrade() else { return };
            let result = {
                let mut st = state.lock().unwrap();
                let dir = st.data_dir.clone();
                if let Some(updated) = st.policies.set_archived(id.as_str(), false) {
                    save_policy(&dir, &updated)
                } else {
                    Err(anyhow::anyhow!(tr::lookup_id(TrId::ErrorPolicyNotFound)))
                }
            };
            match result {
                Ok(()) => {
                    refresh_home(&ui, &state);
                    set_status(&ui, &trfmt(TrId::StatusRestoredPolicy, &[id.as_str()]));
                }
                Err(e) => set_status(&ui, &format!("{e}")),
            }
        });
    }

    // -- delete policy (permanent, from the archive): store + disk ----------
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
                        (reg.descriptor.clone(), st.data_dir.join(&filename), filename)
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
            match export_via_picker(&filename, descriptor.as_bytes()) {
                Ok(dest) => {
                    cb.set_export_error("".into());
                    cb.set_export_done_title(tr::lookup_id(TrId::ExportDescriptorSavedTitle).into());
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
                    cb.set_export_error(if msg.contains("cancelled") { "".into() } else { msg.into() });
                }
            }
        });
    }

    ui.run().expect("UI running");
}

// ---------------------------------------------------------------------------
// UI population
// ---------------------------------------------------------------------------

fn policy_row(p: &RegisteredPolicy) -> PolicyRow {
    let network = network_from_policy(p).map(network_display).unwrap_or(p.network.as_str());
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
    // Active policies drive the home list; archived ones live in the archive.
    let active: Vec<PolicyRow> = st.policies.all().iter().filter(|p| !p.archived).map(policy_row).collect();
    let archived: Vec<PolicyRow> = st.policies.all().iter().filter(|p| p.archived).map(policy_row).collect();
    let cb = ui.global::<Callbacks>();
    cb.set_policy_count(active.len() as i32);
    cb.set_archived_count(archived.len() as i32);
    cb.set_policies(ModelRc::new(VecModel::from(active)));
    cb.set_archived_policies(ModelRc::new(VecModel::from(archived)));
}

fn populate_detail(ui: &AppWindow, reg: &RegisteredPolicy) {
    let cb = ui.global::<Callbacks>();
    cb.set_detail_id(reg.descriptor_checksum.clone().into());
    cb.set_detail_name(reg.name.clone().into());
    // Keep the rename field in sync with the selected policy's current name.
    cb.set_rename_value(reg.name.clone().into());
    cb.set_detail_checksum(format!("#{}", reg.descriptor_checksum).into());
    cb.set_detail_network(
        network_from_policy(reg).map(network_display).unwrap_or(reg.network.as_str()).into(),
    );
    cb.set_detail_descriptor(reg.descriptor.clone().into());
    cb.set_detail_archived(reg.archived);

    // Number recovery tiers when there is more than one (a decaying policy), so
    // "Recovery path 1 / 2 / 3" disambiguate the cards; a lone recovery stays
    // just "Recovery path".
    let recovery_total = reg.paths.iter().filter(|p| matches!(p.kind, SpendPathKind::Recovery)).count();
    let mut recovery_seen = 0usize;
    let mut paths: Vec<PathRow> = Vec::with_capacity(reg.paths.len());
    for p in &reg.paths {
        let is_recovery = matches!(p.kind, SpendPathKind::Recovery);
        // Does Passport own a key on this path?
        let owned = p
            .signer_fingerprints
            .iter()
            .any(|fp| reg.signers.iter().any(|s| &s.fingerprint == fp && s.owned_by_passport));
        // Natural phrasing, avoiding "1 key(s)". Singular keys get "the key";
        // all-of-N gets "all N keys"; thresholds get "M of N keys".
        let who = if p.total_keys == 1 {
            tr::lookup_id(TrId::PathTheKey).to_string()
        } else if p.threshold == p.total_keys {
            trfmt(TrId::PathAllKeys, &[&p.total_keys.to_string()])
        } else {
            trfmt(TrId::PathThresholdKeys, &[&p.threshold.to_string(), &p.total_keys.to_string()])
        };
        let (headline, detail) = if is_recovery {
            let n = p.relative_timelock_blocks.unwrap_or(0);
            let months = n / 4380;
            let blocks = commas(n);
            let months = months.to_string();
            let sig =
                if owned { tr::lookup_id(TrId::PathThisPassportHoldsOne).to_string() } else { String::new() };
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
    cb.set_review_signed_detail("".into());

    let path_label = match m.active_path {
        Some(SpendPathKind::Primary) => tr::lookup_id(TrId::ReviewPathPrimary).to_string(),
        Some(SpendPathKind::Recovery) => {
            trfmt(TrId::ReviewPathRecovery, &[&m.active_timelock_blocks.unwrap_or(0).to_string()])
        }
        None => tr::lookup_id(TrId::ReviewPathUnknown).to_string(),
    };
    cb.set_review_path_label(path_label.into());

    // Outputs + fee. Build one row per output, flagging the ones that pay back
    // into this wallet (change) vs the ones actually leaving (destinations), so
    // the UI can separate them visually and we can total what's truly sent.
    let out_sum: u64 = psbt.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
    let in_sum: u64 =
        psbt.inputs.iter().filter_map(|i| i.witness_utxo.as_ref().map(|u| u.value.to_sat())).sum();

    let mut rows: Vec<OutputRow> = Vec::new();
    let mut leaving: u64 = 0;
    for o in &psbt.unsigned_tx.output {
        let sats = o.value.to_sat();
        let (address, is_change) = match Address::from_script(&o.script_pubkey, network) {
            Ok(addr) => {
                let a = addr.to_string();
                let change = verify_address_in_policy(&reg.descriptor, &a.to_lowercase(), network).is_some();
                (a, change)
            }
            Err(_) => (tr::lookup_id(TrId::ReviewNonStandardScript).to_string(), false),
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
    cb.set_review_total_out(format!("{} sats", commas(leaving + fee)).into());

    let warning =
        if is_recovery { tr::lookup_id(TrId::ReviewRecoveryWarning).to_string() } else { String::new() };
    cb.set_review_warning(warning.into());

    let status = if !m.matched {
        tr::lookup_id(TrId::ReviewNotPolicy).to_string()
    } else if !m.passport_can_sign {
        tr::lookup_id(TrId::ReviewNoKeyOnPath).to_string()
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
    cb.set_verify_title("".into());
    cb.set_verify_addr("".into());
    cb.set_verify_detail("".into());
}

fn set_status(ui: &AppWindow, msg: &str) { ui.global::<Callbacks>().set_status(msg.to_string().into()); }

fn trfmt(id: TrId, args: &[&str]) -> String {
    let mut text = tr::lookup_id(id).to_string();
    for (idx, arg) in args.iter().enumerate() {
        text = text.replace(&format!("{{{idx}}}"), arg);
    }
    text
}

fn format_saved_to(dest: &str) -> String { format!("{} {dest}", tr::lookup_id(TrId::ExportSavedTo)) }

// ---------------------------------------------------------------------------
// Policy building / persistence
// ---------------------------------------------------------------------------

/// Owned-result PSBT match, for running on a worker thread (no borrows escape).
fn match_owned(
    psbt: &Psbt,
    policies: &[RegisteredPolicy],
    fp: Fingerprint,
    gap: u32,
) -> std::result::Result<Option<(RegisteredPolicy, lpsbt::MatchResult)>, String> {
    match lpsbt::match_against_all(psbt, policies, fp, gap) {
        Ok(Some((p, m))) => Ok(Some((p.clone(), m))),
        Ok(None) => Ok(None),
        Err(e) => Err(format!("{e}")),
    }
}

fn master_for_network(seed: &[u8; 32], network: Network) -> anyhow::Result<Xpriv> {
    Xpriv::new_master(network, seed).map_err(|e| anyhow::anyhow!("master xpriv: {e}"))
}

fn account_path(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => MAINNET_ACCOUNT_PATH,
        _ => TEST_ACCOUNT_PATH,
    }
}

fn account_xpub(seed: &[u8; 32], secp: &Secp256k1<All>, network: Network) -> anyhow::Result<Xpub> {
    let master = master_for_network(seed, network)?;
    let acct = DerivationPath::from_str(account_path(network))?;
    Ok(Xpub::from_priv(secp, &master.derive_priv(secp, &acct)?))
}

fn key_with_origin(
    seed: &[u8; 32],
    secp: &Secp256k1<All>,
    fp: Fingerprint,
    network: Network,
) -> anyhow::Result<String> {
    let path = account_path(network);
    let xpub = account_xpub(seed, secp, network)?;
    Ok(format!("[{}/{}]{}", fp, path.trim_start_matches("m/"), xpub))
}

fn set_xpub_export(ui: &AppWindow, state: &Arc<Mutex<AppState>>, network: Network) {
    let result = {
        let mut st = state.lock().unwrap();
        st.xpub_network = network;
        key_with_origin(&st.seed, &st.secp, st.fp, network).map(|key| {
            let path = account_path(network).to_string();
            let fp = st.fp.to_string();
            write_bridge_file(&st.data_dir, EXPORT_KEY_FILE, key.as_bytes());
            (key, path, fp)
        })
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

fn is_public_network(network: Network) -> bool { matches!(network, Network::Bitcoin | Network::Signet) }

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

fn network_from_descriptor(descriptor: &str) -> Network {
    if descriptor.contains("xpub") || descriptor.contains("ypub") || descriptor.contains("zpub") {
        Network::Bitcoin
    } else {
        // Liana's signet/testnet exports use testnet-style extended keys. The
        // app defaults those to Signet because this companion flow is tested
        // there and signet/testnet addresses share the `tb` human prefix.
        Network::Signet
    }
}

fn register_descriptor(text: &str, passport_fp: Fingerprint) -> anyhow::Result<RegisteredPolicy> {
    let parsed = descriptor::import(text).map_err(|e| anyhow::anyhow!("{e}"))?;
    let id = parsed.checksum.clone();
    let network = network_from_descriptor(&parsed.canonical);
    let reg =
        policy::build_registered_policy(id, "Imported policy", network_label(network), &parsed, passport_fp)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    if !reg.signers.iter().any(|s| s.owned_by_passport) {
        anyhow::bail!("{}", tr::lookup_id(TrId::ImportErrorNoPassportKey));
    }
    Ok(reg)
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
fn sample_descriptor(secp: &Secp256k1<All>, device_account_xpub: &Xpub, device_fp: Fingerprint) -> String {
    let rec_master = Xpriv::new_master(DEFAULT_NETWORK, &[0x22; 32]).unwrap();
    let rec_fp = rec_master.fingerprint(secp);
    let acct = DerivationPath::from_str(TEST_ACCOUNT_PATH).unwrap();
    let rec_xpub = Xpub::from_priv(secp, &rec_master.derive_priv(secp, &acct).unwrap());
    let p = TEST_ACCOUNT_PATH.trim_start_matches("m/");
    format!(
        "wsh(or_d(pk([{device_fp}/{p}]{device_account_xpub}/<0;1>/*),and_v(v:pkh([{rec_fp}/{p}]{rec_xpub}/<0;1>/*),older({RECOVERY_BLOCKS}))))"
    )
}

/// Build a demo owner-path PSBT spending the policy's index-0 output (test only).
#[cfg(test)]
fn build_owner_psbt(
    secp: &Secp256k1<All>,
    reg: &RegisteredPolicy,
    device_account_xpub: &Xpub,
    device_fp: Fingerprint,
) -> anyhow::Result<Psbt> {
    let parsed = descriptor::import(&reg.descriptor).map_err(|e| anyhow::anyhow!("{e}"))?;
    let singles = parsed.descriptor.into_single_descriptors().map_err(|e| anyhow::anyhow!("{e}"))?;
    let def = singles[0].at_derivation_index(0).map_err(|e| anyhow::anyhow!("{e}"))?;
    let spk = def.script_pubkey();
    let ws = def.explicit_script().map_err(|e| anyhow::anyhow!("{e}"))?;

    let child = DerivationPath::from_str("m/0/0").unwrap();
    let dev_pk = PublicKey::new(device_account_xpub.derive_pub(secp, &child)?.public_key);
    let full = DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap();

    let value = Amount::from_sat(100_000);
    let prevout = OutPoint {
        txid: Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
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
            script_pubkey: ScriptBuf::from_hex("0014000000000000000000000000000000000000dead").unwrap(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut input = Input {
        witness_utxo: Some(TxOut { value, script_pubkey: spk }),
        witness_script: Some(ws),
        ..Default::default()
    };
    input.bip32_derivation.insert(dev_pk.inner, (device_fp, full));
    psbt.inputs[0] = input;
    Ok(psbt)
}

fn policy_summary(p: &RegisteredPolicy) -> String {
    let network = network_from_policy(p).map(network_display).unwrap_or(p.network.as_str());
    let recovery = p
        .paths
        .iter()
        .find(|x| matches!(x.kind, SpendPathKind::Recovery))
        .and_then(|x| x.relative_timelock_blocks);
    match recovery {
        Some(n) => trfmt(TrId::SummaryRecoveryAfterMonths, &[network, &(n / 4380).to_string()]),
        None => trfmt(TrId::SummarySinglePath, &[network]),
    }
}

fn policy_is_signable(policy: &RegisteredPolicy) -> bool {
    !policy.archived && network_from_policy(policy).map(is_public_network).unwrap_or(false)
}

fn signable_policies(store: &store::PolicyStore) -> Vec<RegisteredPolicy> {
    store.all().iter().filter(|p| policy_is_signable(p)).cloned().collect()
}

fn load_policies(dir: &Path) -> store::PolicyStore { load_policies_impl(dir) }

#[cfg(not(keyos))]
fn load_policies_impl(dir: &Path) -> store::PolicyStore {
    let mut s = store::PolicyStore::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return s };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(reg) = store::from_json(&text) {
                let _ = s.add(reg);
            }
        }
    }
    s
}

#[cfg(keyos)]
fn load_policies_impl(_dir: &Path) -> store::PolicyStore {
    let fs = FileSystem::default();
    let mut s = store::PolicyStore::new();
    let Ok(dir) = fs.open_dir("", fs::Location::AppData) else { return s };
    while let Ok(Some(entry)) = dir.next_entry() {
        if !entry.name.starts_with("policy_") || !entry.name.ends_with(".json") || entry.is_dir {
            continue;
        }
        let Ok(text) =
            read_text_fs_limited(&fs, &entry.name, fs::Location::AppData, MAX_DESCRIPTOR_BYTES, "policy")
        else {
            continue;
        };
        if let Ok(reg) = store::from_json(&text) {
            let _ = s.add(reg);
        }
    }
    s
}

fn save_policy(dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> { save_policy_impl(dir, reg) }

#[cfg(not(keyos))]
fn save_policy_impl(dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> {
    let json = store::to_json(reg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = dir.join(format!("policy_{}.json", reg.descriptor_checksum));
    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(keyos)]
fn save_policy_impl(_dir: &Path, reg: &RegisteredPolicy) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let json = store::to_json(reg).map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = format!("policy_{}.json", reg.descriptor_checksum);
    let mut fs = FileSystem::default();
    {
        let mut file = fs
            .open_file(&path, fs::Location::AppData, fs::OpenFlags { read: true, write: true, create: true })
            .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(json.as_bytes())?;
        file.truncate().map_err(|e| anyhow::anyhow!("truncate {path}: {e:?}"))?;
        file.flush()?;
    }
    fs.flush(fs::Location::AppData).map_err(|e| anyhow::anyhow!("flush app data: {e:?}"))?;
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

#[cfg(all(not(keyos), feature = "sim-bridge"))]
fn sim_bridge_file(dir: &Path, filename: &str) -> Option<PathBuf> {
    let path = dir.join(filename);
    path.exists().then_some(path)
}

#[cfg(any(keyos, not(feature = "sim-bridge")))]
fn sim_bridge_file(_dir: &Path, _filename: &str) -> Option<PathBuf> { None }

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
    cb.set_archived_count(0);
    cb.set_import_error(msg.into());
}

/// Open the QR scanner overlay and return the scanned text (address / BIP21 URI).
fn scan_address_qr() -> Option<String> {
    match open_qr_scanner::<GuiPermissions>(ScanQrOptions::new()) {
        Ok(Some(ScanQrResult::Qr { data, .. })) => String::from_utf8(data).ok(),
        _ => None, // cancelled, UR payload, or error
    }
}

/// Normalize a scanned address: strip a `bitcoin:` URI prefix + query params,
/// lowercase (bech32 is case-insensitive; derived addresses are lowercase).
fn normalize_address(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("bitcoin:").or_else(|| s.strip_prefix("BITCOIN:")).unwrap_or(s);
    s.split('?').next().unwrap_or(s).trim().to_lowercase()
}

fn read_bytes_path_limited(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        anyhow::bail!("{label} file is too large ({} bytes, max {max_bytes})", meta.len());
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} file is too large (max {max_bytes})");
    }
    Ok(bytes)
}

fn read_text_path_limited(path: &Path, max_bytes: u64, label: &str) -> anyhow::Result<String> {
    Ok(String::from_utf8(read_bytes_path_limited(path, max_bytes, label)?)
        .map_err(|_| anyhow::anyhow!("{label} file is not valid UTF-8"))?)
}

fn read_bytes_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<Vec<u8>> {
    let meta = filesystem.metadata(path, location).map_err(|e| anyhow::anyhow!("metadata {path}: {e:?}"))?;
    if meta.size > max_bytes {
        anyhow::bail!("{label} file is too large ({} bytes, max {max_bytes})", meta.size);
    }
    let file = filesystem
        .open_file(path, location, fs::OpenFlags { read: true, write: false, create: false })
        .map_err(|e| anyhow::anyhow!("open {path}: {e:?}"))?;
    let mut bytes = Vec::with_capacity(meta.size as usize);
    file.take(max_bytes + 1).read_to_end(&mut bytes).map_err(|e| anyhow::anyhow!("read {path}: {e:?}"))?;
    if bytes.len() as u64 > max_bytes {
        anyhow::bail!("{label} file is too large (max {max_bytes})");
    }
    Ok(bytes)
}

fn read_text_fs_limited(
    filesystem: &FileSystem,
    path: &str,
    location: fs::Location,
    max_bytes: u64,
    label: &str,
) -> anyhow::Result<String> {
    Ok(String::from_utf8(read_bytes_fs_limited(filesystem, path, location, max_bytes, label)?)
        .map_err(|_| anyhow::anyhow!("{label} file is not valid UTF-8"))?)
}

/// Is `target` an address derived from this policy's descriptor? Returns the
/// path ("receive"/"change") and derivation index if found.
fn verify_address_in_policy(descriptor_str: &str, target: &str, network: Network) -> Option<(String, u32)> {
    let parsed = descriptor::import(descriptor_str).ok()?;
    let singles = parsed.descriptor.into_single_descriptors().ok()?;
    for (si, single) in singles.iter().enumerate() {
        for idx in 0..GAP {
            if let Ok(def) = single.at_derivation_index(idx) {
                if let Ok(addr) = def.address(network) {
                    if addr.to_string().to_lowercase() == target {
                        let kind = if si == 0 { "receive" } else { "change" };
                        return Some((kind.to_string(), idx));
                    }
                }
            }
        }
    }
    None
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

/// Open the file picker (any `.psbt` on USB / Airlock / internal), read it, and
/// parse the PSBT. This is the device path for loading a transaction to sign.
fn read_psbt_via_picker() -> anyhow::Result<Psbt> {
    let options = SelectFileOptions::default()
        .with_allowed_locations(AllowedLocations::All)
        .with_allowed_extensions(AllowedExtensions::specific(["psbt"]));
    let result =
        select_file::<GuiPermissions>(options).map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((path, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no file selected");
    };
    let filesystem = FileSystem::default();
    let location = map_location(loc);
    let bytes = read_bytes_fs_limited(&filesystem, &path, location, MAX_PSBT_BYTES, "PSBT")?;
    parse_psbt_bytes(&bytes)
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
/// file -> `FileSystem::flush` (which flushes the block cache to the medium).
///
/// The directory-entry flush on close is the critical step (see SFT-7122): in
/// rust-fatfs the FAT and data bytes hit the block cache during the write, but the
/// directory entry only persists on `File::flush` / close. A bare
/// `FileSystem::flush` on a still-open file leaves a stale entry and a torn image.
fn write_export(filename: &str, bytes: &[u8], location: fs::Location, dir: &str) -> anyhow::Result<String> {
    use std::io::Write;
    let mut filesystem = FileSystem::default();
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
    let unique =
        directory.pick_next_filename(filename, None).map_err(|e| anyhow::anyhow!("pick filename: {e:?}"))?;
    let path = format!("{dir}/{unique}");
    {
        let mut file = filesystem
            .open_file(path.clone(), location, fs::OpenFlags { read: false, write: true, create: true })
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
        file.flush().map_err(|e| anyhow::anyhow!("flush {path}: {e:?}"))?;
    } // drop file -> CloseFile (re-commits the directory entry)
    drop(directory); // CloseDir
    filesystem.flush(location).map_err(|e| anyhow::anyhow!("flush fs: {e:?}"))?;
    Ok(format!("{}{}", loc_label(location), path))
}

/// Open the folder picker and write `filename` into the chosen folder/location
/// (SD, USB, internal, or Airlock), using the close-before-flush sequence above.
fn export_via_picker(filename: &str, bytes: &[u8]) -> anyhow::Result<String> {
    let options = SelectFileOptions::default()
        .with_dir_selection_mode(true)
        .with_allowed_locations(AllowedLocations::All);
    let result =
        select_file::<GuiPermissions>(options).map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((dir, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no folder selected");
    };
    let dir = dir.trim_end_matches('/').to_string();
    // Picking a location root gives an empty path; tuck files into a `liana/` subdir.
    let dir = if dir.is_empty() { EXPORT_DIR.to_string() } else { dir };
    write_export(filename, bytes, map_location(loc), &dir)
}

fn loc_label(loc: fs::Location) -> &'static str {
    match loc {
        fs::Location::Usb => "usb:/",
        fs::Location::Airlock => "airlock:/",
        fs::Location::User => "user:/",
        _ => "",
    }
}

/// Open the file picker (file-selection mode), read the chosen file, and return
/// its text contents. Used to import a Liana descriptor.
fn import_via_picker() -> anyhow::Result<String> {
    let options = SelectFileOptions::default().with_allowed_locations(AllowedLocations::All);
    let result =
        select_file::<GuiPermissions>(options).map_err(|e| anyhow::anyhow!("picker error: {e:?}"))?;
    let Some(result) = result else {
        anyhow::bail!("cancelled");
    };
    let Some((path, loc)) = result.files().first().cloned() else {
        anyhow::bail!("no file selected");
    };
    let filesystem = FileSystem::default();
    read_text_fs_limited(&filesystem, &path, map_location(loc), MAX_DESCRIPTOR_BYTES, "descriptor")
}

fn map_location(loc: PickLocation) -> fs::Location {
    match loc {
        PickLocation::Internal => fs::Location::User,
        PickLocation::Airlock => fs::Location::Airlock,
        PickLocation::External => fs::Location::Usb,
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

    fn device() -> (Secp256k1<All>, Xpub, Fingerprint) {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(DEFAULT_NETWORK, &[0x11; 32]).unwrap();
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
        assert_eq!(parsed.checksum, "9xtyycfv", "our checksum must match Liana's");
        let fp = Fingerprint::from_str("22663c8a").unwrap();
        let reg = policy::build_registered_policy("real", "Real", "signet", &parsed, fp).unwrap();
        assert_eq!(reg.paths.len(), 2);
        let recovery = reg.paths.iter().find(|p| matches!(p.kind, SpendPathKind::Recovery)).unwrap();
        assert_eq!(recovery.relative_timelock_blocks, Some(52596));
        assert!(reg.signers.iter().all(|s| s.fingerprint == "22663c8a" && s.owned_by_passport));
    }

    #[test]
    fn sample_descriptor_is_valid_liana_p2wsh() {
        let (secp, xpub, fp) = device();
        let desc = sample_descriptor(&secp, &xpub, fp);
        assert!(desc.starts_with("wsh("));
        let parsed = descriptor::import(&desc).expect("imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| matches!(p.kind, SpendPathKind::Primary)));
        let rec = paths.iter().find(|p| matches!(p.kind, SpendPathKind::Recovery)).unwrap();
        assert_eq!(rec.relative_timelock_blocks, Some(RECOVERY_BLOCKS));
    }

    // A key-with-origin string (`[fp/path]xpub`) from a deterministic seed, for
    // building descriptors in tests without hardcoding xpubs.
    fn test_key(seed: u8) -> String {
        let secp = Secp256k1::new();
        let m = Xpriv::new_master(DEFAULT_NETWORK, &[seed; 32]).unwrap();
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

    // A decaying policy (primary + two recovery tiers at different timelocks)
    // must flatten into three distinct spend paths, not merge the nested
    // recovery branches into one.
    #[test]
    fn decaying_policy_flattens_into_distinct_tiers() {
        let (a, b, c) = (test_key(0x21), test_key(0x22), test_key(0x23));
        let desc = format!(
            "wsh(or_d(pk({a}/<0;1>/*),or_i(and_v(v:pkh({b}/<0;1>/*),older(1000)),and_v(v:pkh({c}/<0;1>/*),older(2000)))))"
        );
        let parsed = descriptor::import(&desc).expect("decaying descriptor imports");
        let paths = policy::analyze_paths(&parsed.descriptor).expect("analyze");
        assert_eq!(paths.len(), 3, "primary + 2 recovery tiers");
        assert_eq!(paths.iter().filter(|p| matches!(p.kind, SpendPathKind::Primary)).count(), 1);
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
        let desc = format!("tr({a}/<0;1>/*,and_v(v:pk({b}/<0;1>/*),older(4032)))");
        let err = import_error(&desc);
        assert!(err.contains("Taproot"), "got: {err}");
    }

    #[test]
    fn absolute_timelock_descriptor_is_rejected_for_now() {
        let a = test_key(0x33);
        let desc = format!("wsh(and_v(v:pk({a}/<0;1>/*),after(100)))");
        let err = import_error(&desc);
        assert!(err.contains("absolute locktimes"), "got: {err}");
    }

    #[test]
    fn time_based_csv_descriptor_is_rejected_for_now() {
        let (a, b) = (test_key(0x34), test_key(0x35));
        let time_based_csv = (1 << 22) + 144;
        let desc = format!("wsh(or_d(pk({a}/<0;1>/*),and_v(v:pkh({b}/<0;1>/*),older({time_based_csv}))))");
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
        assert!(reg.signers.iter().any(|s| s.fingerprint == fp.to_string() && s.owned_by_passport));
    }

    #[test]
    fn owner_psbt_matches_and_signs_with_device_key() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");

        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).expect("match");
        assert!(m.matched, "demo PSBT must match the seeded policy");
        assert_eq!(m.active_path, Some(SpendPathKind::Primary));
        assert!(m.passport_can_sign);

        // The decision gate must allow, and signing must finalize.
        assert!(matches!(
            signing::decide(&m, &reg),
            signing::SignDecision::Allow { path: SpendPathKind::Primary, .. }
        ));
        let master = Xpriv::new_master(DEFAULT_NETWORK, &[0x11; 32]).unwrap();
        let finalized = signing::sign_and_finalize(psbt, &master, &secp).expect("sign");
        assert!(finalized.inputs[0].final_script_witness.is_some());
    }

    #[test]
    fn psbt_with_outputs_exceeding_inputs_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.unsigned_tx.output[0].value = Amount::from_sat(110_000);

        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).expect("match");
        assert!(m.matched, "the script still belongs to the registered policy");
        assert!(!m.passport_can_sign, "invalid amounts must block signing");
        assert!(m.reasons.iter().any(|r| r.contains("outputs exceed verified inputs")));
        assert!(matches!(signing::decide(&m, &reg), signing::SignDecision::Refuse(_)));
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

        let err = lpsbt::match_against_all(&psbt, &policies, fp, GAP).unwrap_err().to_string();
        assert!(err.contains("more than one registered policy"), "got: {err}");
    }

    #[test]
    fn psbt_with_unsafe_sighash_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::Single.into());

        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).expect("match");
        assert!(m.matched, "the script still belongs to the registered policy");
        assert!(!m.passport_can_sign, "unsafe sighash must block signing");
        assert!(m.reasons.iter().any(|r| r.contains("unsupported sighash")), "{:?}", m.reasons);
    }

    #[test]
    fn psbt_with_mismatched_witness_script_is_not_signable() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.inputs[0].witness_script = Some(ScriptBuf::from_hex("51").unwrap());

        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).expect("match");
        assert!(m.matched, "the scriptPubKey still belongs to the registered policy");
        assert!(!m.passport_can_sign, "mismatched witness_script must block signing");
        assert!(m.reasons.iter().any(|r| r.contains("witness_script")), "{:?}", m.reasons);
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

        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).expect("match");
        assert!(m.matched, "the witness_utxo still belongs to the registered policy");
        assert!(!m.passport_can_sign, "inconsistent non_witness_utxo must block signing");
        assert!(m.reasons.iter().any(|r| r.contains("non_witness_utxo")), "{:?}", m.reasons);
    }

    #[test]
    fn recovery_spend_requires_bip68_transaction_version() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let mut psbt = build_owner_psbt(&secp, &reg, &xpub, fp).expect("psbt");
        psbt.unsigned_tx.version = Version::ONE;
        psbt.unsigned_tx.input[0].sequence = Sequence::from_height(RECOVERY_BLOCKS as u16);

        let m = lpsbt::match_psbt(&psbt, &reg, fp, GAP).expect("match");
        assert!(m.matched, "the input still belongs to the registered policy");
        assert!(!m.passport_can_sign, "BIP68-disabled recovery spend must block signing");
        assert!(m.reasons.iter().any(|r| r.contains("version 2")), "{:?}", m.reasons);
    }

    #[test]
    fn register_descriptor_rejects_garbage() {
        let (_, _, fp) = device();
        assert!(register_descriptor("definitely not a descriptor", fp).is_err());
    }

    #[test]
    fn register_descriptor_rejects_policy_without_passport_key() {
        let (secp, xpub, fp) = device();
        let desc = sample_descriptor(&secp, &xpub, fp);
        let wrong_fp = Fingerprint::from_str("deadbeef").unwrap();
        let err = register_descriptor(&desc, wrong_fp).unwrap_err().to_string();
        assert!(err.contains("does not contain this Passport"), "got: {err}");
    }

    #[test]
    fn save_then_load_roundtrips() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();

        let dir = std::env::temp_dir().join("liana-signer-test-store");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        save_policy(&dir, &reg).expect("save");
        let store = load_policies(&dir);
        assert_eq!(store.len(), 1);
        assert!(store.find_by_checksum(&reg.descriptor_checksum).is_some());

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
        unsupported.network = "testnet".into();

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
    fn policy_summary_mentions_recovery_months() {
        let (secp, xpub, fp) = device();
        let reg = seed_sample(&secp, &xpub, fp).unwrap();
        let summary = policy_summary(&reg);
        assert!(summary.contains("recovery"), "got: {summary}");
        assert!(summary.contains("months"), "got: {summary}");
    }
}
