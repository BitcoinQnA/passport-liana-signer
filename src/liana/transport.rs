// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Foundation's versioned Passport/Liana air-gap protocol.

use std::{collections::HashSet, str::FromStr};

use minicbor::{data::Tag, Encoder};
use serde::{Deserialize, Serialize};

use super::{
    bitcoin::{
        bip32::{Fingerprint, Xpub},
        hashes::{sha256, Hash},
        Network,
    },
    descriptor,
    miniscript::Descriptor,
    miniscript::DescriptorPublicKey,
    Error, RegisteredPolicy, Result, POLICY_SCHEMA_VERSION,
};

pub const POLICY_FORMAT: &str = "passport-wallet-policy";
pub const ADDRESS_REQUEST_FORMAT: &str = "passport-address-verification";
pub const ADDRESS_RESPONSE_FORMAT: &str = "passport-address-verification-response";
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_REGISTRY_CBOR_BYTES: usize = 24 * 1024;
pub const MAX_JSON_BYTES: usize = 4_096;
pub const MAX_JSON_DEPTH: usize = 16;
pub const MAX_DESCRIPTOR_BYTES: usize = 4_096;
pub const MAX_TEMPLATE_BYTES: usize = 2_048;
pub const MAX_KEYS: usize = 20;
pub const MAX_NAME_BYTES: usize = 20;

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyNetwork {
    Btc,
    Tbtc,
}

impl PolicyNetwork {
    pub fn from_network(network: Network) -> Result<Self> {
        match network {
            Network::Bitcoin => Ok(Self::Btc),
            Network::Signet | Network::Testnet | Network::Testnet4 => Ok(Self::Tbtc),
            _ => Err(Error::Unsupported(
                "Liana QR supports Bitcoin mainnet and public test networks only".into(),
            )),
        }
    }

    pub fn bitcoin(self, selected_test_network: Network) -> Network {
        match self {
            Self::Btc => Network::Bitcoin,
            Self::Tbtc => match selected_test_network {
                Network::Signet | Network::Testnet | Network::Testnet4 => selected_test_network,
                _ => Network::Signet,
            },
        }
    }

    fn text(self) -> &'static str {
        match self {
            Self::Btc => "BTC",
            Self::Tbtc => "TBTC",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRegistration {
    pub format: String,
    pub version: u8,
    pub name: String,
    pub network: PolicyNetwork,
    pub template: String,
    pub keys: Vec<String>,
    pub policy_id: String,
}

impl PolicyRegistration {
    pub fn from_json(data: &[u8]) -> Result<Self> {
        let registration: Self = decode_json(data)?;
        registration.validate()?;
        Ok(registration)
    }

    pub fn from_descriptor(name: &str, network: Network, canonical: &str) -> Result<Self> {
        let parsed = descriptor::import(canonical)?;
        let body = parsed
            .canonical
            .rsplit_once('#')
            .map(|(body, _)| body)
            .ok_or_else(|| Error::Parse("descriptor checksum is missing".into()))?;
        let (template, keys) = descriptor_to_template(body)?;
        let name = printable_name(name);
        let mut registration = Self {
            format: POLICY_FORMAT.into(),
            version: PROTOCOL_VERSION,
            name,
            network: PolicyNetwork::from_network(network)?,
            template,
            keys,
            policy_id: String::new(),
        };
        registration.policy_id = registration.calculate_policy_id();
        registration.validate()?;
        Ok(registration)
    }

    pub fn from_registered(policy: &RegisteredPolicy) -> Result<Self> {
        if policy.policy_id.is_empty() || policy.policy_template.is_empty() || policy.policy_keys.is_empty() {
            let network = match policy.network.as_str() {
                "bitcoin" => Network::Bitcoin,
                "signet" => Network::Signet,
                "testnet" => Network::Testnet,
                "testnet4" => Network::Testnet4,
                _ => {
                    return Err(Error::Unsupported(
                        "registered policy is not on a supported Bitcoin network".into(),
                    ))
                }
            };
            return Self::from_descriptor(&policy.name, network, &policy.descriptor);
        }
        let registration = Self {
            format: POLICY_FORMAT.into(),
            version: PROTOCOL_VERSION,
            name: printable_name(&policy.name),
            network: match policy.network.as_str() {
                "bitcoin" => PolicyNetwork::Btc,
                "signet" | "testnet" | "testnet4" => PolicyNetwork::Tbtc,
                _ => {
                    return Err(Error::Unsupported(
                        "registered policy is not on a supported Bitcoin network".into(),
                    ))
                }
            },
            template: policy.policy_template.clone(),
            keys: policy.policy_keys.clone(),
            policy_id: policy.policy_id.clone(),
        };
        registration.validate()?;
        Ok(registration)
    }

    pub fn apply_to(&self, policy: &mut RegisteredPolicy) {
        policy.schema_version = POLICY_SCHEMA_VERSION;
        policy.policy_id = self.policy_id.clone();
        policy.policy_template = self.template.clone();
        policy.policy_keys = self.keys.clone();
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != POLICY_FORMAT || self.version != PROTOCOL_VERSION {
            return Err(Error::Parse("unsupported wallet-policy envelope".into()));
        }
        validate_printable_ascii(&self.name, 1, MAX_NAME_BYTES, "wallet name")?;
        validate_printable_ascii(&self.template, 1, MAX_TEMPLATE_BYTES, "policy template")?;
        if self.template.starts_with("tr(") {
            return Err(Error::Unsupported("Taproot Liana policies remain disabled in this app".into()));
        }
        if !self.template.starts_with("wsh(") || !self.template.ends_with(')') {
            return Err(Error::Unsupported("only top-level P2WSH Liana policies are supported".into()));
        }
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(Error::Parse(format!("policy must contain between 1 and {MAX_KEYS} keys")));
        }
        if placeholder_order(&self.template)? != (0..self.keys.len()).collect::<Vec<_>>() {
            return Err(Error::Parse("policy keys must be used in canonical first-use order".into()));
        }
        let mut unique = HashSet::new();
        for key in &self.keys {
            let parsed = DescriptorPublicKey::from_str(key)
                .map_err(|e| Error::Parse(format!("invalid descriptor key: {e}")))?;
            if parsed.to_string() != *key || !unique.insert(key) {
                return Err(Error::Parse("policy keys must be canonical and unique".into()));
            }
        }
        let full = self.full_descriptor();
        if full.len() > MAX_DESCRIPTOR_BYTES {
            return Err(Error::Parse("descriptor is too large".into()));
        }
        let parsed = Descriptor::<DescriptorPublicKey>::from_str(&full)
            .map_err(|e| Error::Parse(format!("invalid reconstructed descriptor: {e}")))?;
        let canonical = parsed.to_string();
        if canonical.rsplit_once('#').map(|(body, _)| body) != Some(full.as_str()) {
            return Err(Error::Parse("policy descriptor is not canonical".into()));
        }
        descriptor::import(&canonical)?;
        if self.policy_id.len() != 64
            || !self.policy_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.policy_id != self.calculate_policy_id()
        {
            return Err(Error::Parse("policy identity mismatch".into()));
        }
        Ok(())
    }

    pub fn full_descriptor(&self) -> String {
        let mut descriptor = self.template.clone();
        for index in (0..self.keys.len()).rev() {
            descriptor = descriptor.replace(&format!("@{index}"), &self.keys[index]);
        }
        descriptor
    }

    pub fn canonical_descriptor(&self) -> Result<String> {
        self.validate()?;
        Descriptor::<DescriptorPublicKey>::from_str(&self.full_descriptor())
            .map(|descriptor| descriptor.to_string())
            .map_err(|e| Error::Parse(format!("invalid reconstructed descriptor: {e}")))
    }

    pub fn descriptor_checksum(&self) -> Result<String> {
        self.canonical_descriptor()?
            .rsplit_once('#')
            .map(|(_, checksum)| checksum.to_owned())
            .ok_or_else(|| Error::Parse("descriptor checksum is missing".into()))
    }

    pub fn calculate_policy_id(&self) -> String {
        let mut payload = b"Passport Wallet Policy\0".to_vec();
        payload.push(PROTOCOL_VERSION);
        encode_field(&mut payload, self.network.text());
        encode_field(&mut payload, &self.template);
        compact_size(&mut payload, self.keys.len());
        for key in &self.keys {
            encode_field(&mut payload, key);
        }
        sha256::Hash::hash(&payload).to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressVerificationRequest {
    pub format: String,
    pub version: u8,
    pub network: PolicyNetwork,
    pub policy_id: String,
    pub descriptor_checksum: String,
    pub branch: u32,
    pub index: u32,
}

impl AddressVerificationRequest {
    pub fn from_json(data: &[u8]) -> Result<Self> {
        let request: Self = decode_json(data)?;
        if request.format != ADDRESS_REQUEST_FORMAT
            || request.version != PROTOCOL_VERSION
            || request.branch > 1
            || request.index >= (1 << 31)
            || request.descriptor_checksum.len() != 8
            || !request.descriptor_checksum.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || request.policy_id.len() != 64
            || !request.policy_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::Parse("invalid address-verification request".into()));
        }
        Ok(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressVerificationResponse {
    pub format: String,
    pub version: u8,
    pub network: PolicyNetwork,
    pub policy_id: String,
    pub descriptor_checksum: String,
    pub branch: u32,
    pub index: u32,
    pub address: String,
    pub fingerprint: String,
}

impl AddressVerificationResponse {
    pub fn new(request: &AddressVerificationRequest, address: String, fingerprint: Fingerprint) -> Self {
        Self {
            format: ADDRESS_RESPONSE_FORMAT.into(),
            version: PROTOCOL_VERSION,
            network: request.network,
            policy_id: request.policy_id.clone(),
            descriptor_checksum: request.descriptor_checksum.to_ascii_lowercase(),
            branch: request.branch,
            index: request.index,
            address,
            fingerprint: fingerprint.to_string(),
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> { encode_json(self) }
}

/// Encode the narrow legacy `crypto-account` profile shared by Passport Core,
/// Prime's Bitcoin app, and Liana desktop.
pub fn encode_crypto_account(
    fingerprint: Fingerprint,
    parent_fingerprint: Fingerprint,
    xpub: &Xpub,
    network: Network,
    account: u32,
) -> Result<Vec<u8>> {
    if account >= (1 << 31) {
        return Err(Error::Parse("Account is outside the BIP32 range.".into()));
    }
    let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
    let mut output = Vec::with_capacity(160);
    let mut encoder = Encoder::new(&mut output);
    let encoded = (|| -> std::result::Result<(), minicbor::encode::Error<std::convert::Infallible>> {
        encoder
            .map(2)?
            .u32(1)?
            .u32(fingerprint_u32(fingerprint))?
            .u32(2)?
            .array(1)?
            .tag(Tag::new(308))?
            .tag(Tag::new(401))?
            .tag(Tag::new(410))?
            .tag(Tag::new(303))?
            .map(6)?
            .u32(2)?
            .bool(false)?
            .u32(3)?
            .bytes(&xpub.public_key.serialize())?
            .u32(4)?
            .bytes(xpub.chain_code.as_bytes())?
            .u32(5)?
            .tag(Tag::new(40305))?
            .map(2)?
            .u32(1)?
            .u32(0)?
            .u32(2)?
            .u32(if network == Network::Bitcoin { 0 } else { 1 })?
            .u32(6)?
            .tag(Tag::new(40304))?
            .map(3)?
            .u32(1)?
            .array(8)?;
        for component in [48, coin_type, account, 2] {
            encoder.u32(component)?.bool(true)?;
        }
        encoder
            .u32(2)?
            .u32(fingerprint_u32(fingerprint))?
            .u32(3)?
            .u8(4)?
            .u32(8)?
            .u32(fingerprint_u32(parent_fingerprint))?;
        Ok(())
    })();
    encoded.map_err(|e| Error::Parse(format!("encode crypto-account: {e}")))?;
    Ok(output)
}

pub fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).map_err(|e| Error::Parse(format!("encode JSON: {e}")))?;
    if encoded.len() > MAX_JSON_BYTES {
        return Err(Error::Parse("JSON envelope is too large".into()));
    }
    Ok(encoded)
}

fn decode_json<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T> {
    if data.is_empty() || data.len() > MAX_JSON_BYTES {
        return Err(Error::Parse("JSON envelope is empty or too large".into()));
    }
    validate_json_depth(data)?;
    serde_json::from_slice(data).map_err(|e| Error::Parse(format!("invalid JSON envelope: {e}")))
}

fn printable_name(name: &str) -> String {
    let mut name = name
        .chars()
        .filter(|character| character.is_ascii() && !character.is_ascii_control())
        .collect::<String>();
    name.truncate(MAX_NAME_BYTES);
    let name = name.trim().to_owned();
    if name.is_empty() {
        "Liana".into()
    } else {
        name
    }
}

fn validate_printable_ascii(value: &str, min: usize, max: usize, field: &str) -> Result<()> {
    if !(min..=max).contains(&value.len())
        || !value.is_ascii()
        || value.trim() != value
        || value.bytes().any(|byte| !(32..=126).contains(&byte))
    {
        return Err(Error::Parse(format!("invalid {field}")));
    }
    Ok(())
}

fn validate_json_depth(data: &[u8]) -> Result<()> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in data {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > MAX_JSON_DEPTH {
                    return Err(Error::Parse("JSON nesting exceeds limit".into()));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

fn descriptor_to_template(body: &str) -> Result<(String, Vec<String>)> {
    if body.len() > MAX_DESCRIPTOR_BYTES || !body.is_ascii() {
        return Err(Error::Parse("descriptor is non-ASCII or too large".into()));
    }
    let bytes = body.as_bytes();
    let mut output = String::with_capacity(body.len());
    let mut keys = Vec::<String>::new();
    let mut position = 0usize;
    while position < bytes.len() {
        if bytes[position] != b'[' {
            output.push(char::from(bytes[position]));
            position += 1;
            continue;
        }
        let close = body[position + 1..]
            .find(']')
            .map(|offset| position + 1 + offset)
            .ok_or_else(|| Error::Parse("key origin is incomplete".into()))?;
        let mut xpub_end = close + 1;
        while xpub_end < bytes.len() && BASE58.contains(&bytes[xpub_end]) {
            xpub_end += 1;
        }
        if xpub_end == close + 1 {
            return Err(Error::Parse("key origin is not followed by an extended public key".into()));
        }
        let raw_key = &body[position..xpub_end];
        let key = DescriptorPublicKey::from_str(raw_key)
            .map_err(|e| Error::Parse(format!("invalid descriptor key: {e}")))?
            .to_string();
        let (suffix, next) = if body[xpub_end..].starts_with("/**") {
            ("/**".to_owned(), xpub_end + 3)
        } else if body[xpub_end..].starts_with("/<") {
            let relative_end = body[xpub_end + 2..]
                .find(">/*")
                .ok_or_else(|| Error::Parse("multipath suffix is incomplete".into()))?;
            let suffix_end = xpub_end + 2 + relative_end;
            let branches = &body[xpub_end + 2..suffix_end];
            let mut parts = branches.split(';');
            let first = canonical_number(parts.next())?;
            let second = canonical_number(parts.next())?;
            if parts.next().is_some() || first == second {
                return Err(Error::Parse("exactly two distinct multipath branches are required".into()));
            }
            (format!("/<{first};{second}>/*"), suffix_end + 3)
        } else {
            return Err(Error::Parse("extended keys must end in /** or /<M;N>/*".into()));
        };
        let key_index = match keys.iter().position(|existing| existing == &key) {
            Some(index) => index,
            None => {
                if keys.len() == MAX_KEYS {
                    return Err(Error::Parse("too many policy keys".into()));
                }
                keys.push(key);
                keys.len() - 1
            }
        };
        output.push_str(&format!("@{key_index}{suffix}"));
        position = next;
    }
    Ok((output, keys))
}

fn placeholder_order(template: &str) -> Result<Vec<usize>> {
    let bytes = template.as_bytes();
    let mut cursor = 0usize;
    let mut order = Vec::new();
    while cursor < bytes.len() {
        if bytes[cursor] != b'@' {
            cursor += 1;
            continue;
        }
        cursor += 1;
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if start == cursor {
            return Err(Error::Parse("invalid policy key placeholder".into()));
        }
        let index = template[start..cursor]
            .parse::<usize>()
            .map_err(|_| Error::Parse("invalid policy key placeholder".into()))?;
        if !order.contains(&index) {
            order.push(index);
        }
    }
    Ok(order)
}

fn canonical_number(number: Option<&str>) -> Result<u32> {
    let number = number.ok_or_else(|| Error::Parse("missing branch number".into()))?;
    if number.is_empty()
        || !number.bytes().all(|byte| byte.is_ascii_digit())
        || (number.len() > 1 && number.starts_with('0'))
    {
        return Err(Error::Parse("branch number is not canonical".into()));
    }
    let value = number.parse::<u32>().map_err(|_| Error::Parse("branch number is too large".into()))?;
    if value >= (1 << 31) {
        return Err(Error::Parse("branch number is too large".into()));
    }
    Ok(value)
}

fn compact_size(output: &mut Vec<u8>, value: usize) {
    if value < 253 {
        output.push(value as u8);
    } else if value <= u16::MAX as usize {
        output.push(253);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else {
        output.push(254);
        output.extend_from_slice(&(value as u32).to_le_bytes());
    }
}

fn encode_field(output: &mut Vec<u8>, value: &str) {
    compact_size(output, value.len());
    output.extend_from_slice(value.as_bytes());
}

fn fingerprint_u32(fingerprint: Fingerprint) -> u32 { u32::from_be_bytes(fingerprint.to_bytes()) }

#[cfg(test)]
mod tests {
    use super::super::bitcoin::{
        bip32::{ChainCode, ChildNumber},
        secp256k1::PublicKey,
        NetworkKind,
    };
    use super::*;

    const XPUB_1: &str = "xpub6Eze7yAT3Y1wGrnzedCNVYDXUqa9NmHVWck5emBaTbXtURbe1NWZbK9bsz1TiVE7Cz341PMTfYgFw1KdLWdzcM1UMFTcdQfCYhhXZ2HJvTW";
    const XPUB_2: &str = "xpub688Hn4wScQAAiYJLPg9yH27hUpfZAUnmJejRQBCiwfP5PEDzjWMNW1wChcninxr5gyavFqbbDjdV1aK5USJz8NDVjUy7FRQaaqqXHh5SbXe";

    fn fixture() -> PolicyRegistration {
        let mut policy = PolicyRegistration {
            format: POLICY_FORMAT.into(),
            version: PROTOCOL_VERSION,
            name: "Recovery".into(),
            network: PolicyNetwork::Btc,
            template: "wsh(or_d(pk(@0/<0;1>/*),and_v(v:pkh(@1/<0;1>/*),older(52560))))".into(),
            keys: vec![format!("[abcdef01]{XPUB_1}"), format!("[abcdef02]{XPUB_2}")],
            policy_id: String::new(),
        };
        policy.policy_id = policy.calculate_policy_id();
        policy
    }

    #[test]
    fn identity_and_checksum_match_core_and_liana() {
        let policy = fixture();
        policy.validate().unwrap();
        assert_eq!(policy.policy_id, "506b3dd1ce28b757cde12e2977c483b0afb518de9ad8edbdfbc01e5d9763dd9f");
        assert_eq!(policy.descriptor_checksum().unwrap(), "y7qrgwup");
    }

    #[test]
    fn address_exchange_matches_shared_liana_fixture() {
        const REQUEST: &str = concat!(
            r#"{"format":"passport-address-verification","version":1,"network":"BTC","#,
            r#""policy_id":"506b3dd1ce28b757cde12e2977c483b0afb518de9ad8edbdfbc01e5d9763dd9f","#,
            r#""descriptor_checksum":"y7qrgwup","branch":0,"index":7}"#,
        );
        const RESPONSE: &str = concat!(
            r#"{"format":"passport-address-verification-response","version":1,"network":"BTC","#,
            r#""policy_id":"506b3dd1ce28b757cde12e2977c483b0afb518de9ad8edbdfbc01e5d9763dd9f","#,
            r#""descriptor_checksum":"y7qrgwup","branch":0,"index":7,"#,
            r#""address":"bc1qvqtd2lx6368nuwxy9frnmf55ft8mhp376ussqp9gywtl5qepaa6s260tt9","#,
            r#""fingerprint":"abcdef01"}"#,
        );

        let request = AddressVerificationRequest::from_json(REQUEST.as_bytes()).unwrap();
        assert_eq!(request.policy_id, fixture().policy_id);
        let response = AddressVerificationResponse::new(
            &request,
            "bc1qvqtd2lx6368nuwxy9frnmf55ft8mhp376ussqp9gywtl5qepaa6s260tt9".into(),
            Fingerprint::from_str("abcdef01").unwrap(),
        );
        assert_eq!(response.to_json().unwrap(), RESPONSE.as_bytes());
    }

    #[test]
    fn json_depth_and_address_bounds_are_enforced() {
        let deeply_nested = format!("{}0{}", "[".repeat(17), "]".repeat(17));
        assert!(decode_json::<serde_json::Value>(deeply_nested.as_bytes()).is_err());

        let mut request = serde_json::json!({
            "format": ADDRESS_REQUEST_FORMAT,
            "version": PROTOCOL_VERSION,
            "network": "BTC",
            "policy_id": fixture().policy_id,
            "descriptor_checksum": "y7qrgwup",
            "branch": 2,
            "index": 7
        });
        assert!(AddressVerificationRequest::from_json(&serde_json::to_vec(&request).unwrap()).is_err());
        request["branch"] = 0.into();
        request["index"] = (1u64 << 31).into();
        assert!(AddressVerificationRequest::from_json(&serde_json::to_vec(&request).unwrap()).is_err());
    }

    #[test]
    fn crypto_account_matches_shared_vector() {
        let xpub = Xpub {
            network: NetworkKind::Main,
            depth: 4,
            parent_fingerprint: Fingerprint::from_str("11223344").unwrap(),
            child_number: ChildNumber::from_hardened_idx(2).unwrap(),
            public_key: PublicKey::from_str(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .unwrap(),
            chain_code: ChainCode::from([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                26, 27, 28, 29, 30, 31,
            ]),
        };
        let encoded = encode_crypto_account(
            Fingerprint::from_str("a1b2c3d4").unwrap(),
            xpub.parent_fingerprint,
            &xpub,
            Network::Bitcoin,
            7,
        )
        .unwrap();
        assert_eq!(
            hex::encode(encoded),
            concat!(
                "a2011aa1b2c3d40281d90134d90191d9019ad9012fa602f40358210279be667e",
                "f9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179804582000",
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05",
                "d99d71a20100020006d99d70a301881830f500f507f502f5021aa1b2c3d40304",
                "081a11223344"
            )
        );
    }

    #[test]
    fn unknown_json_fields_and_taproot_are_rejected() {
        let mut json = serde_json::to_value(fixture()).unwrap();
        json.as_object_mut().unwrap().insert("extra".into(), true.into());
        assert!(PolicyRegistration::from_json(&serde_json::to_vec(&json).unwrap()).is_err());

        let mut taproot = fixture();
        taproot.template = "tr(@0/<0;1>/*)".to_owned();
        taproot.keys.truncate(1);
        taproot.policy_id = taproot.calculate_policy_id();
        assert!(matches!(taproot.validate(), Err(Error::Unsupported(_))));
    }
}
