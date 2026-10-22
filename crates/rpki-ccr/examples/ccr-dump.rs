//! Prints a CCR file in the textual format used by Appendix B of the
//! specification and by `rpki-client -f`, for side-by-side comparison.
//!
//! Manifest instances are printed sorted by AKI, as rpki-client does; the
//! library itself keeps them in encoded order (ascending by hash).
//!
//! Usage: `cargo run --example ccr-dump -- [--lenient] FILE[.gz]`

use std::io::Read as _;
use std::process::ExitCode;

use base64::prelude::*;
use chrono::{DateTime, Utc};
use rpki_ccr::{Ccr, DecodeOptions, Digest, ManifestInstance};

fn b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

fn time(t: DateTime<Utc>) -> String {
    t.format("%a %d %b %Y %H:%M:%S %z").to_string()
}

fn line(label: &str, value: impl std::fmt::Display) {
    println!("{label:<24}{value}");
}

fn entry(value: impl std::fmt::Display) {
    println!("{:<24}{value}", "");
}

fn manifest_instance(mi: &ManifestInstance) -> String {
    let mut s = format!(
        "hash:{} size:{} aki:{} seqnum:{} thisupdate:{} sia:{}",
        b64(mi.hash().as_slice()),
        mi.size(),
        mi.aki(),
        mi.manifest_number(),
        mi.this_update().timestamp(),
        mi.locations()
            .iter()
            .map(|l| l.uri())
            .collect::<Vec<_>>()
            .join(",")
    );
    if !mi.subordinates().is_empty() {
        s.push_str(" subordinates:");
        s.push_str(
            &mi.subordinates()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    s
}

fn main() -> ExitCode {
    let mut lenient = false;
    let mut path = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--lenient" => lenient = true,
            _ if path.is_none() => path = Some(arg),
            _ => {
                eprintln!("usage: ccr-dump [--lenient] FILE");
                return ExitCode::FAILURE;
            }
        }
    }
    let Some(path) = path else {
        eprintln!("usage: ccr-dump [--lenient] FILE");
        return ExitCode::FAILURE;
    };

    let mut der = match std::fs::read(&path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("{path}: {err}");
            return ExitCode::FAILURE;
        }
    };
    if Ccr::is_gzip(&der) {
        let mut inflated = Vec::new();
        if let Err(err) = flate2::read::MultiGzDecoder::new(&der[..]).read_to_end(&mut inflated) {
            eprintln!("{path}: gzip decompression failed: {err}");
            return ExitCode::FAILURE;
        }
        der = inflated;
    }

    line("File:", &path);
    line("Hash identifier:", b64(Digest::sha256(&der).as_slice()));

    let options = if lenient {
        DecodeOptions::lenient()
    } else {
        DecodeOptions::strict()
    };
    let ccr = match Ccr::decode_der_with(&der, &options) {
        Ok(ccr) => ccr,
        Err(err) => {
            line("Validation:", format!("Failed, {err}"));
            return ExitCode::FAILURE;
        }
    };

    line("CCR produced at:", time(ccr.produced_at()));
    if let Some(state) = ccr.manifests() {
        line("Manifest state hash:", b64(state.hash().as_slice()));
        line("Manifest last update:", time(state.most_recent_update()));
        println!("Manifest instances:");
        let mut instances: Vec<&ManifestInstance> = state.instances().iter().collect();
        instances.sort_by_key(|mi| *mi.aki());
        for mi in instances {
            entry(manifest_instance(mi));
        }
    }
    if let Some(state) = ccr.roa_payloads() {
        line("ROA payload state hash:", b64(state.hash().as_slice()));
        println!("ROA payload entries:");
        for vrp in state.vrps() {
            entry(vrp);
        }
    }
    if let Some(state) = ccr.aspa_payloads() {
        line("ASPA payload state hash:", b64(state.hash().as_slice()));
        println!("ASPA payload entries:");
        for set in state.sets() {
            let providers: Vec<String> = set.providers().iter().map(ToString::to_string).collect();
            entry(format!(
                "customer: {} providers: {}",
                set.customer_as_id(),
                providers.join(", ")
            ));
        }
    }
    if let Some(state) = ccr.trust_anchors() {
        line("Trust anchor state hash:", b64(state.hash().as_slice()));
        let skis: Vec<String> = state.skis().iter().map(ToString::to_string).collect();
        line("Trust anchor keyids:", skis.join(", "));
    }
    if let Some(state) = ccr.router_keys() {
        line("Router key state hash:", b64(state.hash().as_slice()));
        println!("Router keys:");
        for (asn, key) in state.router_keys() {
            entry(format!(
                "asid:{} ski:{} pubkey:{}",
                asn,
                key.ski(),
                b64(key.spki().as_der())
            ));
        }
    }
    for ext in ccr.extensions() {
        line("Unknown extension:", b64(ext));
    }
    line("Validation:", if lenient { "N/A (lenient)" } else { "OK" });
    ExitCode::SUCCESS
}
