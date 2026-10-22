//! Prints the changes from one CCR file to another.
//!
//! Usage: `cargo run --example ccr-diff -- [--summary] [--lenient] OLD NEW`

use std::process::ExitCode;

use rpki_ccr::{AccessDescription, Ccr, ChangeKind, ManifestInstance, ValidationOptions};

fn describe(mi: &ManifestInstance) -> String {
    format!(
        "seqnum {} thisupdate {} {}",
        mi.manifest_number(),
        mi.this_update().format("%Y-%m-%dT%H:%M:%SZ"),
        mi.locations()
            .iter()
            .map(AccessDescription::uri)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn main() -> ExitCode {
    let mut summary = false;
    let mut lenient = false;
    let mut files = Vec::new();
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--summary" => summary = true,
            "--lenient" => lenient = true,
            _ => files.push(arg),
        }
    }
    let [before_path, after_path] = files.as_slice() else {
        eprintln!("usage: ccr-diff [--summary] [--lenient] OLD NEW");
        return ExitCode::FAILURE;
    };
    let options = if lenient {
        ValidationOptions::lenient()
    } else {
        ValidationOptions::strict()
    };
    let load = |path: &str| match Ccr::from_file_with(path, &options) {
        Ok(ccr) => Some(ccr),
        Err(err) => {
            eprintln!("{path}: {err}");
            None
        }
    };
    let (Some(before), Some(after)) = (load(before_path), load(after_path)) else {
        return ExitCode::FAILURE;
    };
    let diff = before.diff(&after);
    println!(
        "Before: {before_path} produced at {}",
        diff.before_produced_at()
    );
    println!(
        "After:  {after_path} produced at {}",
        diff.after_produced_at()
    );

    if let Some(m) = diff.manifests() {
        println!(
            "Manifests: +{} -{} ({} unchanged); issuers: {} changed ({} unchanged)",
            m.added().len(),
            m.removed().len(),
            m.unchanged(),
            m.issuers().len(),
            m.unchanged_issuers()
        );
        if !summary {
            for change in m.issuers() {
                let sign = match change.kind() {
                    ChangeKind::Added => "+",
                    ChangeKind::Removed => "-",
                    ChangeKind::Updated => "~",
                };
                println!("  {sign} aki {}", change.aki());
                for mi in change.before() {
                    println!("      was {}", describe(mi));
                }
                for mi in change.after() {
                    println!("      now {}", describe(mi));
                }
            }
        }
    }
    if let Some(v) = diff.roa_payloads() {
        println!(
            "VRPs: +{} -{} ({} unchanged)",
            v.added().len(),
            v.removed().len(),
            v.unchanged()
        );
        if !summary {
            for vrp in v.removed() {
                println!("  - {vrp}");
            }
            for vrp in v.added() {
                println!("  + {vrp}");
            }
        }
    }
    if let Some(a) = diff.aspa_payloads() {
        println!(
            "ASPAs: +{} -{} ~{} ({} unchanged)",
            a.added().len(),
            a.removed().len(),
            a.updated().len(),
            a.unchanged()
        );
        if !summary {
            for set in a.removed() {
                println!("  - customer {}", set.customer_as_id());
            }
            for set in a.added() {
                println!("  + customer {}", set.customer_as_id());
            }
            for update in a.updated() {
                let mut parts: Vec<String> = update
                    .providers_added()
                    .iter()
                    .map(|p| format!("+{p}"))
                    .collect();
                parts.extend(update.providers_removed().iter().map(|p| format!("-{p}")));
                println!(
                    "  ~ customer {}: {}",
                    update.customer_as_id(),
                    parts.join(" ")
                );
            }
        }
    }
    if let Some(t) = diff.trust_anchors() {
        println!(
            "Trust anchors: +{} -{} ({} unchanged)",
            t.added().len(),
            t.removed().len(),
            t.unchanged()
        );
        if !summary {
            for ski in t.removed() {
                println!("  - {ski}");
            }
            for ski in t.added() {
                println!("  + {ski}");
            }
        }
    }
    if let Some(r) = diff.router_keys() {
        println!(
            "Router keys: +{} -{} ({} unchanged)",
            r.added().len(),
            r.removed().len(),
            r.unchanged()
        );
        if !summary {
            for (asn, key) in r.removed() {
                println!("  - AS {asn} ski {}", key.ski());
            }
            for (asn, key) in r.added() {
                println!("  + AS {asn} ski {}", key.ski());
            }
        }
    }
    if diff.is_empty() {
        println!("No changes.");
    }
    ExitCode::SUCCESS
}
