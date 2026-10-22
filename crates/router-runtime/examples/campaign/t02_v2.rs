//! Versioned t02 qualification fixture. No arbitrary candidate or adoption authority.
use super::public_score::{read_private, run_bounded};
use super::{Result, mkdir, save};
use router_adapter_api::content_digest;
use router_runtime::FiniteClientVerifier;
use router_types::{VerificationOutcome, VerificationRecord};
use serde_json::Value;
use std::{path::Path, process::Command, time::Duration};

const VERIFIER: &[u8] = include_bytes!("t02-v2/verify.py");
const CASES: &[u8] = include_bytes!("t02-v2/cases.rs");
const BASELINE: &[u8] = include_bytes!("t02-v2/acceptance.json");
const SOLUTION: &[u8] = include_bytes!(
    "../../../../docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02/controller/control-output.json"
);

// This parser is private to the fixed child invocation below. There is no
// user-supplied receipt entrance and no objective/acceptance inference.
fn validate_receipt(
    raw: &[u8],
    report: &[u8],
    candidate: &[u8],
    patch: &[u8],
) -> Result<VerificationRecord> {
    let receipt = router_adapter_api::strict_json_limited(raw, 32768)?;
    let mut expected: Value = serde_json::from_slice(BASELINE)?;
    expected["runtime_report_sha256"] = content_digest(report).into();
    for label in ["source", "candidate"] {
        let hash = receipt["outcomes"][label]["stdout_sha256"]
            .as_str()
            .ok_or("case output digest")?;
        if !router_adapter_api::is_digest(hash) {
            return Err("case output digest".into());
        }
        expected["outcomes"][label]["stdout_sha256"] = hash.into();
    }
    if receipt != expected
        || receipt["candidate_sha256"] != content_digest(candidate)
        || receipt["artifact_sha256"] != content_digest(patch)
        || receipt["verifier_sha256"] != content_digest(VERIFIER)
        || receipt["required_cases_sha256"] != content_digest(CASES)
    {
        return Err("t02 v2 receipt binding".into());
    }
    Ok(VerificationRecord {
        verifier: "t02-score-v2".into(),
        evidence_sha256: content_digest(raw),
        artifact_sha256: Some(content_digest(patch)),
        validation: VerificationOutcome::Passed,
        objective: VerificationOutcome::Unknown,
    })
}
pub(super) fn evaluate(
    root: &Path,
    report: &[u8],
    verifier: &FiniteClientVerifier<'_>,
) -> Result<Value> {
    let patch = verifier.artifact()?;
    let candidate = read_private(&root.join("submission/lib.rs"), 32768)?;
    let packet = super::recipe::packets()?
        .assignments
        .into_iter()
        .find(|p| p.assignment_id == "t02-Lm-r1-H1")
        .ok_or("public score packet")?;
    let capsule = tempfile::Builder::new()
        .prefix("t02-v2-")
        .tempdir_in(root)?;
    let base = capsule.path();
    for directory in [
        "docs",
        "docs/bench",
        "docs/bench/linux-finite-dispatch-2026-10-16",
        "docs/bench/linux-finite-dispatch-2026-10-16/inputs",
        "docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02",
        "docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02/controller",
        "crates",
        "crates/router-runtime",
        "crates/router-runtime/examples",
        "crates/router-runtime/examples/campaign",
        "crates/router-runtime/examples/campaign/t02-v2",
        "input",
    ] {
        mkdir(&base.join(directory))?;
    }
    let script = base.join("crates/router-runtime/examples/campaign/t02-v2/verify.py");
    save(&script, VERIFIER)?;
    save(
        &base.join("crates/router-runtime/examples/campaign/t02-v2/cases.rs"),
        CASES,
    )?;
    save(
        &base.join(
            "docs/bench/linux-finite-dispatch-2026-10-16/inputs/t02/controller/control-output.json",
        ),
        SOLUTION,
    )?;
    save(
        &base.join("crates/router-runtime/examples/campaign/packets.json"),
        include_bytes!("packets.json"),
    )?;
    for (name, bytes) in [
        ("source-lib.rs", packet.files["lib.rs"].as_bytes()),
        ("lib.rs", &candidate),
        ("change.patch", &patch),
        ("runtime-result.json", report),
    ] {
        save(&base.join("input").join(name), bytes)?;
    }
    let receipt_path = base.join("receipt.json");
    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["-I", "-B"])
        .arg(script)
        .arg("--input")
        .arg(base.join("input"))
        .arg("--output")
        .arg(&receipt_path)
        .env_clear()
        .env("PATH", "/usr/local/cargo/bin:/usr/bin:/bin")
        .env("HOME", base)
        .env("TMPDIR", base)
        .current_dir(base);
    run_bounded(command, Duration::from_secs(120))?;
    let raw = read_private(&receipt_path, 32768)?;
    let record = validate_receipt(&raw, report, &candidate, &patch)?;
    // Retain the exact evidence before the atomic attestation. A failed write
    // cannot leave an attestation whose evidence was never preserved.
    save(&root.join("t02-v2-receipt.json"), &raw)?;
    let summary = verifier.record(record.clone())?;
    Ok(
        serde_json::json!({"schema_version":2,"scope":"t02-score-v2","verification":record,"summary":summary,"human_acceptance":null,"source_publication":false,"model_calls_started":0}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t02_v2_attestation_binds_actual_report_patch_and_all_required_cases() {
        let mut receipt: serde_json::Value = serde_json::from_slice(BASELINE).unwrap();
        let patch =
            include_bytes!("../../../../docs/bench/native-useful-score-2026-10-21/change.patch");
        let candidate = include_bytes!(
            "../../../../docs/bench/native-useful-score-2026-10-21/submission/lib.rs"
        );
        let report = b"current private report";
        receipt["runtime_report_sha256"] = content_digest(report).into();
        let raw = serde_json::to_vec(&receipt).unwrap();
        let record = validate_receipt(&raw, report, candidate, patch).unwrap();
        assert_eq!(record.verifier, "t02-score-v2");
        let old =
            include_bytes!("../../../../docs/bench/native-useful-score-2026-10-21/acceptance.json");
        assert!(validate_receipt(old, report, candidate, patch).is_err());
        assert_eq!(record.validation, VerificationOutcome::Passed);
        assert_eq!(record.objective, VerificationOutcome::Unknown);
        assert_eq!(record.evidence_sha256, content_digest(&raw));
        assert_eq!(record.artifact_sha256, Some(content_digest(patch)));
        assert!(validate_receipt(&raw, b"stale report", candidate, patch).is_err());
        assert!(validate_receipt(&raw, report, b"changed candidate", patch).is_err());
        assert!(validate_receipt(&raw, report, candidate, b"changed patch").is_err());
        for pointer in [
            "/packet_sha256",
            "/frozen_campaign_acceptance_sha256",
            "/source_sha256",
            "/verifier_sha256",
            "/required_cases_sha256",
            "/outcomes/candidate/cases/t02_v2_empty",
            "/outcomes/source/exit_code",
            "/human_acceptance",
            "/source_publication",
            "/model_calls_started",
            "/memory_bytes",
            "/swap_bytes",
            "/git_mode",
            "/result_tree",
            "/evaluator_id",
            "/compiler_sha256",
            "/predecessor_oracle_sha256",
            "/case_role",
            "/decision_cases_executed",
            "/adoption_authorized",
            "/oracle_authenticity",
            "/outcomes/candidate/outcome",
        ] {
            let mut bad = receipt.clone();
            *bad.pointer_mut(pointer).unwrap() = serde_json::json!("invalid");
            assert!(
                validate_receipt(&serde_json::to_vec(&bad).unwrap(), report, candidate, patch)
                    .is_err(),
                "{pointer}"
            );
        }
        receipt["outcomes"]["candidate"]["cases"]
            .as_object_mut()
            .unwrap()
            .remove("t02_v2_wide_sums");
        assert!(
            validate_receipt(
                &serde_json::to_vec(&receipt).unwrap(),
                report,
                candidate,
                patch
            )
            .is_err()
        );
    }
}
