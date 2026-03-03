//! STF test vectors for statistics sub-transition (Section 13).

use grey_state::statistics;
use grey_types::header::*;
use grey_types::state::{ValidatorRecord, ValidatorStatistics};
use grey_types::Hash;
use std::collections::BTreeMap;

/// Helper: decode a 0x-prefixed hex string to bytes.
fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("bad hex")
}

fn hash_from_hex(s: &str) -> Hash {
    let bytes = decode_hex(s);
    let mut h = [0u8; 32];
    h.copy_from_slice(&bytes);
    Hash(h)
}

fn sig64_from_hex(s: &str) -> grey_types::Ed25519Signature {
    let bytes = decode_hex(s);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&bytes);
    grey_types::Ed25519Signature(sig)
}

/// Parse WorkReport from JSON value.
fn work_report_from_json(json: &serde_json::Value) -> grey_types::work::WorkReport {
    use grey_types::work::*;

    let ps = &json["package_spec"];
    let ctx = &json["context"];

    WorkReport {
        package_spec: AvailabilitySpec {
            package_hash: hash_from_hex(ps["hash"].as_str().unwrap()),
            bundle_length: ps["length"].as_u64().unwrap() as u32,
            erasure_root: hash_from_hex(ps["erasure_root"].as_str().unwrap()),
            exports_root: hash_from_hex(ps["exports_root"].as_str().unwrap()),
            exports_count: ps["exports_count"].as_u64().unwrap() as u16,
        },
        context: RefinementContext {
            anchor: hash_from_hex(ctx["anchor"].as_str().unwrap()),
            state_root: hash_from_hex(ctx["state_root"].as_str().unwrap()),
            beefy_root: hash_from_hex(ctx["beefy_root"].as_str().unwrap()),
            lookup_anchor: hash_from_hex(ctx["lookup_anchor"].as_str().unwrap()),
            lookup_anchor_timeslot: ctx["lookup_anchor_slot"].as_u64().unwrap() as u32,
            prerequisites: ctx["prerequisites"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| hash_from_hex(v.as_str().unwrap()))
                .collect(),
        },
        core_index: json["core_index"].as_u64().unwrap() as u16,
        authorizer_hash: hash_from_hex(json["authorizer_hash"].as_str().unwrap()),
        auth_gas_used: json["auth_gas_used"].as_u64().unwrap(),
        auth_output: decode_hex(json["auth_output"].as_str().unwrap()),
        segment_root_lookup: json["segment_root_lookup"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    hash_from_hex(item["work_package_hash"].as_str().unwrap()),
                    hash_from_hex(item["segment_tree_root"].as_str().unwrap()),
                )
            })
            .collect(),
        results: json["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| {
                let result = &r["result"];
                let work_result = if let Some(data) = result.get("ok") {
                    WorkResult::Ok(decode_hex(data.as_str().unwrap()))
                } else if result.get("out_of_gas").is_some() {
                    WorkResult::OutOfGas
                } else if result.get("panic").is_some() {
                    WorkResult::Panic
                } else {
                    WorkResult::Panic // fallback
                };

                let rl = &r["refine_load"];
                WorkDigest {
                    service_id: r["service_id"].as_u64().unwrap() as u32,
                    code_hash: hash_from_hex(r["code_hash"].as_str().unwrap()),
                    payload_hash: hash_from_hex(r["payload_hash"].as_str().unwrap()),
                    accumulate_gas: r["accumulate_gas"].as_u64().unwrap(),
                    result: work_result,
                    gas_used: rl["gas_used"].as_u64().unwrap(),
                    imports_count: rl["imports"].as_u64().unwrap() as u16,
                    extrinsics_count: rl["extrinsic_count"].as_u64().unwrap() as u16,
                    extrinsics_size: rl["extrinsic_size"].as_u64().unwrap() as u32,
                    exports_count: rl["exports"].as_u64().unwrap() as u16,
                }
            })
            .collect(),
    }
}

/// Parse an Extrinsic from JSON (for statistics tests, we just need the structure).
fn extrinsic_from_json(json: &serde_json::Value) -> Extrinsic {
    Extrinsic {
        tickets: json["tickets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| TicketProof {
                attempt: t["attempt"].as_u64().unwrap() as u8,
                proof: decode_hex(t["signature"].as_str().unwrap()),
            })
            .collect(),
        preimages: json["preimages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["requester"].as_u64().unwrap() as u32,
                    decode_hex(p["blob"].as_str().unwrap()),
                )
            })
            .collect(),
        guarantees: json["guarantees"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| Guarantee {
                report: work_report_from_json(&g["report"]),
                timeslot: g["slot"].as_u64().unwrap() as u32,
                credentials: g["signatures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| {
                        (
                            s["validator_index"].as_u64().unwrap() as u16,
                            sig64_from_hex(s["signature"].as_str().unwrap()),
                        )
                    })
                    .collect(),
            })
            .collect(),
        assurances: json["assurances"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| Assurance {
                anchor: hash_from_hex(a["anchor"].as_str().unwrap()),
                bitfield: decode_hex(a["bitfield"].as_str().unwrap()),
                validator_index: a["validator_index"].as_u64().unwrap() as u16,
                signature: sig64_from_hex(a["signature"].as_str().unwrap()),
            })
            .collect(),
        disputes: {
            let d = &json["disputes"];
            DisputesExtrinsic {
                verdicts: d["verdicts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| Verdict {
                        report_hash: hash_from_hex(v["target"].as_str().unwrap()),
                        age: v["age"].as_u64().unwrap() as u32,
                        judgments: v["votes"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|j| Judgment {
                                is_valid: j["vote"].as_bool().unwrap(),
                                validator_index: j["index"].as_u64().unwrap() as u16,
                                signature: sig64_from_hex(j["signature"].as_str().unwrap()),
                            })
                            .collect(),
                    })
                    .collect(),
                culprits: d["culprits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| Culprit {
                        report_hash: hash_from_hex(c["target"].as_str().unwrap()),
                        validator_key: {
                            let bytes = decode_hex(c["key"].as_str().unwrap());
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&bytes);
                            grey_types::Ed25519PublicKey(key)
                        },
                        signature: sig64_from_hex(c["signature"].as_str().unwrap()),
                    })
                    .collect(),
                faults: d["faults"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| Fault {
                        report_hash: hash_from_hex(f["target"].as_str().unwrap()),
                        is_valid: f["vote"].as_bool().unwrap(),
                        validator_key: {
                            let bytes = decode_hex(f["key"].as_str().unwrap());
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&bytes);
                            grey_types::Ed25519PublicKey(key)
                        },
                        signature: sig64_from_hex(f["signature"].as_str().unwrap()),
                    })
                    .collect(),
            }
        },
    }
}

/// Parse ValidatorRecord from JSON.
fn validator_record_from_json(json: &serde_json::Value) -> ValidatorRecord {
    serde_json::from_value(json.clone()).expect("failed to parse ValidatorRecord")
}

/// Run a single statistics STF test vector.
fn run_statistics_test(path: &str) {
    let content = std::fs::read_to_string(path).expect("failed to read test vector");
    let json: serde_json::Value = serde_json::from_str(&content).expect("failed to parse JSON");

    let input = &json["input"];
    let pre = &json["pre_state"];
    let post = &json["post_state"];

    // Parse input
    let new_slot = input["slot"].as_u64().unwrap() as u32;
    let author_index = input["author_index"].as_u64().unwrap() as u16;
    let extrinsic = extrinsic_from_json(&input["extrinsic"]);

    // Parse pre-state
    let prior_slot = pre["slot"].as_u64().unwrap() as u32;
    let pre_curr: Vec<ValidatorRecord> = pre["vals_curr_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();
    let pre_last: Vec<ValidatorRecord> = pre["vals_last_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();

    let mut stats = ValidatorStatistics {
        current: pre_curr,
        last: pre_last,
        core_stats: vec![],
        service_stats: BTreeMap::new(),
    };

    // Apply transition using tiny config
    let config = grey_types::config::Config::tiny();
    let incoming_reports: Vec<&grey_types::work::WorkReport> = extrinsic.guarantees.iter().map(|g| &g.report).collect();
    statistics::update_statistics(&config, &mut stats, prior_slot, new_slot, author_index, &extrinsic, &incoming_reports, &[], &std::collections::BTreeMap::new());

    // Parse expected post-state
    let expected_curr: Vec<ValidatorRecord> = post["vals_curr_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();
    let expected_last: Vec<ValidatorRecord> = post["vals_last_stats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| validator_record_from_json(v))
        .collect();

    // Compare
    assert_eq!(
        stats.current, expected_curr,
        "current stats mismatch in {}",
        path
    );
    assert_eq!(
        stats.last, expected_last,
        "last stats mismatch in {}",
        path
    );
}

#[test]
fn test_stf_statistics_empty_extrinsic() {
    run_statistics_test("../../res/testvectors/stf/statistics/tiny/stats_with_empty_extrinsic-1.json");
}

#[test]
fn test_stf_statistics_some_extrinsic() {
    run_statistics_test("../../res/testvectors/stf/statistics/tiny/stats_with_some_extrinsic-1.json");
}

#[test]
fn test_stf_statistics_epoch_change() {
    run_statistics_test("../../res/testvectors/stf/statistics/tiny/stats_with_epoch_change-1.json");
}
