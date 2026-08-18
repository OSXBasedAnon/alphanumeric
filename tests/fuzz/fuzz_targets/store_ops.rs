#![no_main]

//! Differential fuzzing of the storage boundary against a BTreeMap model.
//!
//! The engine swap (sled -> redb, 8.0.0) replaced the implementation under
//! `a9::store` while promising the same observable semantics to ~120 call sites
//! in the chain. Unit tests cover the shapes we thought to write down. This
//! covers the ones we did not: the fuzzer drives an arbitrary interleaving of
//! inserts, removes, batches, scans, range queries and clears against both the
//! real store and a BTreeMap, and asserts they never disagree.
//!
//! What a disagreement would mean is the whole point. A wrapper that returns the
//! wrong previous value on insert, drops a key from a prefix scan, or leaves a
//! table non-empty after clear does not crash — it silently corrupts chain state
//! and the node keeps running. The model is the oracle for exactly that class.
//!
//! Deliberately NOT fuzzed here: durability across reopen. Opening a redb file
//! costs milliseconds, so a reopen per iteration would starve the fuzzer of
//! executions. `durable_after_flush_and_reopen` covers it as a unit test.

use alphanumeric::a9::store::Store;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_INPUT_BYTES: usize = 4096;
/// Small key space on purpose: collisions are where overwrite, delete-then-read
/// and previous-value semantics actually get exercised. A wide key space would
/// spend every iteration inserting keys that never interact.
const KEY_SPACE: u8 = 32;

fn key_of(b: u8) -> Vec<u8> {
    // Two-byte keys so ordering is exercised beyond single-byte comparison, and
    // so prefix scans have a real prefix to match on.
    vec![b % KEY_SPACE, b]
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES || data.len() < 2 {
        return;
    }

    let store = match Store::temporary() {
        Ok(s) => s,
        // A temp-file failure is an environment problem, not a finding.
        Err(_) => return,
    };
    let tree = match store.open_tree(b"fuzz") {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    let mut i = 0usize;
    while i + 1 < data.len() {
        let op = data[i] % 8;
        let arg = data[i + 1];
        i += 2;

        match op {
            // insert: the returned previous value must match the model's
            0 => {
                let k = key_of(arg);
                let v = vec![arg; 1 + (arg as usize % 24)];
                let got = tree.insert(&k, &v).expect("insert");
                let expected = model.insert(k, v);
                assert_eq!(got, expected, "insert returned the wrong previous value");
            }
            // remove: likewise, the removed value must match
            1 => {
                let k = key_of(arg);
                let got = tree.remove(&k).expect("remove");
                let expected = model.remove(&k);
                assert_eq!(got, expected, "remove returned the wrong previous value");
            }
            2 => {
                let k = key_of(arg);
                let got = tree.get(&k).expect("get");
                assert_eq!(got, model.get(&k).cloned(), "get disagreed with the model");
            }
            3 => {
                let k = key_of(arg);
                let got = tree.contains_key(&k).expect("contains_key");
                assert_eq!(got, model.contains_key(&k), "contains_key disagreed");
            }
            // batch: every operation in it must land, atomically and completely
            4 => {
                let mut batch = alphanumeric::a9::store::Batch::default();
                let n = 1 + (arg as usize % 6);
                let mut staged: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::new();
                for j in 0..n {
                    let kb = arg.wrapping_add(j as u8);
                    let k = key_of(kb);
                    if kb % 3 == 0 {
                        batch.remove(&k);
                        staged.push((k, None));
                    } else {
                        let v = vec![kb; 1 + (kb as usize % 8)];
                        batch.insert(&k, &v);
                        staged.push((k, Some(v)));
                    }
                }
                tree.apply_batch(batch).expect("apply_batch");
                for (k, v) in staged {
                    match v {
                        Some(v) => {
                            model.insert(k, v);
                        }
                        None => {
                            model.remove(&k);
                        }
                    }
                }
            }
            // full iteration must yield exactly the model, in key order
            5 => {
                let got: Vec<(Vec<u8>, Vec<u8>)> = tree.iter().map(|r| r.expect("scan")).collect();
                let expected: Vec<(Vec<u8>, Vec<u8>)> =
                    model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                assert_eq!(got, expected, "full scan disagreed with the model");
                assert_eq!(
                    tree.len().expect("len") as usize,
                    model.len(),
                    "len disagreed with the model"
                );
            }
            // prefix scan must yield exactly the model's matching subset, in order
            6 => {
                let prefix = vec![arg % KEY_SPACE];
                let got: Vec<(Vec<u8>, Vec<u8>)> = tree.scan_prefix(&prefix).map(|r| r.expect("scan")).collect();
                let expected: Vec<(Vec<u8>, Vec<u8>)> = model
                    .iter()
                    .filter(|(k, _)| k.starts_with(&prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                assert_eq!(got, expected, "prefix scan disagreed with the model");
            }
            // clear must leave the tree genuinely empty, not merely unreadable
            _ => {
                tree.clear().expect("clear");
                model.clear();
                assert!(tree.is_empty().expect("is_empty"), "clear left entries behind");
                assert_eq!(tree.len().expect("len"), 0, "clear left a non-zero len");
                assert_eq!(tree.first().expect("first"), None, "clear left a first key");
            }
        }
    }

    // Final reconciliation: whatever the interleaving did, the two must agree
    // both forwards and on the endpoints.
    let final_scan: Vec<(Vec<u8>, Vec<u8>)> = tree.iter().map(|r| r.expect("scan")).collect();
    let final_model: Vec<(Vec<u8>, Vec<u8>)> =
        model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    assert_eq!(final_scan, final_model, "final state disagreed with the model");
    assert_eq!(
        tree.first().expect("first"),
        final_model.first().cloned(),
        "first() disagreed with the model"
    );
    assert_eq!(
        tree.last().expect("last"),
        final_model.last().cloned(),
        "last() disagreed with the model"
    );
});
