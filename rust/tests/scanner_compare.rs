//! Reason / result comparison shared by the scanner and fuzz tests.
#![allow(dead_code)]
use serde_json::Value;

/// The b017 prefix of a reason whose tail is an SDK's own text, or None when the reason is all b017's.
fn sdk_prefix(reason: &str) -> Option<String> {
    let own_tails = [
        "no unlocking script",
        "the script evaluated false",
        "its source tx was not supplied",
        "BEEF ",
    ];
    let split = |prefix_end: usize| -> Option<String> {
        let tail = &reason[prefix_end..];
        if own_tails.iter().any(|t| tail.starts_with(t)) {
            None
        } else {
            Some(reason[..prefix_end].to_string())
        }
    };
    if let Some(rest) = reason.strip_prefix("script execution failed: tx ") {
        if let Some(p) = rest.find(": ") {
            return split("script execution failed: tx ".len() + p + 2);
        }
    }
    for p in [
        "unverifiable input: ",
        "malformed transaction hex: ",
        "invalid BEEF: ",
    ] {
        if reason.starts_with(p) {
            return split(p.len());
        }
    }
    if let Some(i) = reason.find("its merkle path does not prove it (") {
        return split(i + "its merkle path does not prove it (".len());
    }
    None
}

pub fn reasons_match(got: &str, want: &str) -> bool {
    if got == want {
        return true;
    }
    match sdk_prefix(want) {
        Some(p) => got.starts_with(&p) && sdk_prefix(got).as_deref() == Some(p.as_str()),
        None => false,
    }
}

pub fn compare(got: &str, want: &Value) -> Option<String> {
    let mut g: Value = serde_json::from_str(got).unwrap();
    let mut w = want.clone();
    let gr = g["reason"].as_str().unwrap_or("").to_string();
    let wr = w["reason"].as_str().unwrap_or("").to_string();
    if !reasons_match(&gr, &wr) {
        return Some(format!("reason\n got {gr:?}\nwant {wr:?}"));
    }
    g.as_object_mut().unwrap().remove("reason");
    w.as_object_mut().unwrap().remove("reason");
    if g != w {
        return Some(format!("result\n got {g}\nwant {w}"));
    }
    None
}
