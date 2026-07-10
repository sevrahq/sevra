//! Output contract, identical to the TS CLI: `--json` makes stdout
//! machine-readable on EVERY command, including errors; human mode prints a
//! plain line and sends errors to stderr with a `sevra:` prefix. Informational
//! notices always go to stderr so they never corrupt `--json` stdout.

use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

static JSON_MODE: AtomicBool = AtomicBool::new(false);

pub fn set_json_mode(on: bool) {
    JSON_MODE.store(on, Ordering::Relaxed);
}

pub fn json_mode() -> bool {
    JSON_MODE.load(Ordering::Relaxed)
}

/// Print a result: the human string in human mode, the data as pretty JSON in
/// `--json` mode (an empty object when no data is supplied).
pub fn out(human: &str, data: Option<Value>) {
    if json_mode() {
        println!("{}", serde_json::to_string_pretty(&data.unwrap_or_else(|| json!({}))).unwrap());
    } else {
        println!("{human}");
    }
}

/// A notice to the operator (agent or human) that must not touch stdout in
/// `--json` mode.
pub fn note(msg: &str) {
    eprintln!("sevra: {msg}");
}

/// Fail: in `--json` mode emit `{ "error": msg, ...data }` on stdout (so a
/// parsing agent still gets structured output); in human mode print
/// `sevra: msg` on stderr. Always exit 1.
pub fn fail(msg: &str, data: Option<Value>) -> ! {
    if json_mode() {
        let mut obj = serde_json::Map::new();
        obj.insert("error".into(), Value::String(msg.to_string()));
        if let Some(Value::Object(extra)) = data {
            for (k, v) in extra {
                obj.insert(k, v);
            }
        }
        println!("{}", serde_json::to_string_pretty(&Value::Object(obj)).unwrap());
    } else {
        eprintln!("sevra: {msg}");
    }
    exit(1);
}
