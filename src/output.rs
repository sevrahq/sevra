//! Output contract, identical to the TS CLI: `--json` makes stdout
//! machine-readable on EVERY command, including errors; human mode prints a
//! plain line and sends errors to stderr with a `sevra:` prefix. Informational
//! notices always go to stderr so they never corrupt `--json` stdout.

use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

static JSON_MODE: AtomicBool = AtomicBool::new(false);

/// Make an untrusted scalar inert before it reaches a terminal.
///
/// JSON output is already escaped by serde. Human output is different: brain
/// names, paths, record bodies, and hub error strings can all be remote or
/// store-controlled. ESC/CSI/OSC, BEL, carriage return, backspace, and the
/// rest of C0/C1 can rewrite the terminal, forge lines, set titles, or plant
/// clipboard contents. Escape every control scalar, including LF and TAB:
/// only call-site literals may create terminal layout.
pub fn terminal_safe(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => safe.push_str("\\n"),
            '\r' => safe.push_str("\\r"),
            '\t' => safe.push_str("\\t"),
            _ if c.is_control() || terminal_format_control(c) => {
                use std::fmt::Write;
                let _ = write!(safe, "\\u{{{:04x}}}", c as u32);
            }
            _ => safe.push(c),
        }
    }
    safe
}

fn terminal_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}' // soft hyphen
            | '\u{061c}' // Arabic letter mark
            | '\u{180e}' // Mongolian vowel separator
            | '\u{200b}'..='\u{200f}' // zero-width + bidi marks
            | '\u{2028}'..='\u{202e}' // Unicode line/paragraph + bidi overrides
            | '\u{2060}'..='\u{206f}' // word joiner + bidi isolates/controls
            | '\u{feff}' // zero-width no-break space
            | '\u{fff9}'..='\u{fffb}' // interlinear annotation controls
            | '\u{e0001}' // language tag
            | '\u{e0020}'..='\u{e007f}' // invisible tag characters
    )
}

/// Trusted program-authored layout may keep LF/TAB while still neutralizing
/// every terminal command control. Never pass a remote/store scalar here.
pub fn terminal_layout_safe(text: &str) -> String {
    let mut safe = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '\n' || c == '\t' {
            safe.push(c);
        } else if c.is_control() || terminal_format_control(c) {
            use std::fmt::Write;
            let _ = write!(safe, "\\u{{{:04x}}}", c as u32);
        } else {
            safe.push(c);
        }
    }
    safe
}

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
        println!(
            "{}",
            serde_json::to_string_pretty(&data.unwrap_or_else(|| json!({}))).unwrap()
        );
    } else {
        println!("{}", terminal_safe(human));
    }
}

/// Print program-authored multi-line/tabular layout whose interpolated fields
/// have already passed through `terminal_safe`.
///
/// Keeping this separate from `out` makes the secure default a scalar: a new
/// call site cannot accidentally let an untrusted newline forge output.
pub fn out_layout(human: &str, data: Option<Value>) {
    if json_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(&data.unwrap_or_else(|| json!({}))).unwrap()
        );
    } else {
        println!("{}", terminal_layout_safe(human));
    }
}

/// A notice to the operator (agent or human) that must not touch stdout in
/// `--json` mode.
pub fn note(msg: &str) {
    eprintln!("sevra: {}", terminal_safe(msg));
}

/// A usage error detected AFTER clap parsing (exit 2, matching clap's own
/// usage errors, so agents keep the 1-vs-2 exit-code split). Exists because
/// clap's error rendering echoes the offending VALUE — unusable when the
/// offense is a secret that must never reach stdout or stderr.
pub fn usage_fail(msg: &str) -> ! {
    if json_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "error": msg })).unwrap()
        );
    } else {
        eprintln!("sevra: {}", terminal_safe(msg));
    }
    exit(2);
}

/// Fail: in `--json` mode emit `{ "error": msg, ...data }` on stdout (so a
/// parsing agent still gets structured output); in human mode print
/// `sevra: msg` on stderr. Always exit 1.
pub fn fail(msg: &str, data: Option<Value>) -> ! {
    if json_mode() {
        let mut obj = serde_json::Map::new();
        // Extras first: `error` must always be OUR formatted message — a hub
        // body that itself carries an `error` key must not clobber it (the
        // formatted message embeds the hub's text plus the HTTP status).
        if let Some(Value::Object(extra)) = data {
            for (k, v) in extra {
                obj.insert(k, v);
            }
        }
        obj.insert("error".into(), Value::String(msg.to_string()));
        println!(
            "{}",
            serde_json::to_string_pretty(&Value::Object(obj)).unwrap()
        );
    } else {
        eprintln!("sevra: {}", terminal_safe(msg));
    }
    exit(1);
}

#[cfg(test)]
mod tests {
    use super::terminal_safe;

    #[test]
    fn terminal_scalar_escapes_layout_ansi_osc_and_line_rewrites() {
        let hostile = "ok\n\t\u{1b}[31mred\u{1b}[0m\u{1b}]52;c;Y2xpcA==\u{7}\rPWN\u{8}\u{202e}txt";
        let safe = terminal_safe(hostile);
        assert!(safe.starts_with(r"ok\n\t"));
        assert!(!safe.contains('\n'));
        assert!(!safe.contains('\t'));
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\u{7}'));
        assert!(!safe.contains('\r'));
        assert!(!safe.contains('\u{8}'));
        assert!(!safe.contains('\u{202e}'));
        assert!(safe.contains(r"\u{001b}[31m"));
        assert!(safe.contains(r"\u{0007}\rPWN\u{0008}"));
        assert!(safe.contains(r"\u{202e}txt"));
    }

    #[test]
    fn trusted_layout_keeps_only_lf_and_tab() {
        let safe = super::terminal_layout_safe("one\n\ttwo\u{1b}\r\u{202e}txt");
        assert_eq!(safe, "one\n\ttwo\\u{001b}\\u{000d}\\u{202e}txt");
    }
}
