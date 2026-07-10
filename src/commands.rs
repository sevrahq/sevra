//! The command handlers — full parity with the retired TS CLI, including the
//! quality-pass behaviors (env-blind login, https-only hubs, non-JSON refusal,
//! symlink-following push under the 4 MB cap, export path containment + slug
//! validation, gated-page reporting). `validate` shells `dbmd` and never links
//! its library — Sevra's product tool consumes the standard through the same
//! public binary any third party gets.

use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::config::{self, Config, DEFAULT_HUB};
use crate::hub::{ensure_ok, request};
use crate::output::{fail, json_mode, note, out};
use crate::store::read_store;

const MAX_PUSH_BYTES: usize = 4 * 1024 * 1024;

fn enc(s: &str) -> String {
    // Percent-encode a path segment for a URL (RFC 3986 unreserved kept).
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("")
}

// --- login / logout / whoami -------------------------------------------------

pub fn login(flag_hub: Option<String>, key: Option<String>) {
    // Env-blind: login PERSISTS a hub, so a one-off SEVRA_HUB_URL must not
    // silently become the stored default. --hub is the explicit path.
    let hub = flag_hub
        .clone()
        .or(config::load_file().hub)
        .unwrap_or_else(|| DEFAULT_HUB.to_string());
    let hub = hub.strip_suffix('/').unwrap_or(&hub).to_string();
    if flag_hub.is_none() {
        if let Some(env_hub) = config::env_nonempty("SEVRA_HUB_URL") {
            if env_hub.strip_suffix('/').unwrap_or(&env_hub) != hub {
                note(&format!("note: SEVRA_HUB_URL is ignored by login — pass --hub {env_hub} to store that hub"));
            }
        }
    }
    let key = key.unwrap_or_else(|| {
        fail("provide a key: `sevra login --key vc_account_…` (create one in the dashboard). SEVRA_API_KEY also works.", None)
    });

    let probe_cfg = Config { hub: hub.clone(), key: Some(key.clone()) };
    let probe = request(&probe_cfg, "GET", "/api/hub/me", None, true);
    let email = probe.body.as_ref().and_then(|b| b.get("email")).and_then(|e| e.as_str()).map(String::from);
    if probe.status != 200 || email.is_none() {
        let suffix = if probe.body.is_none() { ", non-JSON response" } else { "" };
        fail(&format!("that key did not authenticate against {hub} (HTTP {}{suffix})", probe.status), None);
    }
    if let Err(e) = config::save(&hub, &key) {
        fail(&format!("could not write config: {e}"), None);
    }
    let mut data = probe.body.and_then(|b| b.as_object().cloned()).unwrap_or_default();
    data.insert("hub".into(), json!(hub));
    out(
        &format!("logged in to {hub} as {} (config: {})", email.unwrap(), config::config_path().display()),
        Some(Value::Object(data)),
    );
}

pub fn logout() {
    config::remove();
    out("logged out (removed ~/.sevra/config.json)", Some(json!({ "ok": true })));
}

pub fn whoami(cfg: &Config) {
    let me = ensure_ok(request(cfg, "GET", "/api/hub/me", None, true), "whoami");
    out(
        &format!("{} ({}) @ {}", str_field(&me, "email"), str_field(&me, "userId"), cfg.hub),
        Some(me),
    );
}

// --- brains ------------------------------------------------------------------

pub fn brains(cfg: &Config) {
    let r = ensure_ok(request(cfg, "GET", "/api/hub/brains", None, true), "list brains");
    let list = r.get("brains").and_then(|b| b.as_array()).cloned().unwrap_or_default();
    if json_mode() {
        out("", Some(json!({ "brains": list })));
        return;
    }
    if list.is_empty() {
        out("no brains yet — `sevra create <slug>`", None);
        return;
    }
    for b in list {
        out(&format!("{}\t{}\t{}\t{}", str_field(&b, "slug"), str_field(&b, "id"), str_field(&b, "visibility"), str_field(&b, "name")), None);
    }
}

pub fn create(cfg: &Config, slug: &str, name: Option<String>, scope: Option<String>, public: bool) {
    let body = json!({
        "slug": slug,
        "name": name,
        "scope": scope,
        "visibility": if public { "public" } else { "private" },
    });
    let b = ensure_ok(request(cfg, "POST", "/api/hub/brains", Some(&body), true), "create brain");
    out(
        &format!("created brain {} ({}, {})", str_field(&b, "slug"), str_field(&b, "id"), str_field(&b, "visibility")),
        Some(b),
    );
}

// --- push --------------------------------------------------------------------

pub fn push(cfg: &Config, dir: &str, brain: &str) {
    if !Path::new(dir).exists() {
        fail(&format!("store directory not found: {dir}"), None);
    }
    let store = read_store(dir).unwrap_or_else(|e| fail(&format!("could not read {dir}: {e}"), None));
    if store.files.is_empty() {
        fail(&format!("no .md files under {dir}"), None);
    }
    let payload = serde_json::to_value(&store).unwrap();
    let bytes = payload.to_string().len();
    if bytes > MAX_PUSH_BYTES {
        fail(
            &format!(
                "store is {:.1} MB as JSON — over the hub's push cap (~4 MB). Large brains sync a pack via presigned R2 upload (coming with the object store); push a smaller store for now.",
                bytes as f64 / 1024.0 / 1024.0
            ),
            Some(json!({ "bytes": bytes, "cap": MAX_PUSH_BYTES })),
        );
    }
    let file_count = store.files.len();
    let r = ensure_ok(
        request(cfg, "POST", &format!("/api/hub/brains/{}/push", enc(brain)), Some(&payload), true),
        "push",
    );
    let s = r.get("indexed").cloned().unwrap_or(json!({}));
    let n = |k: &str| s.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    out(
        &format!(
            "pushed {file_count} files → indexed {} docs, {} edges ({} broken), {} assets",
            n("documents"), n("edges"), n("brokenEdges"), n("assets")
        ),
        Some(r),
    );
}

// --- query / get / graph -----------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn query(
    cfg: &Config,
    brain: &str,
    text: Option<String>,
    type_: Option<String>,
    layer: Option<String>,
    meta_type: Option<String>,
    tag: Option<String>,
    order: Option<String>,
    limit: Option<String>,
    where_: Option<String>,
) {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(q) = text { params.push(("q".into(), q)); }
    for (k, v) in [("type", type_), ("layer", layer), ("meta-type", meta_type), ("tag", tag), ("order", order), ("limit", limit)] {
        if let Some(val) = v { params.push((k.into(), val)); }
    }
    if let Some(w) = where_ { params.push(("where".into(), w)); }
    let qs = params.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&");
    let r = ensure_ok(
        request(cfg, "GET", &format!("/api/hub/brains/{}/query?{qs}", enc(brain)), None, true),
        "query",
    );
    if json_mode() { out("", Some(r)); return; }
    out(&format!("{} result(s):", r.get("total").and_then(|t| t.as_i64()).unwrap_or(0)), None);
    for d in r.get("results").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
        let sum = d.get("summary").and_then(|s| s.as_str()).or_else(|| d.get("title").and_then(|t| t.as_str())).unwrap_or("");
        out(&format!("  {}\t{}\t{}", str_field(&d, "path"), str_field(&d, "type"), sum), None);
    }
}

pub fn get(cfg: &Config, brain: &str, reference: &str) {
    let key = if reference.contains('/') || reference.to_lowercase().ends_with(".md") { "path" } else { "id" };
    let r = ensure_ok(
        request(cfg, "GET", &format!("/api/hub/brains/{}/resolve?{key}={}", enc(brain), enc(reference)), None, true),
        "get",
    );
    if json_mode() { out("", Some(r)); return; }
    let d = r.get("document").cloned().unwrap_or(json!({}));
    let title = d.get("title").and_then(|t| t.as_str()).unwrap_or_else(|| str_field(&d, "path"));
    out(
        &format!(
            "# {title}\npath: {}\ntype: {}  meta-type: {}\nid: {}\n\n{}",
            str_field(&d, "path"), str_field(&d, "type"), str_field(&d, "metaType"), str_field(&d, "dbmdId"), str_field(&d, "body")
        ),
        None,
    );
}

pub fn graph(cfg: &Config, brain: &str, path: &str, dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| "both".into());
    if !["in", "out", "both"].contains(&dir.as_str()) {
        fail("--dir must be one of: in, out, both", None);
    }
    let r = ensure_ok(
        request(cfg, "GET", &format!("/api/hub/brains/{}/graph?path={}&dir={}", enc(brain), enc(path), enc(&dir)), None, true),
        "graph",
    );
    if json_mode() { out("", Some(r)); return; }
    let edges = |k: &str| r.get(k).and_then(|x| x.as_array()).cloned().unwrap_or_default();
    let back = edges("backlinks");
    out(&format!("backlinks ({}):", back.len()), None);
    for e in back {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) { "" } else { " (broken)" };
        out(&format!("  ← {}{broken}", str_field(&e, "srcPath")), None);
    }
    let outl = edges("outlinks");
    out(&format!("outlinks ({}):", outl.len()), None);
    for e in outl {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) { "" } else { " (broken)" };
        out(&format!("  → {}{broken}", str_field(&e, "dstPath")), None);
    }
}

// --- grants ------------------------------------------------------------------

pub fn grant(cfg: &Config, brain: &str, email: &str, write: bool) {
    let capability = if write { "write" } else { "read" };
    let body = json!({ "email": email, "capability": capability });
    let r = ensure_ok(
        request(cfg, "POST", &format!("/api/hub/brains/{}/grants", enc(brain)), Some(&body), true),
        "grant",
    );
    if r.get("pending").and_then(|p| p.as_bool()).unwrap_or(false) {
        out(&format!("invited {email} to {brain} ({capability}) — they get access when they sign up free"), Some(r));
    } else {
        out(&format!("granted {capability} on {brain} to {email}"), Some(r));
    }
}

pub fn grants(cfg: &Config, brain: &str) {
    let r = ensure_ok(request(cfg, "GET", &format!("/api/hub/brains/{}/grants", enc(brain)), None, true), "grants");
    if json_mode() { out("", Some(r)); return; }
    let list = r.get("grants").and_then(|g| g.as_array()).cloned().unwrap_or_default();
    if list.is_empty() { out("no grants", None); return; }
    for g in list {
        out(&format!("  {}\t{}\t{}", str_field(&g, "email"), str_field(&g, "capability"), str_field(&g, "id")), None);
    }
}

pub fn revoke(cfg: &Config, brain: &str, grant_id: &str) {
    ensure_ok(
        request(cfg, "DELETE", &format!("/api/hub/brains/{}/grants/{}", enc(brain), enc(grant_id)), None, true),
        "revoke",
    );
    out(&format!("revoked grant {grant_id}"), Some(json!({ "revoked": true })));
}

pub fn shared(cfg: &Config) {
    let r = ensure_ok(request(cfg, "GET", "/api/hub/shared", None, true), "shared");
    if json_mode() { out("", Some(r)); return; }
    let list = r.get("shared").and_then(|s| s.as_array()).cloned().unwrap_or_default();
    if list.is_empty() { out("nothing shared with you", None); return; }
    for b in list {
        out(&format!("  {}\t{}\t{}\t{}", str_field(&b, "slug"), str_field(&b, "id"), str_field(&b, "capability"), str_field(&b, "name")), None);
    }
}

// --- publish / unpublish / inbox / export ------------------------------------

pub fn publish(cfg: &Config, brain: &str) {
    let r = ensure_ok(request(cfg, "POST", &format!("/api/hub/brains/{}/publish", enc(brain)), None, true), "publish");
    if json_mode() { out("", Some(r)); return; }
    let layout_notes: Vec<String> = r.get("layoutErrors").and_then(|e| e.as_array()).cloned().unwrap_or_default()
        .iter().map(|e| format!("skipped (layout: site): {}", str_field(e, "message"))).collect();
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 {
        for m in &layout_notes { out(m, None); }
        out("nothing public to publish yet — make the brain public (`sevra` dashboard) or mark records `visibility: public`, then publish again.", None);
        return;
    }
    let url = str_field(&r, "url");
    out(&format!("published {count} page(s) → {url}"), None);
    for p in r.get("published").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
        out(&format!("  {url}/{}\t{}", str_field(&p, "pageSlug"), str_field(&p, "title")), None);
    }
    for m in &layout_notes { out(&format!("  {m}"), None); }
    let gated = r.get("gatedPages").and_then(|g| g.as_array()).cloned().unwrap_or_default();
    if !gated.is_empty() {
        let paths = gated.iter().map(|g| str_field(g, "docPath").to_string()).collect::<Vec<_>>().join(", ");
        out(&format!("  {} record(s) gated by audience — served behind Sign in with Sevra, never on public surfaces: {paths}", gated.len()), None);
    }
}

pub fn unpublish(cfg: &Config, brain: &str) {
    ensure_ok(request(cfg, "DELETE", &format!("/api/hub/brains/{}/publish", enc(brain)), None, true), "unpublish");
    out(&format!("unpublished {brain} (public pages pulled)"), Some(json!({ "unpublished": true })));
}

pub fn inbox(cfg: &Config, sub: &str, brain: &str) {
    if sub != "list" && sub != "drain" {
        fail("usage: sevra inbox list|drain <brain>", None);
    }
    let r = ensure_ok(
        request(cfg, "GET", &format!("/api/hub/brains/{}/inbox?limit=200", enc(brain)), None, true),
        "inbox",
    );
    if json_mode() || sub == "drain" {
        // drain prints the full payload as JSON regardless of mode (the BYO
        // agent's read half).
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
        return;
    }
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 { out("inbox empty — no submissions.", None); return; }
    out(&format!("{count} submission(s):"), None);
    for it in r.get("items").and_then(|i| i.as_array()).cloned().unwrap_or_default() {
        out(&format!("  {}  {}  {}  {}",
            it.get("created").and_then(|c| c.as_str()).unwrap_or("-"),
            it.get("app").and_then(|a| a.as_str()).unwrap_or("-"),
            str_field(&it, "submittedBy"),
            str_field(&it, "path")), None);
    }
}

/// Normalize + contain: the resolved write path must stay inside `root`.
fn contained(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() || rel.contains('\0') { return None; }
    let mut full = root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => full.push(c),
            _ => return None, // .. / root / prefix — reject outright
        }
    }
    if full == root { return None; }
    Some(full)
}

pub fn export(cfg: &Config, brain: &str, dir: Option<String>) {
    let r = ensure_ok(request(cfg, "GET", &format!("/api/hub/brains/{}/export", enc(brain)), None, true), "export");
    // The default dir name comes from the hub's slug — validate it before it
    // becomes a path (don't trust the hub response).
    let remote_slug = r.get("slug").and_then(|s| s.as_str())
        .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') && !s.starts_with('-'));
    let local_slug: String = brain.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' }).collect();
    let local_slug = local_slug.trim_matches('-');
    let dir = dir.unwrap_or_else(|| format!("./{}-export", remote_slug.unwrap_or(if local_slug.is_empty() { "brain" } else { local_slug })));
    let root = std::fs::canonicalize(".").unwrap_or_else(|_| PathBuf::from(".")).join(&dir);
    let root = normalize(&root);

    let files = r.get("files").and_then(|f| f.as_array()).cloned().unwrap_or_default();
    for f in &files {
        let path = f.get("path").and_then(|p| p.as_str());
        let content = f.get("content").and_then(|c| c.as_str());
        let (path, content) = match (path, content) {
            (Some(p), Some(c)) => (p, c),
            _ => fail("refusing malformed file entry from hub (path/content must be strings)", None),
        };
        let full = contained(&root, path).unwrap_or_else(|| fail(&format!("refusing unsafe export path: {path}"), None));
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&full, content).unwrap_or_else(|e| fail(&format!("write failed {}: {e}", full.display()), None));
    }
    let mut data = r.as_object().cloned().unwrap_or_default();
    data.remove("files");
    data.insert("dir".into(), json!(dir));
    data.insert("fileCount".into(), json!(files.len()));
    out(&format!("exported {} file(s) → {dir}", files.len()), Some(Value::Object(data)));
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => { out.pop(); }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// --- validate (shells dbmd) --------------------------------------------------

pub fn validate(dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| ".".into());
    if !Path::new(&dir).exists() {
        fail(&format!("directory not found: {dir}"), None);
    }
    match Command::new("dbmd").args(["validate", "--all"]).current_dir(&dir).status() {
        Ok(status) => {
            // A signal death (no code) is not a pass.
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => fail(&format!("could not run dbmd (is it installed? https://www.sevrahq.com/install): {e}"), None),
    }
}
