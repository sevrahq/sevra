//! The command handlers — full parity with the retired TS CLI, including the
//! quality-pass behaviors (env-blind login, https-only hubs, non-JSON refusal,
//! symlink-following bounded push, export path containment + slug
//! validation, gated-page reporting). `validate` shells `dbmd` and never links
//! its library — Sevra's product tool consumes the standard through the same
//! public binary any third party gets.

use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{self, Config, DEFAULT_HUB};
use crate::hub::{ensure_ok, get_presigned, put_presigned, request, NOT_LOGGED_IN};
use crate::output::{fail, json_mode, note, out, usage_fail};
use crate::store::{build_pack, read_store};

const MAX_JSON_PUSH_BYTES: usize = 4 * 1024 * 1024;
const MAX_STORE_FILES: usize = 100_000;
const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACK_BYTES: u64 = 256 * 1024 * 1024;
/// The hub's cap on one secret value (mirrored client-side so an oversized
/// paste fails fast, before any request).
const MAX_SECRET_VALUE_CHARS: usize = 4096;

fn enc(s: &str) -> String {
    // Percent-encode a path segment for a URL (RFC 3986 unreserved kept).
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                o.push(b as char)
            }
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
    // The apex 308s to www, and redirects strip the authorization header (the
    // safe default), so a valid key probed against the apex reads back as a
    // misleading 401. Normalize the one known apex to the canonical host.
    let hub = if hub == "https://sevrahq.com" {
        note("note: sevrahq.com redirects to www.sevrahq.com; storing the www host");
        DEFAULT_HUB.to_string()
    } else {
        hub
    };
    if flag_hub.is_none() {
        if let Some(env_hub) = config::env_nonempty("SEVRA_HUB_URL") {
            if env_hub.strip_suffix('/').unwrap_or(&env_hub) != hub {
                note(&format!("note: SEVRA_HUB_URL is ignored by login — pass --hub {env_hub} to store that hub"));
            }
        }
    }
    // The message promises SEVRA_API_KEY works — honor it: --key wins, the
    // env var is the fallback.
    let key = key.or_else(|| config::env_nonempty("SEVRA_API_KEY")).unwrap_or_else(|| {
        fail("provide a key: `sevra login --key sevra_account_…` (create one in the dashboard). SEVRA_API_KEY also works.", None)
    });
    // Trim paste artifacts + refuse non-token bytes NOW, so the stored file is
    // clean and the refusal happens at login, not on the next command.
    let key = crate::hub::clean_key(&key);

    let probe_cfg = Config {
        hub: hub.clone(),
        key: Some(key.clone()),
    };
    let probe = request(&probe_cfg, "GET", "/api/hub/me", None, true);
    let email = probe
        .body
        .as_ref()
        .and_then(|b| b.get("email"))
        .and_then(|e| e.as_str())
        .map(String::from);
    if probe.status != 200 || email.is_none() {
        let suffix = if probe.body.is_none() {
            ", non-JSON response"
        } else {
            ""
        };
        fail(
            &format!(
                "that key did not authenticate against {hub} (HTTP {}{suffix})",
                probe.status
            ),
            None,
        );
    }
    if let Err(e) = config::save(&hub, &key) {
        fail(&format!("could not write config: {e}"), None);
    }
    let mut data = probe
        .body
        .and_then(|b| b.as_object().cloned())
        .unwrap_or_default();
    data.insert("hub".into(), json!(hub));
    out(
        &format!(
            "logged in to {hub} as {} (config: {})",
            email.unwrap(),
            config::config_path().display()
        ),
        Some(Value::Object(data)),
    );
}

pub fn logout() {
    // Honest about what happened: a credential file that EXISTS but cannot be
    // removed must be a loud failure (the key would silently survive on disk),
    // and a no-op logout must not claim it removed anything.
    match config::remove() {
        Ok(true) => out(
            "logged out (removed ~/.sevra/config.json)",
            Some(json!({ "ok": true, "removed": true })),
        ),
        Ok(false) => out(
            "logged out (no stored credential to remove)",
            Some(json!({ "ok": true, "removed": false })),
        ),
        Err(e) => fail(
            &format!(
                "could not remove {} — the stored key is STILL on disk: {e}",
                config::config_path().display()
            ),
            None,
        ),
    }
}

pub fn whoami(cfg: &Config) {
    let me = ensure_ok(request(cfg, "GET", "/api/hub/me", None, true), "whoami");
    out(
        &format!(
            "{} ({}) @ {}",
            str_field(&me, "email"),
            str_field(&me, "userId"),
            cfg.hub
        ),
        Some(me),
    );
}

// --- brains ------------------------------------------------------------------

pub fn brains(cfg: &Config) {
    let r = ensure_ok(
        request(cfg, "GET", "/api/hub/brains", None, true),
        "list brains",
    );
    let list = r
        .get("brains")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    if json_mode() {
        out("", Some(json!({ "brains": list })));
        return;
    }
    if list.is_empty() {
        out("no brains yet — `sevra create <slug>`", None);
        return;
    }
    for b in list {
        out(
            &format!(
                "{}\t{}\t{}\t{}",
                str_field(&b, "slug"),
                str_field(&b, "id"),
                str_field(&b, "visibility"),
                str_field(&b, "name")
            ),
            None,
        );
    }
}

pub fn create(cfg: &Config, slug: &str, name: Option<String>, scope: Option<String>, public: bool) {
    let body = json!({
        "slug": slug,
        "name": name,
        "scope": scope,
        "visibility": if public { "public" } else { "private" },
    });
    let b = ensure_ok(
        request(cfg, "POST", "/api/hub/brains", Some(&body), true),
        "create brain",
    );
    out(
        &format!(
            "created brain {} ({}, {})",
            str_field(&b, "slug"),
            str_field(&b, "id"),
            str_field(&b, "visibility")
        ),
        Some(b),
    );
}

// --- push --------------------------------------------------------------------

pub fn push(cfg: &Config, dir: &str, brain: &str) {
    if !Path::new(dir).exists() {
        fail(&format!("store directory not found: {dir}"), None);
    }
    let store = match read_store(dir, MAX_STORE_BYTES) {
        Ok(s) => s,
        Err(None) => fail(
            "store exceeds the hub's 512 MB uncompressed snapshot limit",
            Some(json!({ "cap": MAX_STORE_BYTES })),
        ),
        Err(Some(e)) => fail(&format!("could not read {dir}: {e}"), None),
    };
    if store.files.is_empty() {
        fail(&format!("no .md files under {dir}"), None);
    }
    if store.files.len() > MAX_STORE_FILES {
        fail(
            "store exceeds the hub's 100,000-file snapshot limit",
            Some(json!({ "cap": MAX_STORE_FILES, "files": store.files.len() })),
        );
    }
    let payload = serde_json::to_value(&store).unwrap();
    let file_count = store.files.len();
    let payload_bytes = payload.to_string().len();
    let r = if payload_bytes <= MAX_JSON_PUSH_BYTES {
        ensure_ok(
            request(
                cfg,
                "POST",
                &format!("/api/hub/brains/{}/push", enc(brain)),
                Some(&payload),
                true,
            ),
            "push",
        )
    } else {
        let pack = build_pack(&store)
            .unwrap_or_else(|e| fail(&format!("could not build store pack: {e}"), None));
        if pack.len() as u64 > MAX_PACK_BYTES {
            fail(
                "compressed store snapshot exceeds the hub's 256 MB limit",
                Some(json!({ "cap": MAX_PACK_BYTES, "bytes": pack.len() })),
            );
        }
        let sha256 = format!("{:x}", Sha256::digest(&pack));
        let meta = json!({ "sha256": sha256, "bytes": pack.len() });
        let presigned = ensure_ok(
            request(
                cfg,
                "POST",
                &format!("/api/hub/brains/{}/packs/presign", enc(brain)),
                Some(&meta),
                true,
            ),
            "prepare pack upload",
        );
        let url = presigned
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("hub returned no pack upload URL", None));
        put_presigned(url, presigned.get("headers").unwrap_or(&Value::Null), &pack);
        ensure_ok(
            request(
                cfg,
                "POST",
                &format!("/api/hub/brains/{}/packs/commit", enc(brain)),
                Some(&meta),
                true,
            ),
            "commit pack",
        )
    };
    let s = r.get("indexed").cloned().unwrap_or(json!({}));
    let n = |k: &str| s.get(k).and_then(|v| v.as_i64()).unwrap_or(0);
    out(
        &format!(
            "pushed {file_count} files → indexed {} docs, {} edges ({} broken), {} assets",
            n("documents"),
            n("edges"),
            n("brokenEdges"),
            n("assets")
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
    limit: Option<u32>,
    where_: Option<String>,
) {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(q) = text {
        params.push(("q".into(), q));
    }
    for (k, v) in [
        ("type", type_),
        ("layer", layer),
        ("meta-type", meta_type),
        ("tag", tag),
        ("order", order),
        ("limit", limit.map(|n| n.to_string())),
    ] {
        if let Some(val) = v {
            params.push((k.into(), val));
        }
    }
    if let Some(w) = where_ {
        params.push(("where".into(), w));
    }
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/query?{qs}", enc(brain)),
            None,
            true,
        ),
        "query",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    out(
        &format!(
            "{} result(s):",
            r.get("total").and_then(|t| t.as_i64()).unwrap_or(0)
        ),
        None,
    );
    for d in r
        .get("results")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let sum = d
            .get("summary")
            .and_then(|s| s.as_str())
            .or_else(|| d.get("title").and_then(|t| t.as_str()))
            .unwrap_or("");
        out(
            &format!(
                "  {}\t{}\t{}",
                str_field(&d, "path"),
                str_field(&d, "type"),
                sum
            ),
            None,
        );
    }
}

pub fn get(cfg: &Config, brain: &str, reference: &str) {
    let key = if reference.contains('/') || reference.to_lowercase().ends_with(".md") {
        "path"
    } else {
        "id"
    };
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!(
                "/api/hub/brains/{}/resolve?{key}={}",
                enc(brain),
                enc(reference)
            ),
            None,
            true,
        ),
        "get",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let d = r.get("document").cloned().unwrap_or(json!({}));
    let title = d
        .get("title")
        .and_then(|t| t.as_str())
        .unwrap_or_else(|| str_field(&d, "path"));
    out(
        &format!(
            "# {title}\npath: {}\ntype: {}  meta-type: {}\nid: {}\n\n{}",
            str_field(&d, "path"),
            str_field(&d, "type"),
            str_field(&d, "metaType"),
            str_field(&d, "dbmdId"),
            str_field(&d, "body")
        ),
        None,
    );
}

pub fn graph(cfg: &Config, brain: &str, path: &str, dir: Option<String>) {
    // clap's value_parser already constrained --dir to in|out|both.
    let dir = dir.unwrap_or_else(|| "both".into());
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!(
                "/api/hub/brains/{}/graph?path={}&dir={}",
                enc(brain),
                enc(path),
                enc(&dir)
            ),
            None,
            true,
        ),
        "graph",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let edges = |k: &str| {
        r.get(k)
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
    };
    let back = edges("backlinks");
    out(&format!("backlinks ({}):", back.len()), None);
    for e in back {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) {
            ""
        } else {
            " (broken)"
        };
        out(&format!("  ← {}{broken}", str_field(&e, "srcPath")), None);
    }
    let outl = edges("outlinks");
    out(&format!("outlinks ({}):", outl.len()), None);
    for e in outl {
        let broken = if e.get("resolved").and_then(|b| b.as_bool()).unwrap_or(false) {
            ""
        } else {
            " (broken)"
        };
        out(&format!("  → {}{broken}", str_field(&e, "dstPath")), None);
    }
}

// --- grants ------------------------------------------------------------------

pub fn grant(cfg: &Config, brain: &str, email: &str, write: bool) {
    let capability = if write { "write" } else { "read" };
    let body = json!({ "email": email, "capability": capability });
    let r = ensure_ok(
        request(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/grants", enc(brain)),
            Some(&body),
            true,
        ),
        "grant",
    );
    if r.get("pending").and_then(|p| p.as_bool()).unwrap_or(false) {
        out(&format!("invited {email} to {brain} ({capability}) — they get access when they sign up free"), Some(r));
    } else {
        out(
            &format!("granted {capability} on {brain} to {email}"),
            Some(r),
        );
    }
}

pub fn grants(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/grants", enc(brain)),
            None,
            true,
        ),
        "grants",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let list = r
        .get("grants")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        out("no grants", None);
        return;
    }
    for g in list {
        out(
            &format!(
                "  {}\t{}\t{}",
                str_field(&g, "email"),
                str_field(&g, "capability"),
                str_field(&g, "id")
            ),
            None,
        );
    }
}

pub fn revoke(cfg: &Config, brain: &str, grant_id: &str) {
    ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/grants/{}", enc(brain), enc(grant_id)),
            None,
            true,
        ),
        "revoke",
    );
    out(
        &format!("revoked grant {grant_id}"),
        Some(json!({ "revoked": true })),
    );
}

pub fn shared(cfg: &Config) {
    let r = ensure_ok(request(cfg, "GET", "/api/hub/shared", None, true), "shared");
    if json_mode() {
        out("", Some(r));
        return;
    }
    let list = r
        .get("shared")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    if list.is_empty() {
        out("nothing shared with you", None);
        return;
    }
    for b in list {
        out(
            &format!(
                "  {}\t{}\t{}\t{}",
                str_field(&b, "slug"),
                str_field(&b, "id"),
                str_field(&b, "capability"),
                str_field(&b, "name")
            ),
            None,
        );
    }
}

// --- publish / unpublish / inbox / export ------------------------------------

pub fn publish(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "POST",
            &format!("/api/hub/brains/{}/publish", enc(brain)),
            None,
            true,
        ),
        "publish",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let layout_notes: Vec<String> = r
        .get("layoutErrors")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|e| format!("skipped (layout: site): {}", str_field(e, "message")))
        .collect();
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 {
        for m in &layout_notes {
            out(m, None);
        }
        out("nothing public to publish yet — make the brain public (`sevra` dashboard) or mark records `visibility: public`, then publish again.", None);
        return;
    }
    let url = str_field(&r, "url");
    out(&format!("published {count} page(s) → {url}"), None);
    for p in r
        .get("published")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default()
    {
        out(
            &format!(
                "  {url}/{}\t{}",
                str_field(&p, "pageSlug"),
                str_field(&p, "title")
            ),
            None,
        );
    }
    for m in &layout_notes {
        out(&format!("  {m}"), None);
    }
    let gated = r
        .get("gatedPages")
        .and_then(|g| g.as_array())
        .cloned()
        .unwrap_or_default();
    if !gated.is_empty() {
        let paths = gated
            .iter()
            .map(|g| str_field(g, "docPath").to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out(&format!("  {} record(s) gated by audience — served behind Sign in with Sevra, never on public surfaces: {paths}", gated.len()), None);
    }
}

pub fn unpublish(cfg: &Config, brain: &str) {
    ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/publish", enc(brain)),
            None,
            true,
        ),
        "unpublish",
    );
    out(
        &format!("unpublished {brain} (public pages pulled)"),
        Some(json!({ "unpublished": true })),
    );
}

pub fn inbox(cfg: &Config, action: &str, brain: &str) {
    // clap's value_parser already constrained the action to list|drain.
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/inbox?limit=200", enc(brain)),
            None,
            true,
        ),
        "inbox",
    );
    if json_mode() || action == "drain" {
        // drain prints the full payload as JSON regardless of mode (the BYO
        // agent's read half).
        println!("{}", serde_json::to_string_pretty(&r).unwrap());
        return;
    }
    let count = r.get("count").and_then(|c| c.as_i64()).unwrap_or(0);
    if count == 0 {
        out("inbox empty — no submissions.", None);
        return;
    }
    out(&format!("{count} submission(s):"), None);
    for it in r
        .get("items")
        .and_then(|i| i.as_array())
        .cloned()
        .unwrap_or_default()
    {
        out(
            &format!(
                "  {}  {}  {}  {}",
                it.get("created").and_then(|c| c.as_str()).unwrap_or("-"),
                it.get("app").and_then(|a| a.as_str()).unwrap_or("-"),
                str_field(&it, "submittedBy"),
                str_field(&it, "path")
            ),
            None,
        );
    }
}

/// Normalize + contain: the resolved write path must stay inside `root`.
fn contained(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() || rel.contains('\0') {
        return None;
    }
    let mut full = root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(c) => full.push(c),
            _ => return None, // .. / root / prefix — reject outright
        }
    }
    if full == root {
        return None;
    }
    Some(full)
}

fn entries_from_pack(bytes: Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .unwrap_or_else(|e| fail(&format!("hub returned an invalid store pack: {e}"), None));
    if archive.is_empty() || archive.len() > 100_000 {
        fail("hub returned a store pack with an invalid file count", None);
    }
    let mut entries = Vec::with_capacity(archive.len());
    let mut seen = std::collections::HashSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .unwrap_or_else(|e| fail(&format!("could not read store pack entry: {e}"), None));
        if file.is_dir() {
            continue;
        }
        let path = file.name().to_string();
        if file.enclosed_name().is_none() || contained(Path::new("/store"), &path).is_none() {
            fail(&format!("refusing unsafe export path: {path}"), None);
        }
        if let Some(mode) = file.unix_mode() {
            let kind = mode & 0o170000;
            if kind != 0 && kind != 0o100000 {
                fail(&format!("refusing non-file ZIP entry: {path}"), None);
            }
        }
        if !seen.insert(path.clone()) {
            fail(&format!("refusing duplicate export path: {path}"), None);
        }
        total = total.saturating_add(file.size());
        if total > MAX_STORE_BYTES {
            fail("store pack expands beyond the 512 MB limit", None);
        }
        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .unwrap_or_else(|e| fail(&format!("could not decompress {path}: {e}"), None));
        if content.len() as u64 != file.size() {
            fail(&format!("store pack entry length mismatch: {path}"), None);
        }
        entries.push((path, content));
    }
    if entries.is_empty() {
        fail("hub returned an empty store pack", None);
    }
    entries
}

pub fn export(cfg: &Config, brain: &str, dir: Option<String>) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/export?format=pack", enc(brain)),
            None,
            true,
        ),
        "export",
    );
    // The default dir name comes from the hub's slug — validate it before it
    // becomes a path (don't trust the hub response).
    let remote_slug = r.get("slug").and_then(|s| s.as_str()).filter(|s| {
        !s.is_empty()
            && s.len() <= 63
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !s.starts_with('-')
            && !s.ends_with('-')
    });
    let local_slug: String = brain
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let local_slug = local_slug.trim_matches('-');
    let dir = dir.unwrap_or_else(|| {
        format!(
            "./{}-export",
            remote_slug.unwrap_or(if local_slug.is_empty() {
                "brain"
            } else {
                local_slug
            })
        )
    });
    let root = std::fs::canonicalize(".")
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(&dir);
    let root = normalize(&root);

    let entries: Vec<(String, Vec<u8>)> = if let Some(url) = r.get("url").and_then(Value::as_str) {
        let expected = r
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or_else(|| fail("hub returned an invalid pack hash", None));
        let pack = get_presigned(url, MAX_PACK_BYTES);
        let actual = format!("{:x}", Sha256::digest(&pack));
        if actual != expected {
            fail("downloaded store pack failed SHA-256 verification", None);
        }
        entries_from_pack(pack)
    } else {
        let files = r
            .get("files")
            .and_then(Value::as_array)
            .unwrap_or_else(|| fail("hub returned neither a store pack nor files", None));
        files
            .iter()
            .map(|file| {
                let path = file
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("refusing malformed file path from hub", None));
                let content = file
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("refusing malformed file content from hub", None));
                (path.to_string(), content.as_bytes().to_vec())
            })
            .collect()
    };

    // Gate the entire remote manifest before the first filesystem mutation.
    let mut seen = std::collections::HashSet::new();
    for (path, _) in &entries {
        if contained(&root, path).is_none() {
            fail(&format!("refusing unsafe export path: {path}"), None);
        }
        if !seen.insert(path) {
            fail(&format!("refusing duplicate export path: {path}"), None);
        }
    }
    std::fs::create_dir_all(&root)
        .unwrap_or_else(|e| fail(&format!("cannot create {}: {e}", root.display()), None));
    let real_root = std::fs::canonicalize(&root)
        .unwrap_or_else(|e| fail(&format!("cannot resolve {}: {e}", root.display()), None));
    for (path, content) in &entries {
        let full = contained(&root, path)
            .unwrap_or_else(|| fail(&format!("refusing unsafe export path: {path}"), None));
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                fail(&format!("cannot create {}: {e}", parent.display()), None)
            });
            // The lexical containment above can be defeated by a symlinked
            // subdir INSIDE an existing target dir — re-check the REAL parent
            // after creation (exports into a fresh dir are unaffected).
            let real_parent = std::fs::canonicalize(parent).unwrap_or_else(|e| {
                fail(&format!("cannot resolve {}: {e}", parent.display()), None)
            });
            if !real_parent.starts_with(&real_root) {
                fail(
                    &format!(
                        "refusing export through a symlink escaping {}: {path}",
                        root.display()
                    ),
                    None,
                );
            }
        }
        // Never write THROUGH a pre-existing symlink at the leaf: a planted
        // link inside the target dir would redirect the write outside it
        // (the parent re-check above only covers directories).
        if let Ok(m) = std::fs::symlink_metadata(&full) {
            if m.file_type().is_symlink() {
                fail(
                    &format!("refusing to overwrite a symlink: {}", full.display()),
                    None,
                );
            }
        }
        std::fs::write(&full, content)
            .unwrap_or_else(|e| fail(&format!("write failed {}: {e}", full.display()), None));
    }
    let mut data = r.as_object().cloned().unwrap_or_default();
    data.remove("files");
    data.remove("url");
    data.insert("dir".into(), json!(dir));
    data.insert("fileCount".into(), json!(entries.len()));
    out(
        &format!("exported {} file(s) → {dir}", entries.len()),
        Some(Value::Object(data)),
    );
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

// --- secrets (the vault) -------------------------------------------------------
//
// Write-only Cloudflare secret values bound to the brain's published functions
// (docs: /docs/publishing.md, "Functions + the vault"). The security contract,
// locked by tests: the VALUE is read from stdin only — never argv (argv is
// visible to every process on the machine), never echoed back on any path
// (prompts, errors, --json included). NAMES are public metadata (records
// declare them; the dashboard lists them) and are clap-validated to the hub's
// exact shape before any request.

/// clap value_parser for a secret NAME — the hub's gate, mirrored exactly:
/// `^[A-Z][A-Z0-9_]{0,63}$`. Refusal is a usage error (exit 2) before any I/O.
pub fn parse_secret_name(s: &str) -> Result<String, String> {
    let ok = matches!(s.as_bytes().first(), Some(b'A'..=b'Z'))
        && s.len() <= 64
        && s.bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'));
    if ok {
        Ok(s.to_string())
    } else {
        Err(
            "secret names are UPPER_SNAKE_CASE: start with A-Z, then A-Z/0-9/_, at most 64 chars (e.g. STRIPE_KEY)"
                .into(),
        )
    }
}

/// Trim exactly ONE trailing newline (`\n` or `\r\n`) — so `printf %s "$V" |`
/// and `echo "$V" |` both deliver the same value, while a value that really
/// ends in a newline can still be sent by appending one more.
fn trim_one_newline(mut s: String) -> String {
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    s
}

/// Read the secret VALUE: prompted on the controlling terminal with echo OFF
/// when stdin is a TTY (rpassword talks to /dev/tty directly, so `--json`
/// stdout stays clean), else read whole from piped stdin. Never from argv;
/// never echoed — the refusal messages below name sizes and shapes, never
/// bytes.
fn secret_value_from_stdin(name: &str) -> String {
    use std::io::{IsTerminal, Read};
    let value = if std::io::stdin().is_terminal() {
        match rpassword::prompt_password(format!("value for {name} (input hidden): ")) {
            Ok(v) => v,
            Err(e) => fail(
                &format!(
                    "could not read from the terminal: {e} — pipe the value instead: printf %s \"$VALUE\" | sevra secrets set <brain> {name}"
                ),
                None,
            ),
        }
    } else {
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            fail(
                &format!("could not read the value from stdin (it must be UTF-8): {e}"),
                None,
            );
        }
        trim_one_newline(buf)
    };
    if value.is_empty() {
        fail(
            &format!(
                "empty value — pipe the secret on stdin: printf %s \"$VALUE\" | sevra secrets set <brain> {name}"
            ),
            None,
        );
    }
    if value.chars().count() > MAX_SECRET_VALUE_CHARS {
        fail(
            &format!(
                "the value is {} characters — the hub caps one secret at {MAX_SECRET_VALUE_CHARS}",
                value.chars().count()
            ),
            None,
        );
    }
    value
}

pub fn secrets_list(cfg: &Config, brain: &str) {
    let r = ensure_ok(
        request(
            cfg,
            "GET",
            &format!("/api/hub/brains/{}/secrets", enc(brain)),
            None,
            true,
        ),
        "secrets list",
    );
    if json_mode() {
        out("", Some(r));
        return;
    }
    let names: Vec<&str> = r
        .get("secrets")
        .and_then(|s| s.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if names.is_empty() {
        out(
            "no secrets provisioned — printf %s \"$VALUE\" | sevra secrets set <brain> NAME",
            None,
        );
    } else {
        out(
            &format!(
                "secrets ({}, values write-only): {}",
                names.len(),
                names.join(", ")
            ),
            None,
        );
    }
    let fns = r
        .get("functions")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default();
    if fns.is_empty() {
        return;
    }
    out(&format!("functions ({}):", fns.len()), None);
    let join = |f: &Value, key: &str| -> String {
        let items: Vec<&str> = f
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        if items.is_empty() {
            "-".into()
        } else {
            items.join(", ")
        }
    };
    for f in &fns {
        let live = if f.get("live").and_then(|l| l.as_bool()).unwrap_or(false) {
            "live"
        } else {
            "not live"
        };
        out(
            &format!(
                "  {}\t{}\tneeds: {}\tegress: {}",
                str_field(f, "name"),
                live,
                join(f, "secrets"),
                join(f, "egress")
            ),
            None,
        );
    }
}

pub fn secrets_set(cfg: &Config, brain: &str, name: &str, value_in_argv: bool) {
    if value_in_argv {
        // The trap arguments exist so this refusal happens WITHOUT echoing
        // what clap's own unexpected-argument error would have printed. The
        // argv exposure itself already happened at the OS level — say so.
        usage_fail(
            "the secret value is never taken from the command line (argv is visible to every process on the machine; it was NOT echoed here, but treat it as exposed). Pipe it on stdin instead: printf %s \"$VALUE\" | sevra secrets set <brain> NAME",
        );
    }
    // Before the prompt: never ask for a secret this process cannot send.
    if cfg.key.is_none() {
        fail(NOT_LOGGED_IN, None);
    }
    let value = secret_value_from_stdin(name);
    let body = json!({ "name": name, "value": value });
    let r = ensure_ok(
        request(
            cfg,
            "PUT",
            &format!("/api/hub/brains/{}/secrets", enc(brain)),
            Some(&body),
            true,
        ),
        "secrets set",
    );
    let hub_note = str_field(&r, "note");
    let human = if hub_note.is_empty() {
        format!("set secret {name} on {brain} (write-only)")
    } else {
        format!("set secret {name} on {brain} — {hub_note}")
    };
    out(&human, Some(r));
}

pub fn secrets_delete(cfg: &Config, brain: &str, name: &str) {
    let body = json!({ "name": name });
    let r = ensure_ok(
        request(
            cfg,
            "DELETE",
            &format!("/api/hub/brains/{}/secrets", enc(brain)),
            Some(&body),
            true,
        ),
        "secrets delete",
    );
    let mut data = r.as_object().cloned().unwrap_or_default();
    data.insert("name".into(), json!(name));
    out(
        &format!("deleted secret {name} from {brain} (unbound from its functions)"),
        Some(Value::Object(data)),
    );
}

// --- validate (shells dbmd) --------------------------------------------------

pub fn validate(dir: Option<String>) {
    let dir = dir.unwrap_or_else(|| ".".into());
    // is_dir, not exists: handing dbmd a FILE as its working dir would fail
    // with a spawn error that misreads as "dbmd is not installed".
    if !Path::new(&dir).is_dir() {
        fail(&format!("directory not found: {dir}"), None);
    }
    // The --json contract holds THROUGH the shell-out: dbmd has its own
    // global --json, so machine mode forwards it.
    let mut args = vec!["validate", "--all"];
    if json_mode() {
        args.push("--json");
    }
    match Command::new("dbmd").args(&args).current_dir(&dir).status() {
        Ok(status) => {
            // A signal death (no code) is not a pass.
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => fail(
            &format!("could not run dbmd (is it installed? https://www.sevrahq.com/install): {e}"),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contained_rejects_escapes() {
        let root = Path::new("/safe/root");
        assert!(contained(root, "notes/a.md").is_some());
        assert!(contained(root, "a.md").is_some());
        assert!(contained(root, "../a.md").is_none());
        assert!(contained(root, "notes/../../a.md").is_none());
        assert!(contained(root, "/etc/passwd").is_none());
        assert!(contained(root, "").is_none());
        assert!(contained(root, "a\0b").is_none());
        assert!(contained(root, "./a.md").is_none()); // hub paths are normalized; `./` is refused
    }

    #[test]
    fn normalize_pops_parents_lexically() {
        assert_eq!(
            normalize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
    }

    #[test]
    fn secret_name_shape_matches_the_hub_gate() {
        // ^[A-Z][A-Z0-9_]{0,63}$ — mirrored exactly, boundaries included.
        let max = "A".repeat(64);
        for good in ["A", "STRIPE_KEY", "A1_B2_C3", "OPENAI_API_KEY", &max] {
            assert!(parse_secret_name(good).is_ok(), "should accept {good}");
        }
        let over = "A".repeat(65);
        for bad in [
            "",
            "a",
            "lower_case",
            "1LEADING",
            "_LEADING",
            "HAS-DASH",
            "HAS SPACE",
            "Ä",
            "A\n",
            &over,
        ] {
            assert!(
                parse_secret_name(bad).is_err(),
                "should reject {}",
                bad.escape_debug()
            );
        }
    }

    #[test]
    fn trim_one_newline_trims_exactly_one() {
        assert_eq!(trim_one_newline("v\n".into()), "v");
        assert_eq!(trim_one_newline("v".into()), "v");
        assert_eq!(trim_one_newline("v\n\n".into()), "v\n"); // exactly one
        assert_eq!(trim_one_newline("v\r\n".into()), "v"); // CRLF is one newline
        assert_eq!(trim_one_newline("v\r".into()), "v\r"); // a bare CR is data
        assert_eq!(trim_one_newline("\n".into()), "");
        assert_eq!(trim_one_newline("multi\nline\n".into()), "multi\nline");
    }
}
