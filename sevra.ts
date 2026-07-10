#!/usr/bin/env node
/**
 * sevra — the product CLI for the Sevra hub (the managed home for db.md brains).
 *
 * The primary way to use a hosted brain: push a local db.md store up, query it
 * back, share it. Wraps the hub API; shells `dbmd` for local db.md operations
 * (validate). The neutral link.md client verbs (resolve/sync/grant/propose/
 * subscribe) move into `dbmd` itself as the standards layer — this is the
 * Sevra-specific product surface (login/brains/push/query/grant).
 *
 *   sevra login --key vc_account_…      # store your hub credential (~/.sevra)
 *   sevra whoami
 *   sevra brains                        # list your brains
 *   sevra create acme --name "Acme" --scope agency
 *   sevra push ./my-store --brain acme  # index-on-push (the migration is the demo)
 *   sevra query acme "scope creep" --type client
 *   sevra get acme records/clients/lumio.md
 *   sevra graph acme records/clients/lumio.md
 *   sevra grant acme teammate@acme.com --write
 *   sevra shared                        # brains shared WITH you
 *   sevra validate ./my-store           # wraps `dbmd validate --all`
 *   sevra version                       # this build's stamp
 *   sevra update                        # self-replace with the hub's current build
 *
 * Config precedence: env (SEVRA_HUB_URL / SEVRA_API_KEY) > ~/.sevra/config.json.
 * Add --json to any command for machine-readable output (agent-friendly).
 *
 * License: MIT (cli/LICENSE). The served build (install/sevra.cjs) embeds the
 * full license text in its banner — tsc strips source comments.
 * Public mirror: https://github.com/sevrahq/sevra — after changing this file
 * (or LICENSE / README.public.md / install/sevra.sh / sevra.pub), run
 * `npm run sevra:sync` so the mirror never drifts.
 * SPDX-License-Identifier: MIT
 */

import { spawnSync } from "node:child_process";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
  existsSync,
  realpathSync,
  renameSync,
} from "node:fs";
import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";

const DEFAULT_HUB = "https://www.sevrahq.com";
const CONFIG_DIR = join(homedir(), ".sevra");
const CONFIG_PATH = join(CONFIG_DIR, "config.json");

// Replaced by scripts/build-sevra-cli.sh in the served artifact; "dev" means
// running from source (ts-node), where update/nudge are disabled.
const BUILD = "dev";
const BUILD_DATE = "unreleased";

// The hub's JSON push cap (mirrors MAX_PUSH_BYTES in the push route) — checked
// client-side so an oversized store fails fast with guidance instead of an
// opaque platform 413 or a mid-upload connection reset.
const MAX_PUSH_BYTES = 4 * 1024 * 1024;

// --- config -----------------------------------------------------------------

interface Config {
  hub: string;
  key?: string;
}

function loadConfigFile(): Partial<Config> {
  if (!existsSync(CONFIG_PATH)) return {};
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
  } catch {
    return {}; /* ignore a corrupt config */
  }
}

function loadConfig(): Config {
  const file = loadConfigFile();
  return {
    hub: (process.env.SEVRA_HUB_URL || file.hub || DEFAULT_HUB).replace(/\/$/, ""),
    key: process.env.SEVRA_API_KEY || file.key,
  };
}

function saveConfig(cfg: Config): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o600 });
}

// --- arg parsing (hand-rolled — no dep) -------------------------------------

// Boolean flags never consume the next token — `sevra query acme --json "x"`
// must not swallow the query text as --json's value.
const BOOL_FLAGS = new Set(["json", "public", "write", "help", "version"]);
const VALUE_FLAGS = new Set([
  "key", "hub", "name", "scope", "brain",
  "type", "layer", "meta-type", "tag", "where", "limit", "order", "dir",
]);

interface Args {
  positional: string[];
  flags: Record<string, string | boolean>;
  problems: string[];
}
function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  const problems: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      positional.push(a);
      continue;
    }
    const body = a.slice(2);
    const eq = body.indexOf("=");
    const key = eq === -1 ? body : body.slice(0, eq);
    if (BOOL_FLAGS.has(key)) {
      if (eq !== -1) problems.push(`--${key} takes no value`);
      else flags[key] = true;
    } else if (VALUE_FLAGS.has(key)) {
      if (eq !== -1) {
        flags[key] = body.slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next === undefined || next.startsWith("--")) problems.push(`--${key} needs a value`);
        else {
          flags[key] = next;
          i++;
        }
      }
    } else {
      problems.push(`unknown flag --${key}`);
    }
  }
  return { positional, flags, problems };
}
function flagStr(flags: Args["flags"], name: string): string | undefined {
  const v = flags[name];
  return typeof v === "string" ? v : undefined;
}

// --- output -----------------------------------------------------------------

let jsonMode = false;
function out(human: string, data?: unknown): void {
  if (jsonMode) console.log(JSON.stringify(data ?? {}, null, 2));
  else console.log(human);
}
function fail(msg: string, data?: unknown): never {
  if (jsonMode)
    console.log(
      JSON.stringify({ error: msg, ...((data as Record<string, unknown>) ?? {}) }, null, 2),
    );
  else console.error(`sevra: ${msg}`);
  process.exit(1);
}

// --- hub client -------------------------------------------------------------

// The bearer key must never travel in cleartext; only loopback hosts may skip
// TLS (local dev against `npm run dev`).
function assertSafeHub(hubUrl: string): void {
  let u: URL;
  try {
    u = new URL(hubUrl);
  } catch {
    fail(`invalid hub URL: ${hubUrl}`);
  }
  const loopback =
    u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]" || u.hostname === "::1";
  if (u.protocol !== "https:" && !loopback) {
    fail(`refusing non-HTTPS hub ${hubUrl} — your API key would travel in cleartext (localhost is exempt)`);
  }
}

// --- signed artifact fetch (self-update integrity) ---------------------------

// Every byte the CLI will execute after replacing itself must verify against
// a key pinned HERE — TLS alone would leave install/update trusting whatever
// the origin's edge serves. An array so a key rotation ships additively (the
// new key signs; builds pinning both keys bridge the transition). The same
// key signs at build time (scripts/build-sevra-cli.sh); the pubkey is also
// served at /install/sevra.pub for out-of-band verification.
const SIGNING_PUBKEYS = [
  `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+v5mafEPcIwKAU/DO/z8MM/cT9ndgE1saSUfvcrzLKA=
-----END PUBLIC KEY-----`,
];

function verifyArtifact(script: string, sigB64: string): boolean {
  for (const pem of SIGNING_PUBKEYS) {
    try {
      if (
        cryptoVerify(null, Buffer.from(script), createPublicKey(pem), Buffer.from(sigB64.trim(), "base64"))
      ) {
        return true;
      }
    } catch {
      /* malformed input — try the next pin, fail closed overall */
    }
  }
  return false;
}

// One flat shape (not a discriminated union): the served artifact is also
// transpiled by a bare, non-strict tsc (scripts/build-sevra-cli.sh), which
// cannot narrow union discriminants — this stays clean under both compilers.
interface ArtifactFetch {
  ok: boolean;
  script?: string;
  stamp?: string;
  reason?: string;
  security?: boolean;
}

async function fetchSignedArtifact(hubUrl: string, timeoutMs = 3000): Promise<ArtifactFetch> {
  const base = `${hubUrl}/install/sevra.cjs`;
  let script: string;
  let sig: string;
  try {
    const [a, b] = await Promise.all([
      fetch(base, { signal: AbortSignal.timeout(timeoutMs) }),
      fetch(`${base}.sig`, { signal: AbortSignal.timeout(timeoutMs) }),
    ]);
    if (!a.ok) return { ok: false, reason: `could not download ${base} (HTTP ${a.status})` };
    if (!b.ok) return { ok: false, reason: `could not download ${base}.sig (HTTP ${b.status})` };
    [script, sig] = await Promise.all([a.text(), b.text()]);
  } catch (e) {
    return { ok: false, reason: `could not download ${base}: ${e instanceof Error ? e.message : e}` };
  }
  if (!script.startsWith("#!/usr/bin/env node")) {
    return { ok: false, reason: `unexpected payload from ${base} (not the CLI)` };
  }
  if (!verifyArtifact(script, sig)) {
    return {
      ok: false,
      security: true,
      reason: `the artifact at ${base} FAILED signature verification — refusing to touch the installed CLI. If this persists, report it: https://www.sevrahq.com/security`,
    };
  }
  const stamp = script.match(/const BUILD = "([^"]+)"/)?.[1];
  if (!stamp || stamp === "dev") return { ok: false, reason: `could not read a build stamp from ${base}` };
  return { ok: true, script, stamp };
}

// Evergreen-client auto-update. sevra is a versionless client of exactly one
// hub — its only correct state is "matches the current deploy" — so when a
// hub response carries a different stamp (the x-sevra-build header), the CLI
// replaces its own file right then: the running process keeps executing the
// code it already loaded, and the new build applies from the next invocation.
// SEVRA_NO_AUTO_UPDATE=1 downgrades this to a one-line nudge. Never fires
// from source ("dev"), against a stampless hub, or twice in one process; any
// failure downgrades to the nudge — except a signature failure, which warns
// loudly — and never disturbs the in-flight command.
let updateChecked = false;
async function maybeAutoUpdate(cfg: Config, remote: string | null): Promise<void> {
  if (updateChecked || BUILD === "dev" || !remote || remote === "dev" || remote === BUILD) return;
  updateChecked = true;
  const nudge = () =>
    console.error(`sevra: build ${BUILD} is out of date with the hub (${remote}) — run \`sevra update\``);
  if (process.env.SEVRA_NO_AUTO_UPDATE) return void nudge();
  if (!process.argv[1]) return void nudge();
  let tmp: string | null = null;
  try {
    const self = realpathSync(process.argv[1]);
    const got = await fetchSignedArtifact(cfg.hub);
    if (!got.ok || !got.script || !got.stamp) {
      if (got.security) console.error(`sevra: SECURITY: ${got.reason}`);
      else nudge();
      return;
    }
    if (got.stamp === BUILD) return; // header raced a deploy; the served file IS this build
    tmp = `${self}.new.${process.pid}`;
    writeFileSync(tmp, got.script, { mode: 0o755 });
    renameSync(tmp, self);
    console.error(`sevra: auto-updated ${BUILD} → ${got.stamp} (applies next run; SEVRA_NO_AUTO_UPDATE=1 disables)`);
  } catch {
    if (tmp) rmSync(tmp, { force: true });
    nudge();
  }
}

interface HubResponse {
  status: number;
  body: any;
}
async function hub(
  cfg: Config,
  method: string,
  path: string,
  body?: unknown,
  { auth = true }: { auth?: boolean } = {},
): Promise<HubResponse> {
  assertSafeHub(cfg.hub);
  const headers: Record<string, string> = {};
  if (auth) {
    if (!cfg.key) fail("not logged in — run `sevra login --key vc_account_…` (get a key from the dashboard)");
    headers.authorization = `Bearer ${cfg.key}`;
  }
  if (body !== undefined) headers["content-type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(`${cfg.hub}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    fail(`hub unreachable at ${cfg.hub}: ${e instanceof Error ? e.message : e}`);
  }
  await maybeAutoUpdate(cfg, res.headers.get("x-sevra-build"));
  let parsed: any = null;
  try {
    parsed = await res.json();
  } catch {
    /* non-JSON */
  }
  return { status: res.status, body: parsed };
}

function ensureOk(r: HubResponse, what: string): any {
  if (r.status >= 400) {
    fail(`${what} failed (HTTP ${r.status}): ${r.body?.error ?? "unknown error"}`, r.body);
  }
  // A 2xx without JSON is not a Sevra hub answer (captive portal, proxy,
  // wrong URL) — fail here rather than TypeError on the missing body later.
  if (r.body === null) {
    fail(`${what} failed: the hub answered HTTP ${r.status} with a non-JSON body — check your hub URL (\`sevra whoami\`, config: ${CONFIG_PATH})`);
  }
  return r.body;
}

// --- local store read (for push) --------------------------------------------

async function readStoreFiles(
  dir: string,
): Promise<{ files: { path: string; content: string }[]; assets?: string }> {
  if (!existsSync(dir)) fail(`store directory not found: ${dir}`);
  const files: { path: string; content: string }[] = [];
  let assets: string | undefined;
  // Symlinks are followed (Obsidian-style vaults symlink shared folders);
  // the real-path set breaks cycles.
  const visited = new Set<string>([await realpath(dir)]);
  async function walk(d: string): Promise<void> {
    for (const e of await readdir(d, { withFileTypes: true })) {
      if (e.name.startsWith(".")) continue;
      const full = join(d, e.name);
      let isDir = e.isDirectory();
      let isFile = e.isFile();
      if (e.isSymbolicLink()) {
        try {
          const st = await stat(full);
          isDir = st.isDirectory();
          isFile = st.isFile();
        } catch {
          continue; /* dangling link */
        }
      }
      const rel = relative(dir, full).split(sep).join("/");
      if (isDir) {
        const rp = await realpath(full);
        if (visited.has(rp)) continue;
        visited.add(rp);
        await walk(full);
      } else if (isFile) {
        if (rel === "assets.jsonl") assets = await readFile(full, "utf8");
        else if (/\.md$/i.test(rel)) files.push({ path: rel, content: await readFile(full, "utf8") });
      }
    }
  }
  await walk(dir);
  return { files, assets };
}

// --- commands ---------------------------------------------------------------

async function cmdLogin(args: Args): Promise<void> {
  // Deliberately env-blind: login PERSISTS a hub, and a one-off SEVRA_HUB_URL
  // must not silently become the stored default. --hub is the explicit path.
  const flagHub = flagStr(args.flags, "hub");
  const hubUrl = (flagHub || loadConfigFile().hub || DEFAULT_HUB).replace(/\/$/, "");
  if (!flagHub && process.env.SEVRA_HUB_URL && process.env.SEVRA_HUB_URL.replace(/\/$/, "") !== hubUrl) {
    console.error(`sevra: note: SEVRA_HUB_URL is ignored by login — pass --hub ${process.env.SEVRA_HUB_URL} to store that hub`);
  }
  const key = flagStr(args.flags, "key");
  if (!key) {
    fail("provide a key: `sevra login --key vc_account_…` (create one in the dashboard). SEVRA_API_KEY also works.");
  }
  const probe = await hub({ hub: hubUrl, key }, "GET", "/api/hub/me");
  if (probe.status !== 200 || typeof probe.body?.email !== "string") {
    fail(`that key did not authenticate against ${hubUrl} (HTTP ${probe.status}${probe.body === null ? ", non-JSON response" : ""})`);
  }
  saveConfig({ hub: hubUrl, key });
  out(`logged in to ${hubUrl} as ${probe.body.email} (config: ${CONFIG_PATH})`, { hub: hubUrl, ...probe.body });
}

function cmdLogout(): void {
  if (existsSync(CONFIG_PATH)) rmSync(CONFIG_PATH);
  out("logged out (removed ~/.sevra/config.json)", { ok: true });
}

async function cmdWhoami(cfg: Config): Promise<void> {
  const me = ensureOk(await hub(cfg, "GET", "/api/hub/me"), "whoami");
  out(`${me.email} (${me.userId}) @ ${cfg.hub}`, me);
}

async function cmdBrains(cfg: Config): Promise<void> {
  const { brains } = ensureOk(await hub(cfg, "GET", "/api/hub/brains"), "list brains");
  if (jsonMode) return void out("", { brains });
  if (!brains.length) return void out("no brains yet — `sevra create <slug>`");
  for (const b of brains) out(`${b.slug}\t${b.id}\t${b.visibility}\t${b.name ?? ""}`);
}

async function cmdCreate(cfg: Config, args: Args): Promise<void> {
  const slug = args.positional[1];
  if (!slug) fail("usage: sevra create <slug> [--name …] [--scope …] [--public]");
  const body = {
    slug,
    name: flagStr(args.flags, "name"),
    scope: flagStr(args.flags, "scope"),
    visibility: args.flags.public ? "public" : "private",
  };
  const b = ensureOk(await hub(cfg, "POST", "/api/hub/brains", body), "create brain");
  out(`created brain ${b.slug} (${b.id}, ${b.visibility})`, b);
}

async function cmdPush(cfg: Config, args: Args): Promise<void> {
  const dir = args.positional[1];
  const brain = flagStr(args.flags, "brain");
  if (!dir || !brain) fail("usage: sevra push <dir> --brain <id|slug>");
  const store = await readStoreFiles(dir);
  if (!store.files.length) fail(`no .md files under ${dir}`);
  const bytes = Buffer.byteLength(JSON.stringify(store));
  if (bytes > MAX_PUSH_BYTES) {
    fail(
      `store is ${(bytes / 1024 / 1024).toFixed(1)} MB as JSON — over the hub's push cap (~4 MB). ` +
        `Large brains sync a pack via presigned R2 upload (coming with the object store); push a smaller store for now.`,
      { bytes, cap: MAX_PUSH_BYTES },
    );
  }
  const r = ensureOk(
    await hub(cfg, "POST", `/api/hub/brains/${encodeURIComponent(brain)}/push`, store),
    "push",
  );
  const s = r.indexed;
  out(
    `pushed ${store.files.length} files → indexed ${s.documents} docs, ${s.edges} edges (${s.brokenEdges} broken), ${s.assets} assets`,
    r,
  );
}

async function cmdQuery(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  if (!brain) fail("usage: sevra query <brain> [text] [--type …] [--layer …] [--meta-type …] [--tag …] [--where k=v] [--limit N]");
  const q = args.positional[2];
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  for (const k of ["type", "layer", "meta-type", "tag", "order", "limit"]) {
    const v = flagStr(args.flags, k);
    if (v) params.set(k, v);
  }
  const where = flagStr(args.flags, "where");
  if (where) params.append("where", where);
  const r = ensureOk(
    await hub(cfg, "GET", `/api/hub/brains/${encodeURIComponent(brain)}/query?${params}`),
    "query",
  );
  if (jsonMode) return void out("", r);
  out(`${r.total} result(s):`);
  for (const d of r.results) out(`  ${d.path}\t${d.type ?? ""}\t${d.summary ?? d.title ?? ""}`);
}

async function cmdGet(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  const ref = args.positional[2];
  if (!brain || !ref) fail("usage: sevra get <brain> <db.md-id|path>");
  // A path has a slash or a .md; otherwise treat it as a db.md id.
  const key = ref.includes("/") || /\.md$/i.test(ref) ? "path" : "id";
  const r = ensureOk(
    await hub(cfg, "GET", `/api/hub/brains/${encodeURIComponent(brain)}/resolve?${key}=${encodeURIComponent(ref)}`),
    "get",
  );
  if (jsonMode) return void out("", r);
  const d = r.document;
  out(`# ${d.title ?? d.path}\npath: ${d.path}\ntype: ${d.type ?? ""}  meta-type: ${d.metaType ?? ""}\nid: ${d.dbmdId ?? ""}\n\n${d.body ?? ""}`);
}

async function cmdGraph(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  const path = args.positional[2];
  if (!brain || !path) fail("usage: sevra graph <brain> <path> [--dir in|out|both]");
  const dir = flagStr(args.flags, "dir") || "both";
  if (!["in", "out", "both"].includes(dir)) fail("--dir must be one of: in, out, both");
  const r = ensureOk(
    await hub(cfg, "GET", `/api/hub/brains/${encodeURIComponent(brain)}/graph?path=${encodeURIComponent(path)}&dir=${encodeURIComponent(dir)}`),
    "graph",
  );
  if (jsonMode) return void out("", r);
  out(`backlinks (${r.backlinks.length}):`);
  for (const e of r.backlinks) out(`  ← ${e.srcPath}${e.resolved ? "" : " (broken)"}`);
  out(`outlinks (${r.outlinks.length}):`);
  for (const e of r.outlinks) out(`  → ${e.dstPath}${e.resolved ? "" : " (broken)"}`);
}

async function cmdGrant(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  const email = args.positional[2];
  if (!brain || !email) fail("usage: sevra grant <brain> <email> [--write]");
  const capability = args.flags.write ? "write" : "read";
  const r = ensureOk(
    await hub(cfg, "POST", `/api/hub/brains/${encodeURIComponent(brain)}/grants`, { email, capability }),
    "grant",
  );
  if (r.pending) {
    out(`invited ${email} to ${brain} (${capability}) — they get access when they sign up free`, r);
  } else {
    out(`granted ${capability} on ${brain} to ${email}`, r);
  }
}

async function cmdGrants(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  if (!brain) fail("usage: sevra grants <brain>");
  const r = ensureOk(await hub(cfg, "GET", `/api/hub/brains/${encodeURIComponent(brain)}/grants`), "grants");
  if (jsonMode) return void out("", r);
  if (!r.grants.length) return void out("no grants");
  for (const g of r.grants) out(`  ${g.email}\t${g.capability}\t${g.id}`);
}

async function cmdRevoke(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  const grantId = args.positional[2];
  if (!brain || !grantId) fail("usage: sevra revoke <brain> <grantId>");
  ensureOk(await hub(cfg, "DELETE", `/api/hub/brains/${encodeURIComponent(brain)}/grants/${encodeURIComponent(grantId)}`), "revoke");
  out(`revoked grant ${grantId}`, { revoked: true });
}

async function cmdShared(cfg: Config): Promise<void> {
  const r = ensureOk(await hub(cfg, "GET", "/api/hub/shared"), "shared");
  if (jsonMode) return void out("", r);
  if (!r.shared.length) return void out("nothing shared with you");
  for (const b of r.shared) out(`  ${b.slug}\t${b.id}\t${b.capability}\t${b.name ?? ""}`);
}

async function cmdExport(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  if (!brain) fail("usage: sevra export <brain> [dir]");
  const r = ensureOk(
    await hub(cfg, "GET", `/api/hub/brains/${encodeURIComponent(brain)}/export`),
    "export",
  );
  // The default dir name comes from the hub's slug — validate it before it
  // becomes a path (same don't-trust-the-hub posture as the write guard).
  const remoteSlug =
    typeof r.slug === "string" && /^[a-z0-9][a-z0-9-]*$/.test(r.slug) ? r.slug : null;
  const localSlug = brain.toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
  const dir = args.positional[2] || `./${remoteSlug ?? localSlug ?? "brain"}-export`;
  const root = resolve(dir);
  for (const f of r.files as { path: string; content: string }[]) {
    if (typeof f?.path !== "string" || typeof f?.content !== "string") {
      fail("refusing malformed file entry from hub (path/content must be strings)");
    }
    // Resolve-containment guard: the RESOLVED write path must stay inside the
    // target dir. A raw-string check (`..`, leading `/`) validates the string,
    // not the path — this checks the actual destination. The server validates
    // too, but a client writing to the user's disk must not blindly trust a hub
    // response (defense in depth against a compromised/buggy hub).
    const full = resolve(dir, f.path);
    if (!f.path || f.path.includes("\0") || full === root || !full.startsWith(root + sep)) {
      fail(`refusing unsafe export path: ${f.path}`);
    }
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, f.content);
  }
  out(`exported ${r.files.length} file(s) → ${dir}`, { dir, ...r, files: undefined, fileCount: r.files.length });
}

async function cmdPublish(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  if (!brain) fail("usage: sevra publish <brain>");
  const r = ensureOk(
    await hub(cfg, "POST", `/api/hub/brains/${encodeURIComponent(brain)}/publish`),
    "publish",
  );
  if (jsonMode) return void out("", r);
  const layoutNotes: string[] = (r.layoutErrors ?? []).map(
    (e: { message: string }) => `skipped (layout: site): ${e.message}`,
  );
  if (!r.count) {
    for (const m of layoutNotes) out(m);
    return void out(
      "nothing public to publish yet — make the brain public (`sevra` dashboard) or mark records `visibility: public`, then publish again.",
    );
  }
  out(`published ${r.count} page(s) → ${r.url}`);
  for (const p of r.published) out(`  ${r.url}/${p.pageSlug}\t${p.title}`);
  for (const m of layoutNotes) out(`  ${m}`);
  if (r.gatedPages?.length) {
    out(
      `  ${r.gatedPages.length} record(s) gated by audience (not publicly served; sign-in support is coming): ` +
        r.gatedPages.map((g: { docPath: string }) => g.docPath).join(", "),
    );
  }
}

// The owner's inbox surface (mini-apps U-B). `list` is human-readable; `drain`
// prints the full items as JSON — the BYO agent's read half (fetch, promote
// what's worth keeping into records/, done).
async function cmdInbox(cfg: Config, args: Args): Promise<void> {
  const sub = args.positional[1];
  const brain = args.positional[2];
  if ((sub !== "list" && sub !== "drain") || !brain) {
    fail("usage: sevra inbox list|drain <brain>");
  }
  const r = ensureOk(
    await hub(cfg, "GET", `/api/hub/brains/${encodeURIComponent(brain)}/inbox?limit=200`),
    "inbox",
  );
  if (jsonMode || sub === "drain") return void out(JSON.stringify(r, null, 2), r);
  if (!r.count) return void out("inbox empty — no submissions.");
  out(`${r.count} submission(s):`);
  for (const it of r.items) {
    out(`  ${it.created ?? "-"}  ${it.app ?? "-"}  ${it.submittedBy}  ${it.path}`);
  }
}

async function cmdUnpublish(cfg: Config, args: Args): Promise<void> {
  const brain = args.positional[1];
  if (!brain) fail("usage: sevra unpublish <brain>");
  ensureOk(
    await hub(cfg, "DELETE", `/api/hub/brains/${encodeURIComponent(brain)}/publish`),
    "unpublish",
  );
  out(`unpublished ${brain} (public pages pulled)`, { unpublished: true });
}

function cmdValidate(args: Args): void {
  const dir = args.positional[1] || ".";
  if (!existsSync(dir)) fail(`directory not found: ${dir}`);
  // Wrap dbmd — the neutral db.md tool. sevra never reimplements it.
  const res = spawnSync("dbmd", ["validate", "--all"], { cwd: dir, stdio: "inherit" });
  if (res.error) fail(`could not run dbmd (is it installed? https://www.sevrahq.com/install): ${res.error.message}`);
  // A signal death (OOM, kill) has status null — that is not a pass.
  process.exit(res.status ?? (res.signal ? 1 : 0));
}

function cmdVersion(): void {
  out(`sevra ${BUILD} (built ${BUILD_DATE})`, { build: BUILD, date: BUILD_DATE });
}

function parseSemver(s: string): [number, number, number] | null {
  const m = s.match(/(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
function semverLt(a: [number, number, number], b: [number, number, number]): boolean {
  return a[0] !== b[0] ? a[0] < b[0] : a[1] !== b[1] ? a[1] < b[1] : a[2] < b[2];
}

// Best-effort dbmd staleness check, riding `sevra update` only. dbmd itself
// has NO network code (deliberately — the format tool provably never phones
// home), so the hub resolves its latest release and sevra carries the signal.
async function checkDbmd(cfg: Config): Promise<{ line: string; data: Record<string, unknown> } | null> {
  try {
    const local = spawnSync("dbmd", ["--version"], { encoding: "utf8" });
    const installed = local.error ? null : parseSemver(local.stdout || "");
    const res = await fetch(`${cfg.hub}/api/hub/versions`);
    if (!res.ok) return null;
    const v = await res.json();
    const latestStr: string | null = typeof v?.dbmd?.latest === "string" ? v.dbmd.latest : null;
    const latest = latestStr ? parseSemver(latestStr) : null;
    if (!latest || !latestStr) return null;
    if (!installed) {
      return {
        line: `dbmd: not installed — get it: curl -fsSL ${cfg.hub}/install/dbmd.sh | sh`,
        data: { installed: null, latest: latestStr },
      };
    }
    const installedStr = installed.join(".");
    if (semverLt(installed, latest)) {
      return {
        line: `dbmd ${installedStr} is behind ${latestStr} — update: curl -fsSL ${cfg.hub}/install/dbmd.sh | sh`,
        data: { installed: installedStr, latest: latestStr, current: false },
      };
    }
    return {
      line: `dbmd ${installedStr} — current`,
      data: { installed: installedStr, latest: latestStr, current: true },
    };
  } catch {
    return null; /* best-effort: never block or fail the update */
  }
}

async function cmdUpdate(cfg: Config): Promise<void> {
  if (BUILD === "dev") fail("running from source — update via git, not `sevra update`");
  assertSafeHub(cfg.hub);
  const got = await fetchSignedArtifact(cfg.hub, 15_000);
  if (!got.ok || !got.script || !got.stamp) {
    fail(got.security ? `SECURITY: ${got.reason}` : (got.reason ?? "update failed"));
  }
  let line: string;
  const data: Record<string, unknown> = {};
  if (got.stamp === BUILD) {
    line = `already up to date (${BUILD}, signature verified)`;
    Object.assign(data, { build: BUILD, updated: false });
  } else {
    if (!process.argv[1]) fail("cannot locate my own path to self-replace");
    const self = realpathSync(process.argv[1]);
    // Write-then-rename so a failed download can never leave a truncated CLI.
    const tmp = `${self}.new`;
    writeFileSync(tmp, got.script, { mode: 0o755 });
    renameSync(tmp, self);
    line = `updated ${BUILD} → ${got.stamp} (signature verified; ${self})`;
    Object.assign(data, { from: BUILD, to: got.stamp, path: self, updated: true });
  }
  const dbmd = await checkDbmd(cfg);
  if (dbmd) {
    line += `\n${dbmd.line}`;
    data.dbmd = dbmd.data;
  }
  out(line, data);
}

const HELP = `sevra — the CLI for the Sevra hub (managed home for db.md brains)

  sevra login --key <vc_account_…> [--hub <url>]   store your credential
  sevra logout
  sevra whoami

  sevra brains                                     list your brains
  sevra create <slug> [--name] [--scope] [--public]
  sevra push <dir> --brain <id|slug>               index-on-push
  sevra query <brain> [text] [--type] [--layer] [--meta-type] [--tag] [--where k=v] [--limit N]
  sevra get <brain> <db.md-id|path>
  sevra graph <brain> <path> [--dir in|out|both]

  sevra grant <brain> <email> [--write]
  sevra grants <brain>
  sevra revoke <brain> <grantId>
  sevra shared                                     brains shared with you
  sevra publish <brain>                             render public records to <handle>.sevra.page
  sevra unpublish <brain>                           pull all public pages
  sevra inbox list|drain <brain>                    read the evidence inbox (drain = full JSON)
  sevra export <brain> [dir]                        write your brain back to disk (you own it)

  sevra validate [dir]                             wraps \`dbmd validate --all\`
  sevra version                                    print this build's stamp
  sevra update                                     self-replace with the hub's current build; checks dbmd too

Add --json to any command for machine-readable output. Config: ~/.sevra/config.json
(env SEVRA_HUB_URL / SEVRA_API_KEY override it).
sevra auto-updates itself when the hub runs a newer build (applies next run;
SEVRA_NO_AUTO_UPDATE=1 keeps a one-line nudge instead). dbmd never auto-updates —
\`sevra update\` reports when it is behind.`;

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  jsonMode = args.flags.json === true;
  if (args.problems.length) fail(`${args.problems.join("; ")} (try \`sevra help\`)`);
  const command = args.positional[0];

  if (args.flags.version === true || command === "version") return cmdVersion();
  if (!command || command === "help" || args.flags.help === true) {
    console.log(HELP);
    return;
  }

  // Commands that don't need a loaded credential first.
  if (command === "login") return cmdLogin(args);
  if (command === "logout") return cmdLogout();
  if (command === "validate") return cmdValidate(args);

  const cfg = loadConfig();
  switch (command) {
    case "whoami": return cmdWhoami(cfg);
    case "brains": return cmdBrains(cfg);
    case "create": return cmdCreate(cfg, args);
    case "push": return cmdPush(cfg, args);
    case "query": return cmdQuery(cfg, args);
    case "get": return cmdGet(cfg, args);
    case "graph": return cmdGraph(cfg, args);
    case "grant": return cmdGrant(cfg, args);
    case "grants": return cmdGrants(cfg, args);
    case "revoke": return cmdRevoke(cfg, args);
    case "shared": return cmdShared(cfg);
    case "publish": return cmdPublish(cfg, args);
    case "unpublish": return cmdUnpublish(cfg, args);
    case "inbox": return cmdInbox(cfg, args);
    case "export": return cmdExport(cfg, args);
    case "update": return cmdUpdate(cfg);
    default:
      fail(`unknown command: ${command} (try \`sevra help\`)`);
  }
}

main().catch((e) => {
  // Even unexpected errors must honor the --json contract on stdout.
  const msg = e instanceof Error ? e.message : String(e);
  if (jsonMode) console.log(JSON.stringify({ error: msg }, null, 2));
  else console.error(`sevra: unexpected error: ${msg}`);
  process.exit(1);
});
