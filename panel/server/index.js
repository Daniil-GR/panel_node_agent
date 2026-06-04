/**
 * Panel Naive + Mieru by RIXXX — Express backend  v1.2.6
 * Node.js 20 LTS + Express + better-sqlite3 + WebSocket + node-cron
 *
 * v1.2.3: Migrated from standalone naive binary to caddy-forwardproxy-naive.
 *   buildCaddyfile(cfg, users) — rebuilds /etc/caddy-naive/Caddyfile atomically
 *   reloadCaddy()              — systemctl reload caddy-naive (graceful, zero downtime)
 *   applyAllConfigs()          — rebuilds Caddyfile + applies Mita config in one call
 *   /api/services/rebuild-all  — endpoint used by update.sh --repair
 *
 * v1.2.5 hotfixes:
 *   Bug 44: buildCaddyfile() skips users without plaintext password (logs warning)
 *   Bug 50: reloadCaddy() uses only systemctl reload — pgrep fallback removed
 *   Bug 51: buildMitaStateFile() uses safe defaults for mieruPortStart/End
 *   Bug 52: /api/settings/naive-port verifies caddy-naive is active after restart
 *   Bug 53: saveConfig() performs atomic write via .new tmp file then rename
 *
 * Bug 5:  Sing-Box outbound uses `transport` field (not `protocol`)
 * Bug 7:  UFW single-port vs range helper (ufwMieruRule)
 * Bug 12: server_ports array in Mieru Sing-Box config
 * Bug 13: version synced via scripts/sync-version.sh
 */
'use strict';

const express        = require('express');
const session        = require('express-session');
const helmet         = require('helmet');
const morgan         = require('morgan');
const rateLimit      = require('express-rate-limit');
const bcrypt         = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const cron           = require('node-cron');
const http           = require('http');
const { WebSocketServer } = require('ws');
const fs             = require('fs');
const path           = require('path');
const { execSync, execFileSync } = require('child_process');
const si             = require('systeminformation');
const crypto         = require('crypto');
const net            = require('net');

// ── Paths ─────────────────────────────────────────────────────────────────────
const PANEL_CONFIG    = '/etc/rixxx-panel/config.json';
const DB_PATH         = '/var/lib/rixxx-panel/db.sqlite';
const MITA_STATE_FILE = '/var/lib/rixxx-panel/mita-state.json';

// v1.2.3: Caddy-forwardproxy-naive paths (replaces standalone naive binary)
const CADDY_BIN         = '/usr/local/bin/caddy-naive';
const CADDY_CONFIG_DIR  = '/etc/caddy-naive';
const CADDY_FILE        = '/etc/caddy-naive/Caddyfile';
const FAKE_SITE_DIR     = '/var/www/fake-site';
const LOG_CADDY         = '/var/log/caddy-naive/access.log';
const LOG_AUTH_AUDIT    = '/var/log/caddy-naive/auth-audit.log';
const LOG_TRAFFIC_AUDIT = '/var/log/caddy-naive/traffic-audit.log';
const LOG_PANEL         = '/var/log/panel-naive-mieru.log';
const AUTH_AUDIT_LOG_UNCONFIGURED_REASON = 'auth audit log not configured';
const AUTH_AUDIT_MAX_BYTES = 1024 * 1024 * 25;
const NODE_EXPLORER_CACHE_TTL_MS = 30000;

// Legacy path kept for migration detection only
const LEGACY_NAIVE_BIN = '/usr/local/bin/naive';

// ── Load system config ────────────────────────────────────────────────────────
let cfg = {};
try {
  cfg = JSON.parse(fs.readFileSync(PANEL_CONFIG, 'utf8'));
} catch {
  cfg = {
    domain: 'localhost', serverIp: '127.0.0.1',
    adminUser: 'admin',
    adminPassHash: bcrypt.hashSync('admin', 12),
    naivePort: 443, mieruPortStart: 2012, mieruPortEnd: 2022,
    panelPort: 3000, panelHost: '127.0.0.1', exposePanel: false,
    dbPath:        DB_PATH,
    caddyBin:      CADDY_BIN,
    caddyFile:     CADDY_FILE,
    caddyConfigDir: CADDY_CONFIG_DIR,
    fakeSiteDir:   FAKE_SITE_DIR,
    staticSite: {
      enabled: false,
      root: '',
      sourceType: 'archive_url',
      sourceUrl: '',
      deployOnInstall: true,
      deployOnUpdate: 'missing-only',
      createIfMissing: true
    },
    fakeSiteUrl:   'https://www.example.com',
    probeSecret:   '',
    probeMode:     'bare',   // Bug 81: 'off' | 'bare' | 'secret' (matches known-good ref)
    mitaStateFile: MITA_STATE_FILE,
    trafficPattern: 'NOOP', mtu: 1400, udpEnabled: false,
    // Cascade (relay): Naive uses Caddyfile upstream; Mieru uses Variant B
    // (redsocks+iptables+mieru-client) orchestrated by scripts/cascade_mieru.sh.
    cascadeEnabled: false, cascadeNaiveUpstream: '',
    cascadeMieru: { host: '', portStart: 2012, portEnd: 2022, user: '', pass: '' },
    cascadeMieruEgress: {},   // legacy (Variant A native egress) — kept for back-compat
    nodeApiKey: '',
    backendAllowedIps: ['127.0.0.1'],
    allowAnyBackendIp: false,
    sessionTtlMinutes: 10,
    authAuditLogPath: LOG_AUTH_AUDIT,
    trafficAuditLogPath: LOG_TRAFFIC_AUDIT,
    ipHistoryTtlHours: 24,
    maxUniqueIpsPerUser: 5,
    enforceIpLimit: false,
    subscriptionBaseUrl: '',
    language: 'ru', version: '1.2.6'
  };
}

cfg.sessionTtlMinutes = parseInt(cfg.sessionTtlMinutes, 10) || 10;
if (cfg.authAuditLogPath === undefined) cfg.authAuditLogPath = LOG_AUTH_AUDIT;
if (cfg.trafficAuditLogPath === undefined) cfg.trafficAuditLogPath = LOG_TRAFFIC_AUDIT;
if (!cfg.staticSite || typeof cfg.staticSite !== 'object') {
  cfg.staticSite = {
    enabled: false,
    root: '',
    sourceType: 'archive_url',
    sourceUrl: '',
    deployOnInstall: true,
    deployOnUpdate: 'missing-only',
    createIfMissing: true
  };
}
cfg.ipHistoryTtlHours = parseInt(cfg.ipHistoryTtlHours, 10) || 24;
cfg.maxUniqueIpsPerUser = parseInt(cfg.maxUniqueIpsPerUser, 10) || 5;
if (cfg.backendAllowedIps === undefined) cfg.backendAllowedIps = ['127.0.0.1'];
else if (!Array.isArray(cfg.backendAllowedIps)) cfg.backendAllowedIps = [];
if (cfg.allowAnyBackendIp !== true) cfg.allowAnyBackendIp = false;

// Resolved paths (prefer config values, fall back to constants)
const resolvedDb        = cfg.dbPath        || DB_PATH;
const resolvedMitaFile  = cfg.mitaStateFile || MITA_STATE_FILE;
const resolvedCaddyFile = cfg.caddyFile     || CADDY_FILE;
const resolvedCaddyBin  = cfg.caddyBin      || CADDY_BIN;
const resolvedCaddyCfgDir = cfg.caddyConfigDir || CADDY_CONFIG_DIR;
const resolvedFakeSiteDir = cfg.fakeSiteDir  || FAKE_SITE_DIR;

function staticSiteRoot(config = cfg) {
  const domain = String(config.domain || 'localhost').trim();
  const site = config.staticSite || {};
  return String(site.root || '').trim() || `/var/www/${domain}/dist`;
}

// ── SQLite (better-sqlite3) ───────────────────────────────────────────────────
let db = null;
try {
  const Database = require('better-sqlite3');
  fs.mkdirSync(path.dirname(resolvedDb), { recursive: true });
  db = new Database(resolvedDb);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id        TEXT PRIMARY KEY,
      email     TEXT UNIQUE,
      username  TEXT NOT NULL UNIQUE,
      passHash  TEXT NOT NULL,
      password  TEXT NOT NULL DEFAULT '',
      expiry    TEXT,
      protocols TEXT DEFAULT '["naive","mieru"]',
      quotaMB   INTEGER DEFAULT 0,
      usedMB    REAL    DEFAULT 0,
      enabled   INTEGER DEFAULT 1,
      suspicious INTEGER DEFAULT 0,
      subscriptionToken TEXT,
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL,
      lastSeen  TEXT
    );
    CREATE TABLE IF NOT EXISTS traffic_snapshots (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT NOT NULL,
      uploadMB   REAL DEFAULT 0,
      downloadMB REAL DEFAULT 0,
      ts         TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS panel_settings (
      key   TEXT PRIMARY KEY,
      value TEXT
    );
    CREATE TABLE IF NOT EXISTS active_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      username TEXT NOT NULL,
      protocol TEXT NOT NULL,
      remote_ip TEXT NOT NULL,
      user_agent TEXT,
      first_seen DATETIME NOT NULL,
      last_seen DATETIME NOT NULL,
      bytes_up INTEGER DEFAULT 0,
      bytes_down INTEGER DEFAULT 0,
      UNIQUE(username, protocol, remote_ip)
    );
    CREATE TABLE IF NOT EXISTS session_resets (
      username TEXT PRIMARY KEY,
      reset_at TEXT NOT NULL
    );
  `);
  // Migrate legacy user tables in-place. SQLite cannot add a UNIQUE column via
  // ALTER TABLE, so subscriptionToken is added as plain TEXT and indexed later.
  try {
    const cols = new Set(db.prepare(`PRAGMA table_info(users)`).all().map(c => c.name));
    const addColumn = (name, ddl) => {
      if (!cols.has(name)) {
        db.exec(`ALTER TABLE users ADD COLUMN ${ddl}`);
        cols.add(name);
      }
    };
    addColumn('password', `password TEXT NOT NULL DEFAULT ''`);
    addColumn('enabled', 'enabled INTEGER DEFAULT 1');
    addColumn('suspicious', 'suspicious INTEGER DEFAULT 0');
    addColumn('subscriptionToken', 'subscriptionToken TEXT');
  } catch (e) {
    console.error('[DB] users column migration skipped:', e.message);
  }

  // Migrate: make `email` nullable so it can be optional (TLS cert is set at
  // install time via Caddy ACME, not per-user). Old schema had `email TEXT
  // NOT NULL UNIQUE`, which rejects empty/absent emails and collides on ''.
  // Rebuild the table only if the column is still NOT NULL.
  try {
    const cols = db.prepare(`PRAGMA table_info(users)`).all();
    const emailCol = cols.find(c => c.name === 'email');
    if (emailCol && emailCol.notnull === 1) {
      db.exec(`
        BEGIN TRANSACTION;
        ALTER TABLE users RENAME TO users_legacy;
        CREATE TABLE users (
          id        TEXT PRIMARY KEY,
          email     TEXT UNIQUE,
          username  TEXT NOT NULL UNIQUE,
          passHash  TEXT NOT NULL,
          password  TEXT NOT NULL DEFAULT '',
          expiry    TEXT,
          protocols TEXT DEFAULT '["naive","mieru"]',
          quotaMB   INTEGER DEFAULT 0,
          usedMB    REAL    DEFAULT 0,
          enabled   INTEGER DEFAULT 1,
          suspicious INTEGER DEFAULT 0,
          subscriptionToken TEXT,
          createdAt TEXT NOT NULL,
          updatedAt TEXT NOT NULL,
          lastSeen  TEXT
        );
        INSERT INTO users
          (id,email,username,passHash,password,expiry,protocols,quotaMB,usedMB,enabled,suspicious,subscriptionToken,createdAt,updatedAt,lastSeen)
        SELECT
          id,
          CASE WHEN email='' THEN NULL ELSE email END,
          username,passHash,password,expiry,protocols,quotaMB,usedMB,1,0,NULL,createdAt,updatedAt,lastSeen
        FROM users_legacy;
        DROP TABLE users_legacy;
        COMMIT;
      `);
      console.log('[DB] migrated users.email -> nullable (email is now optional)');
    }
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch {}
      console.error('[DB] email-nullable migration skipped:', e.message);
  }
  try {
    const rows = db.prepare(`SELECT id FROM users WHERE subscriptionToken IS NULL OR subscriptionToken = ''`).all();
    const stmt = db.prepare(`UPDATE users SET subscriptionToken = ? WHERE id = ?`);
    rows.forEach(r => stmt.run(generateUniqueSubscriptionToken(), r.id));
    const dupes = db.prepare(`
      SELECT subscriptionToken
      FROM users
      WHERE subscriptionToken IS NOT NULL AND subscriptionToken <> ''
      GROUP BY subscriptionToken
      HAVING COUNT(*) > 1
    `).all();
    const updateDup = db.prepare(`UPDATE users SET subscriptionToken = ? WHERE id = ?`);
    for (const d of dupes) {
      const ids = db.prepare(`SELECT id FROM users WHERE subscriptionToken = ? ORDER BY createdAt, id`).all(d.subscriptionToken);
      ids.slice(1).forEach(r => updateDup.run(generateUniqueSubscriptionToken(), r.id));
    }
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_subscription_token ON users(subscriptionToken)`);
  } catch (e) {
    console.error('[DB] subscriptionToken backfill skipped:', e.message);
  }
} catch (err) {
  console.error('[DB] SQLite unavailable:', err.message, '— using in-memory store');
}

// In-memory fallback
const memUsers = new Map();

// ── User DB helpers ───────────────────────────────────────────────────────────
function getAllUsers() {
  if (db) return db.prepare('SELECT * FROM users ORDER BY createdAt DESC').all();
  return [...memUsers.values()];
}
function getUserByUsername(username) {
  if (db) return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  return [...memUsers.values()].find(u => u.username === username);
}
function getUserById(id) {
  if (db) return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  return memUsers.get(id);
}
function getUserBySubscriptionToken(token) {
  if (db) return db.prepare('SELECT * FROM users WHERE subscriptionToken = ?').get(token);
  return [...memUsers.values()].find(u => u.subscriptionToken === token);
}
function upsertUser(u) {
  if (db) {
    db.prepare(`
      INSERT INTO users
        (id,email,username,passHash,password,expiry,protocols,quotaMB,usedMB,enabled,suspicious,subscriptionToken,createdAt,updatedAt,lastSeen)
      VALUES
        (@id,@email,@username,@passHash,@password,@expiry,@protocols,@quotaMB,@usedMB,@enabled,@suspicious,@subscriptionToken,@createdAt,@updatedAt,@lastSeen)
      ON CONFLICT(id) DO UPDATE SET
        email=excluded.email, username=excluded.username,
        passHash=excluded.passHash, password=excluded.password,
        expiry=excluded.expiry, protocols=excluded.protocols,
        quotaMB=excluded.quotaMB, usedMB=excluded.usedMB,
        enabled=excluded.enabled, suspicious=excluded.suspicious,
        subscriptionToken=excluded.subscriptionToken,
        updatedAt=excluded.updatedAt, lastSeen=excluded.lastSeen
    `).run({
      ...u,
      password: u.password || '',
      enabled: u.enabled === false || u.enabled === 0 ? 0 : 1,
      suspicious: u.suspicious ? 1 : 0,
      subscriptionToken: u.subscriptionToken || generateSubscriptionToken()
    });
  } else {
    memUsers.set(u.id, { ...u, subscriptionToken: u.subscriptionToken || generateSubscriptionToken() });
  }
}
function deleteUser(id) {
  if (db) db.prepare('DELETE FROM users WHERE id = ?').run(id);
  else memUsers.delete(id);
}

// ── Persist config ────────────────────────────────────────────────────────────
// Bug 53: atomic write via .new temp file then rename — prevents partial reads
//         if the process is interrupted during the write.
function saveConfig() {
  try {
    const dir = path.dirname(PANEL_CONFIG);
    fs.mkdirSync(dir, { recursive: true });
    const tmp = PANEL_CONFIG + '.new';
    fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, PANEL_CONFIG);   // atomic replace
  } catch (e) { console.error('[CFG]', e.message); }
}

// ── buildCaddyfile() ─────────────────────────────────────────────────────────
// Rebuilds the Caddyfile from current cfg and user list.
//
// Bug 23 (P0): the old code emitted a bare "basic_auth" keyword with no
//   arguments (invalid in caddy-forwardproxy-naive → parse error) and used
//   the wrong spelling "basicauth" for per-user lines.  Both are now fixed
//   by delegating to caddyTemplate.js which is the single source of truth.
//
// Bug 26 (P1): delegate to caddyTemplate.js so install.sh, update.sh, and
//   this file all produce byte-for-byte identical Caddyfiles.
//
// Bug 28 (P1): removed redundant "tls <email>" inside the site block —
//   Caddy's automatic HTTPS handles TLS; the global email directive is enough.
//
// Bug 29 (P1): directive order inside forward_proxy is now enforced by the
//   template: basic_auth lines → hide_ip → hide_via → probe_resistance.
//
// Bug 30 (P1): "order forward_proxy before file_server" now appears in the
//   global block via the template.
//
// Bug 34: placeholder emitted when naiveUsers is empty so the forward_proxy
//   block always has at least one credential (prevents unauthenticated access
//   and Caddy validation failure).
//
// Bug 38 (P2): log rotation uses roll_keep_for 720h (30 days) not roll_keep 5.
//
// Bug 21: no site-level log block — global block covers all traffic.
function buildCaddyfile(config, users) {
  // Filter to naive-protocol users only
  // Bug 44: skip users without a plaintext password — caddy-forwardproxy-naive
  //         hashes the password internally; we cannot feed it a bcrypt hash.
  //         Log a warning so operators know which users are missing.
  const naiveUsers = users.filter(u => {
    if (u.enabled === 0 || u.enabled === false) return false;
    try { return JSON.parse(u.protocols || '["naive","mieru"]').includes('naive'); }
    catch { return true; }
  }).map(u => {
    const pass = (u.password || '').trim();
    if (!pass) {
      console.warn(`[CADDY] Bug 44: user '${u.username}' has no plaintext password — skipped from Caddyfile`);
      return null;
    }
    return { username: u.username, password: pass };
  }).filter(Boolean);

  // Read probe secret from config or from the file written by install.sh
  const probeSecret = (config.probeSecret || '').trim() ||
    (fs.existsSync(path.join(resolvedCaddyCfgDir, 'probe_secret'))
      ? fs.readFileSync(path.join(resolvedCaddyCfgDir, 'probe_secret'), 'utf8').trim()
      : '');

  // Bug 81: probe_resistance mode ('off' | 'bare' | 'secret').
  // Back-compat: derive from probeSecret when unset.
  let probeMode = (config.probeMode || '').trim().toLowerCase();
  if (!probeMode) probeMode = probeSecret ? 'secret' : 'bare';

  // Bug 26: delegate to the shared template module (single source of truth).
  // Falls back to an inline render if the template file is not yet deployed.
  const tplPath = path.join(__dirname, 'caddyTemplate.js');
  if (fs.existsSync(tplPath)) {
    const tpl = require(tplPath);
    return tpl.render({
      adminEmail:  config.adminEmail  || '',
      domain:      config.domain      || 'localhost',
      naivePort:   config.naivePort   || 443,
      panelPort:   config.panelPort   || 3000,
      fakeSiteDir: resolvedFakeSiteDir,
      staticSite:  config.staticSite,
      probeSecret,
      probeMode,
      logFile:     LOG_CADDY,
      authAuditLogPath: (config.authAuditLogPath || '').trim(),
      trafficAuditLogPath: (config.trafficAuditLogPath || '').trim(),
      upstream:    (config.cascadeEnabled && config.cascadeNaiveUpstream) ? config.cascadeNaiveUpstream : '',
    }, naiveUsers);
  }

  // ── Inline fallback (identical rules to caddyTemplate.js) ─────────────────
  // Used only when caddyTemplate.js is not yet on disk (e.g. very first boot
  // before install_panel() has run).  Kept in sync with the template manually.
  const crypto = require('crypto');
  let authLines;
  if (naiveUsers.length > 0) {
    // Bug 23: each credential line is "basic_auth <user> <pass>" — no bare keyword
    authLines = naiveUsers
      .map(u => `    basic_auth ${u.username} ${u.password}`)
      .join('\n');
  } else {
    // Bug 34: unreachable placeholder keeps the block non-empty
    const rnd = crypto.randomBytes(20).toString('hex');
    authLines = `    basic_auth _placeholder_${rnd.slice(0, 16)} _disabled_${rnd.slice(16)}`;
  }

  // Bug 29 + Bug 81: probe_resistance comes after hide_ip + hide_via.
  // 'off' → none; 'secret' → with token; 'bare' → keyword only.
  let probeLine;
  if (probeMode === 'off') {
    probeLine = '';
  } else if (probeMode === 'secret' && probeSecret) {
    probeLine = `\n    probe_resistance ${probeSecret}`;
  } else {
    probeLine = `\n    probe_resistance`;
  }

  // v1.2.6: cascade — upstream proxy support (inline fallback)
  const upstreamUrl = (config.cascadeEnabled && config.cascadeNaiveUpstream) ? config.cascadeNaiveUpstream : '';
  const upstreamLine = upstreamUrl ? `\n    upstream ${upstreamUrl}` : '';
  const authAuditLogPath = (config.authAuditLogPath || '').trim();
  const authAuditLogLine = authAuditLogPath ? `\n    auth_audit_log ${authAuditLogPath}` : '';
  const trafficAuditLogPath = (config.trafficAuditLogPath || '').trim();
  const trafficAuditLogLine = trafficAuditLogPath ? `\n    traffic_audit_log ${trafficAuditLogPath}` : '';
  const siteRoot = (config.staticSite && config.staticSite.enabled === true)
    ? staticSiteRoot(config)
    : resolvedFakeSiteDir;

  // Bug 28: no "tls <email>" inside site block
  // Bug 30: order directive in global block
  // Bug 38: roll_keep_for 720h
  return `{
  # Bug 30: evaluate forwardproxy before file_server
  order forward_proxy before file_server
  # Bug 80: HTTP/1.1 + HTTP/2 only (disable HTTP/3 / QUIC)
  servers {
    protocols h1 h2
  }
  email ${config.adminEmail || ''}
  admin off
  log {
    # Bug 38: 30-day retention by age
    output file ${LOG_CADDY} {
      roll_size     50mb
      roll_keep_for 720h
    }
    format json
  }
}

# HTTP → HTTPS redirect (also needed for ACME HTTP-01 fallback)
:80 {
  redir https://{host}{uri} permanent
}

:${config.naivePort || 443}, ${config.domain || 'localhost'} {
  # Bug 83: match the known-good reference server exactly (":<port>, <domain>"
  # listener + explicit tls + no route{} wrapper).
  tls ${config.adminEmail || ''}

  handle /sub/* {
    reverse_proxy 127.0.0.1:${config.panelPort || 3000}
  }

  forward_proxy {
    # Bug 23: no bare "basic_auth" token; each line IS the credential directive
    # Bug 29: order — credentials → hide_ip → hide_via → probe_resistance
${authLines}
    hide_ip
    hide_via${probeLine}${authAuditLogLine}${trafficAuditLogLine}${upstreamLine}
  }

  file_server {
    root ${siteRoot}
  }
}
`;
}

// ── writeCaddyfileAtomic() ────────────────────────────────────────────────────
function writeCaddyfileAtomic(content) {
  fs.mkdirSync(resolvedCaddyCfgDir, { recursive: true });
  try { execSync(`chown root:caddy ${shellQuote(resolvedCaddyCfgDir)} 2>/dev/null || true`, { timeout: 5000 }); } catch {}
  try { execSync(`chmod 750 ${shellQuote(resolvedCaddyCfgDir)} 2>/dev/null || true`, { timeout: 5000 }); } catch {}
  const tmp = resolvedCaddyFile + '.new';
  fs.writeFileSync(tmp, content, { mode: 0o640 });
  try { execSync(`chown root:caddy ${shellQuote(tmp)} 2>/dev/null || true`, { timeout: 5000 }); } catch {}
  try { execSync(`chmod 640 ${shellQuote(tmp)} 2>/dev/null || true`, { timeout: 5000 }); } catch {}
  fs.renameSync(tmp, resolvedCaddyFile);   // atomic replace
  try { execSync(`chown root:caddy ${shellQuote(resolvedCaddyFile)} 2>/dev/null || true`, { timeout: 5000 }); } catch {}
  try { execSync(`chmod 640 ${shellQuote(resolvedCaddyFile)} 2>/dev/null || true`, { timeout: 5000 }); } catch {}
}

function generateSubscriptionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateUniqueSubscriptionToken() {
  let token = '';
  do {
    token = generateSubscriptionToken();
  } while (db && db.prepare('SELECT 1 FROM users WHERE subscriptionToken = ?').get(token));
  return token;
}

function subscriptionBaseUrl() {
  return String(cfg.subscriptionBaseUrl || '').trim() || `https://${cfg.domain}/sub`;
}

function subscriptionUrlFor(user) {
  return `${subscriptionBaseUrl().replace(/\/+$/, '')}/${encodeURIComponent(user.subscriptionToken || '')}`;
}

function getGitCommit() {
  try { return execSync('git rev-parse --short HEAD 2>/dev/null', { timeout: 2000 }).toString().trim(); }
  catch { return ''; }
}

function normalizeBackendAllowedIps(value) {
  if (!Array.isArray(value)) return null;
  const ips = [...new Set(value.map(v => String(v || '').trim()).filter(Boolean))];
  if (ips.some(ip => !net.isIP(ip))) return null;
  return ips;
}

function safeNodeSettings() {
  return {
    domain: cfg.domain,
    serverIp: cfg.serverIp,
    naivePort: cfg.naivePort || 443,
    mieruPortStart: cfg.mieruPortStart,
    mieruPortEnd: cfg.mieruPortEnd,
    backendAllowedIps: Array.isArray(cfg.backendAllowedIps) ? cfg.backendAllowedIps : [],
    allowAnyBackendIp: cfg.allowAnyBackendIp === true,
    sessionTtlMinutes: parseInt(cfg.sessionTtlMinutes, 10) || 10,
    authAuditLogPath: cfg.authAuditLogPath || '',
    trafficAuditLogPath: cfg.trafficAuditLogPath || '',
    ipHistoryTtlHours: parseInt(cfg.ipHistoryTtlHours, 10) || 24,
    maxUniqueIpsPerUser: parseInt(cfg.maxUniqueIpsPerUser, 10) || 5,
    enforceIpLimit: cfg.enforceIpLimit === true,
    subscriptionBaseUrl: cfg.subscriptionBaseUrl || ''
  };
}

function nodeAgentVersionPayload() {
  return {
    version: cfg.version || '1.2.6',
    commit: getGitCommit() || undefined,
    nodeAgent: 'vetka-node-agent',
    features: {
      internalApi: true,
      activeSessions: true,
      naive: true,
      mieru: true
    }
  };
}

function applyNodeSettingsPatch(body) {
  const patch = body || {};
  if (patch.backendAllowedIps !== undefined) {
    const ips = normalizeBackendAllowedIps(patch.backendAllowedIps);
    if (!ips) return { error: 'backendAllowedIps must be an array of valid IP addresses' };
    cfg.backendAllowedIps = ips;
  }
  if (patch.allowAnyBackendIp !== undefined) {
    cfg.allowAnyBackendIp = patch.allowAnyBackendIp === true;
  }
  if (patch.sessionTtlMinutes !== undefined) {
    const ttl = parseInt(patch.sessionTtlMinutes, 10);
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 1440) return { error: 'sessionTtlMinutes must be 1..1440' };
    cfg.sessionTtlMinutes = ttl;
  }
  if (patch.authAuditLogPath !== undefined) {
    cfg.authAuditLogPath = String(patch.authAuditLogPath || '').trim();
  }
  if (patch.trafficAuditLogPath !== undefined) {
    cfg.trafficAuditLogPath = String(patch.trafficAuditLogPath || '').trim();
  }
  if (patch.ipHistoryTtlHours !== undefined) {
    const ttlHours = parseInt(patch.ipHistoryTtlHours, 10);
    if (!Number.isInteger(ttlHours) || ttlHours < 1 || ttlHours > 168) return { error: 'ipHistoryTtlHours must be 1..168' };
    cfg.ipHistoryTtlHours = ttlHours;
  }
  if (patch.maxUniqueIpsPerUser !== undefined) {
    const maxIps = parseInt(patch.maxUniqueIpsPerUser, 10);
    if (!Number.isInteger(maxIps) || maxIps < 1 || maxIps > 1000) return { error: 'maxUniqueIpsPerUser must be 1..1000' };
    cfg.maxUniqueIpsPerUser = maxIps;
  }
  if (patch.enforceIpLimit !== undefined) {
    cfg.enforceIpLimit = patch.enforceIpLimit === true;
  }
  if (patch.subscriptionBaseUrl !== undefined) {
    cfg.subscriptionBaseUrl = String(patch.subscriptionBaseUrl || '').trim();
  }
  if (!cfg.allowAnyBackendIp && (!Array.isArray(cfg.backendAllowedIps) || cfg.backendAllowedIps.length === 0)) {
    return { error: 'backendAllowedIps cannot be empty unless allowAnyBackendIp=true' };
  }
  saveConfig();
  return { settings: safeNodeSettings() };
}

function shellQuote(v) {
  return `'${String(v).replace(/'/g, `'\\''`)}'`;
}

function validateCaddyfile() {
  try {
    execFileSync(resolvedCaddyBin, ['validate', '--config', resolvedCaddyFile, '--adapter', 'caddyfile'], {
      timeout: 15000,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    return { ok: true };
  } catch (e) {
    const output = (e.stdout ? e.stdout.toString() : '') + (e.stderr ? e.stderr.toString() : '') + (e.message || '');
    return { ok: false, error: output.trim() || 'caddy validate failed' };
  }
}

// ── reloadCaddy() — graceful reload (zero downtime) ──────────────────────────
// Bug 50: use only systemctl reload — the old pgrep fallback was unreliable
//         because 'pgrep -x caddy-naive' matches on exact comm-name which may
//         differ from the binary name, causing SIGUSR1 to miss the process.
function reloadCaddy() {
  try {
    execSync('systemctl reload caddy-naive', { timeout: 10000 });
    return { ok: true, action: 'reload' };
  } catch (reloadErr) {
    try {
      execSync('systemctl restart caddy-naive', { timeout: 15000 });
      return { ok: true, action: 'restart' };
    } catch (restartErr) {
      const msg = (restartErr.stdout ? restartErr.stdout.toString() : '') ||
        (reloadErr.stdout ? reloadErr.stdout.toString() : '') ||
        restartErr.message || reloadErr.message || 'caddy-naive reload/restart failed';
      return { ok: false, error: msg.trim() };
    }
  }
}

// ── restartCaddy() — full restart (needed for port/domain changes) ───────────
function restartCaddy() {
  try {
    execSync('systemctl restart caddy-naive 2>/dev/null', { timeout: 15000 });
    return { ok: true, action: 'restart' };
  } catch (e) { return { ok: false, error: e.message }; }
}

// ── Bug 7: UFW single-port helper ────────────────────────────────────────────
function ufwMieruRule(action, start, end, proto, comment) {
  const commentPart = comment ? ` comment "${comment}"` : '';
  const cmd = (start === end)
    ? `ufw ${action} allow ${start}/${proto}${commentPart} 2>/dev/null || true`
    : `ufw ${action} allow ${start}:${end}/${proto}${commentPart} 2>/dev/null || true`;
  try { execSync(cmd, { timeout: 5000 }); } catch {}
}

// ── Mieru state JSON builder ──────────────────────────────────────────────────
// Bug 51: use safe defaults for mieruPortStart/End in case config values absent
function buildMitaStateFile() {
  const allUsers = getAllUsers();
  const mieruUsers = allUsers.filter(u => {
    if (u.enabled === 0 || u.enabled === false) return false;
    try { return JSON.parse(u.protocols || '["naive","mieru"]').includes('mieru'); }
    catch { return true; }
  });

  // Bug 51: parseInt guards against undefined/NaN causing infinite loops
  const portStart = parseInt(cfg.mieruPortStart, 10) || 2000;
  const portEnd   = parseInt(cfg.mieruPortEnd,   10) || 2010;

  // TCP-only by default; UDP is opt-in via cfg.udpEnabled
  const portBindings = [];
  for (let p = portStart; p <= portEnd; p++) {
    portBindings.push({ port: p, protocol: 'TCP' });
    if (cfg.udpEnabled) portBindings.push({ port: p, protocol: 'UDP' });
  }

  const mieruCfg = {
    portBindings,
    users: mieruUsers.map(u => ({
      name:     u.username,
      password: u.password || ''   // plain string — mita hashes on apply
    })),
    loggingLevel: 'INFO',
    mtu: cfg.mtu || 1400
  };

  const pat = cfg.trafficPattern || 'NOOP';
  if (pat !== 'NOOP') {
    const patMap = {
      'RANDOM_PADDING':            { seed: true,  tcpFragment: false, nonce: false },
      'RANDOM_PADDING_AGGRESSIVE': { seed: true,  tcpFragment: true,  nonce: true  },
      'CUSTOM':                    { seed: true,  tcpFragment: true,  nonce: true  }
    };
    if (patMap[pat]) mieruCfg.trafficPattern = patMap[pat];
  }

  // v1.2.6 cascade (Mieru): Variant B is used instead of mita native egress.
  // The entry mita stays a plain server; the RU->EU relay is handled externally
  // by scripts/cascade_mieru.sh (mieru-client + redsocks + iptables). We
  // therefore intentionally do NOT inject `mieruCfg.egress` here.
  // Legacy Variant A native egress is only applied if an operator explicitly
  // sets cascadeMieruEgress.proxies AND no Variant B host is configured.
  if (cfg.cascadeEnabled
      && (!cfg.cascadeMieru || !cfg.cascadeMieru.host)
      && cfg.cascadeMieruEgress && Array.isArray(cfg.cascadeMieruEgress.proxies)
      && cfg.cascadeMieruEgress.proxies.length > 0) {
    mieruCfg.egress = {
      proxies: cfg.cascadeMieruEgress.proxies,
      rules: cfg.cascadeMieruEgress.rules || [{ ipRanges: ['*'], domainNames: ['*'], action: 'DIRECT' }]
    };
  }

  fs.mkdirSync(path.dirname(resolvedMitaFile), { recursive: true });
  const tmp = resolvedMitaFile + '.new';
  fs.writeFileSync(tmp, JSON.stringify(mieruCfg, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, resolvedMitaFile);
  ensureMitaStatePermissions(resolvedMitaFile);

  shredFile(resolvedMitaFile + '.last');
  try { fs.copyFileSync(resolvedMitaFile, resolvedMitaFile + '.last'); } catch {}

  return resolvedMitaFile;
}

function ensureMitaStatePermissions(file) {
  const dir = path.dirname(file);
  try { fs.mkdirSync(dir, { recursive: true }); }
  catch (e) { return { ok: false, error: `Failed to create ${dir}: ${e.message}` }; }

  const group = runLogged('getent', ['group', 'mita'], { timeout: 5000, quiet: true });
  if (!group.ok) {
    const error = 'mita group does not exist yet; cannot set mita-state.json group permissions';
    console.warn(`[MITA] ${error}`);
    return { ok: false, error };
  }

  const steps = [
    ['chgrp', ['mita', dir], `Failed to set mita group on ${dir}`],
    ['chmod', ['750', dir], `Failed to set mode 750 on ${dir}`]
  ];
  if (fs.existsSync(file)) {
    steps.push(
      ['chgrp', ['mita', file], `Failed to set mita group on ${file}`],
      ['chmod', ['640', file], `Failed to set mode 640 on ${file}`]
    );
  }

  for (const [cmd, args, message] of steps) {
    const r = runLogged(cmd, args, { timeout: 5000 });
    if (!r.ok) return { ok: false, error: `${message}: ${r.error}` };
  }

  if (fs.existsSync(file)) {
    const check = runLogged('bash', ['-lc', `if command -v sudo >/dev/null 2>&1; then sudo -u mita test -x ${shellQuote(dir)} && sudo -u mita test -r ${shellQuote(file)}; else runuser -u mita -- test -x ${shellQuote(dir)} && runuser -u mita -- test -r ${shellQuote(file)}; fi`], { timeout: 5000 });
    if (!check.ok) {
      return { ok: false, error: `mita cannot read ${file}. Check directory/file permissions. ${check.error}`.trim() };
    }
  }

  return { ok: true };
}

function commandText(error) {
  if (!error) return '';
  const stdout = error.stdout ? error.stdout.toString() : '';
  const stderr = error.stderr ? error.stderr.toString() : '';
  return `${stdout}${stderr}${error.message ? `\n${error.message}` : ''}`.trim();
}

function runLogged(command, args = [], options = {}) {
  const label = [command, ...args].join(' ');
  try {
    const stdout = execFileSync(command, args, { encoding: 'utf8', timeout: options.timeout || 15000 });
    if (!options.quiet && stdout && stdout.trim()) console.log(`[MITA] ${label}\n${stdout.trim()}`);
    return { ok: true, stdout: stdout || '', stderr: '', command: label };
  } catch (e) {
    const output = commandText(e);
    if (!options.quiet) console.error(`[MITA] ${label} failed${output ? `\n${output}` : ''}`);
    return { ok: false, stdout: e.stdout ? e.stdout.toString() : '', stderr: e.stderr ? e.stderr.toString() : '', error: output || e.message, command: label };
  }
}

function mitaUserCount(file) {
  try {
    const state = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(state.users) ? state.users.length : 0;
  } catch { return 0; }
}

function ensureMitaJsonBootstrap(file) {
  const dir = '/etc/systemd/system/mita.service.d';
  const dropIn = path.join(dir, '10-rixxx-panel.conf');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(dropIn, `[Service]\nEnvironment=MITA_CONFIG_JSON_FILE=${file}\n`, { mode: 0o644 });
  runLogged('systemctl', ['daemon-reload'], { timeout: 10000 });
  return dropIn;
}

function applyMitaConfigLive(file) {
  return runLogged('mita', ['apply', 'config', file], { timeout: 15000 });
}

function startMitaDaemonForBootstrap(file) {
  const dropIn = ensureMitaJsonBootstrap(file);
  console.log(`[MITA] bootstrap drop-in ensured: ${dropIn}`);
  runLogged('systemctl', ['reset-failed', 'mita'], { timeout: 10000 });
  return runLogged('systemctl', ['restart', 'mita'], { timeout: 20000 });
}

function startMitaProxy() {
  const status = runLogged('mita', ['status'], { timeout: 10000 });
  if (status.ok && /RUNNING/i.test(status.stdout)) {
    return runLogged('mita', ['reload'], { timeout: 15000 });
  }
  const stop = runLogged('mita', ['stop'], { timeout: 10000 });
  if (!stop.ok) console.warn(`[MITA] mita stop before start returned non-zero: ${stop.error}`);
  let start = runLogged('mita', ['start'], { timeout: 15000 });
  if (!start.ok) {
    const restart = runLogged('systemctl', ['restart', 'mita'], { timeout: 20000 });
    if (!restart.ok) return restart;
    start = runLogged('mita', ['start'], { timeout: 15000 });
  }
  return start;
}

function applyMitaConfigDetailed() {
  const file = buildMitaStateFile();
  const users = mitaUserCount(file);
  const perms = ensureMitaStatePermissions(file);
  if (!perms.ok) {
    return { ok: false, required: users > 0, users, file, error: perms.error };
  }
  if (users === 0) {
    const error = 'Mieru не может быть запущен: нет активных Mieru-пользователей';
    console.warn(`[MITA] ${error}`);
    runLogged('systemctl', ['stop', 'mita'], { timeout: 10000 });
    runLogged('systemctl', ['reset-failed', 'mita'], { timeout: 10000 });
    shredFile(file + '.last');
    return { ok: false, required: false, idle: true, users, file, error };
  }

  let apply = applyMitaConfigLive(file);
  if (!apply.ok) {
    const firstError = apply.error || '';
    if (/daemon is not running|connection refused|connect: connection refused|no such file|unavailable/i.test(firstError)) {
      const daemon = startMitaDaemonForBootstrap(file);
      if (!daemon.ok) {
        return { ok: false, required: true, users, file, error: `mita bootstrap daemon restart failed: ${daemon.error}`, applyError: firstError };
      }
      apply = applyMitaConfigLive(file);
    }
  }
  if (!apply.ok) {
    return { ok: false, required: true, users, file, error: apply.error || 'mita apply config failed' };
  }

  const started = startMitaProxy();
  if (!started.ok) {
    return { ok: false, required: true, users, file, error: started.error || 'mita start failed' };
  }

  shredFile(file + '.last');
  return { ok: true, required: true, users, file, applyOutput: apply.stdout || '', startOutput: started.stdout || '' };
}

function applyMitaConfig() {
  try {
    return applyMitaConfigDetailed().ok;
  } catch (e) { console.error('[MITA]', e.message); return false; }
}

function restartMieru() {
  try { return applyMitaConfigDetailed().ok; }
  catch (e) { console.error('[MITA]', e.message); return false; }
}

// ── Mieru cascade (Variant B) — scripts/cascade_mieru.sh orchestrator ─────────
const CASCADE_SCRIPT = path.join(__dirname, '../scripts/cascade_mieru.sh');

// Run cascade_mieru.sh {setup|teardown|status}. Returns { ok, output }.
// Uses execFileSync (no shell) so the exit credentials are passed as argv and
// never interpolated into a shell string.
function runCascadeMieru(action, opts = {}) {
  try {
    const args = [CASCADE_SCRIPT, action];
    if (action === 'setup') {
      args.push(
        '--exit-host',       String(opts.host || ''),
        '--exit-port-start', String(opts.portStart || ''),
        '--exit-port-end',   String(opts.portEnd || ''),
        '--exit-user',       String(opts.user || ''),
        '--exit-pass',       String(opts.pass || '')
      );
    }
    const out = execFileSync('bash', args, { timeout: 120000 }).toString();
    return { ok: true, output: out };
  } catch (e) {
    return { ok: false, output: (e.stdout ? e.stdout.toString() : '') + (e.stderr ? e.stderr.toString() : e.message) };
  }
}

function shredFile(fp) {
  if (!fp || !fs.existsSync(fp)) return;
  try { execSync(`shred -u "${fp}" 2>/dev/null`, { timeout: 5000 }); }
  catch { try { fs.unlinkSync(fp); } catch {} }
}

// ── applyAllConfigs() — unified pipeline ─────────────────────────────────────
// Rebuilds Caddyfile, reloads Caddy, rebuilds mita state, applies mita config.
// Called after every user CRUD operation.
function applyAllConfigs() {
  let caddyOk = false, mitaOk = false, caddyError = '', caddyAction = '', mitaError = '', mitaRequired = false, mitaIdle = false;
  try {
    const content = buildCaddyfile(cfg, getAllUsers());
    writeCaddyfileAtomic(content);
    const validation = validateCaddyfile();
    if (!validation.ok) {
      caddyError = validation.error;
    } else {
      const applied = reloadCaddy();
      caddyOk = applied.ok;
      caddyAction = applied.action || '';
      caddyError = applied.error || '';
    }
  } catch (e) { caddyError = e.message; console.error('[CADDY]', e.message); }
  try {
    const mita = applyMitaConfigDetailed();
    mitaOk = mita.ok;
    mitaError = mita.error || '';
    mitaRequired = !!mita.required;
    mitaIdle = !!mita.idle;
  } catch (e) { mitaError = e.message; console.error('[MITA]', e.message); }
  return { caddyOk, mitaOk, mitaRequired, mitaIdle, mitaError, caddyAction, caddyError, servicesReloaded: caddyOk && (!mitaRequired || mitaOk) };
}

// ── Express app ───────────────────────────────────────────────────────────────
const app    = express();
const server = http.createServer(app);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:      ["'self'"],
      scriptSrc:       ["'self'",
                        'https://cdn.jsdelivr.net'],
      // Bug CSP: script-src-attr 'none' prevents inline event handlers
      scriptSrcAttr:   ["'none'"],
      styleSrc:        ["'self'", "'unsafe-inline'",
                        'https://fonts.googleapis.com',
                        'https://fonts.gstatic.com'],
      fontSrc:         ["'self'", 'https://fonts.gstatic.com'],
      connectSrc:      ["'self'", 'ws:', 'wss:', 'https://fonts.googleapis.com'],
      imgSrc:          ["'self'", 'data:', 'blob:'],
      mediaSrc:        ["'none'"],
      objectSrc:       ["'none'"],
      frameAncestors:  ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(morgan('combined', {
  stream: { write: m => { try { fs.appendFileSync(LOG_PANEL, m); } catch {} } }
}));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Session
let sessionSecret;
const secretFile = path.join(path.dirname(resolvedDb), '.session_secret');
try { sessionSecret = fs.readFileSync(secretFile, 'utf8').trim(); }
catch {
  sessionSecret = require('crypto').randomBytes(64).toString('hex');
  try {
    fs.mkdirSync(path.dirname(secretFile), { recursive: true });
    fs.writeFileSync(secretFile, sessionSecret, { mode: 0o600 });
  } catch {}
}

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, maxAge: 86400000 }
}));

// Rate limits
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20,  message: { error: 'Too many attempts' } });
const apiLimiter   = rateLimit({ windowMs:      60 * 1000, max: 300, message: { error: 'Rate limit exceeded' } });
app.use('/api/', apiLimiter);

// Static files
app.use(express.static(path.join(__dirname, '../public')));

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/');
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Missing credentials' });

  const isAdmin =
    username === cfg.adminUser &&
    cfg.adminPassHash &&
    bcrypt.compareSync(password, cfg.adminPassHash);

  if (!isAdmin) return res.status(401).json({ error: 'Invalid credentials' });
  req.session.authenticated = true;
  req.session.username = username;
  res.json({ ok: true, username });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.session.username, authenticated: true });
});

// ── Config API ────────────────────────────────────────────────────────────────
app.get('/api/config', requireAuth, (req, res) => {
  const { adminPassHash, nodeApiKey, ...safe } = cfg;
  // Never expose secrets to the browser. Mask the cascade exit password and the
  // legacy native-egress proxy passwords; expose a boolean "set" flag instead.
  if (safe.cascadeMieru && typeof safe.cascadeMieru === 'object') {
    const { pass, ...cm } = safe.cascadeMieru;
    safe.cascadeMieru = { ...cm, pass: !!pass };   // pass becomes true/false
  }
  if (safe.cascadeMieruEgress && Array.isArray(safe.cascadeMieruEgress.proxies)) {
    safe.cascadeMieruEgress = {
      ...safe.cascadeMieruEgress,
      proxies: safe.cascadeMieruEgress.proxies.map(p => {
        if (p && p.socks5Authentication) {
          const { password, ...auth } = p.socks5Authentication;
          return { ...p, socks5Authentication: { ...auth, password: !!password } };
        }
        return p;
      })
    };
  }
  res.json(safe);
});

app.post('/api/config', requireAuth, (req, res) => {
  ['domain','naivePort','mieruPortStart','mieruPortEnd',
   'trafficPattern','mtu','udpEnabled','adminEmail','language',
   'probeSecret','fakeSiteUrl'].forEach(k => {
    if (req.body[k] !== undefined) cfg[k] = req.body[k];
  });
  saveConfig();
  const { adminPassHash, ...safe } = cfg;
  res.json({ ok: true, cfg: safe });
});

app.post('/api/config/password', requireAuth, (req, res) => {
  const { current, newPass } = req.body;
  if (!current || !newPass) return res.status(400).json({ error: 'Missing fields' });
  if (newPass.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  const valid = cfg.adminPassHash && bcrypt.compareSync(current, cfg.adminPassHash);
  if (!valid) return res.status(401).json({ error: 'Current password incorrect' });
  cfg.adminPassHash = bcrypt.hashSync(newPass, 12);
  saveConfig();
  res.json({ ok: true });
});

// ── Validation helpers ────────────────────────────────────────────────────────
const VALID_PROTOCOLS = ['naive', 'mieru'];
const USERNAME_RE     = /^[a-zA-Z0-9_.-]{1,64}$/;
const EMAIL_RE        = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Bug 8: normalise quota — accept quotaMB or quotaGb (gb * 1024 → MB).
 * Bug 9: validate all user input fields.
 */
function validateUserInput({ email, username, password, protocols, quotaMB, quotaGb, enabled }, requirePassword) {
  if (!username || !USERNAME_RE.test(username))
    return { error: 'username required and must match [a-zA-Z0-9_.-] (max 64 chars)' };
  // Email is optional (TLS cert is configured at install time via Caddy ACME,
  // not per-user). If provided, it must still be a valid address.
  if (email !== undefined && email !== null && email !== '' && !EMAIL_RE.test(email))
    return { error: 'email is invalid' };
  if (requirePassword) {
    if (!password) return { error: 'password is required for new users' };
    if (password.length < 8) return { error: 'password must be at least 8 characters' };
  } else if (password !== undefined && password !== null && password !== '' && password.length < 8) {
    return { error: 'new password must be at least 8 characters' };
  }
  // Bug 8: accept quotaGb; convert to quotaMB
  let resolvedQuotaMB = 0;
  if (quotaMB !== undefined && quotaMB !== null) {
    resolvedQuotaMB = parseInt(quotaMB, 10);
    if (isNaN(resolvedQuotaMB) || resolvedQuotaMB < 0)
      return { error: 'quotaMB must be a non-negative integer' };
  } else if (quotaGb !== undefined && quotaGb !== null) {
    const gb = parseFloat(quotaGb);
    if (isNaN(gb) || gb < 0) return { error: 'quotaGb must be a non-negative number' };
    resolvedQuotaMB = Math.round(gb * 1024);
  }
  // Bug 9: protocols allowlist
  let resolvedProtocols = ['naive', 'mieru'];
  if (protocols !== undefined) {
    if (!Array.isArray(protocols))
      return { error: 'protocols must be an array' };
    const invalid = protocols.filter(p => !VALID_PROTOCOLS.includes(p));
    if (invalid.length)
      return { error: `unknown protocol(s): ${invalid.join(', ')}. Allowed: ${VALID_PROTOCOLS.join(', ')}` };
    if (!protocols.length)
      return { error: 'at least one protocol is required (naive, mieru)' };
    resolvedProtocols = protocols;
  }
  const resolvedEnabled = enabled === undefined ? undefined : !(enabled === false || enabled === 0 || enabled === 'false');
  return { quotaMB: resolvedQuotaMB, protocols: resolvedProtocols, enabled: resolvedEnabled };
}

/**
 * Bug 7: parse all TEXT JSON columns back to JS types when returning user rows.
 */
function parseUserRow(u) {
  return {
    ...u,
    enabled: !(u.enabled === 0 || u.enabled === false),
    suspicious: !!u.suspicious,
    protocols: typeof u.protocols === 'string'
      ? (() => { try { return JSON.parse(u.protocols); } catch { return []; } })()
      : (u.protocols || []),
  };
}

function clientIp(req) {
  const raw = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip || '').toString().split(',')[0].trim();
  return raw.replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
}

function isIpAllowed(req) {
  const allowed = Array.isArray(cfg.backendAllowedIps) ? cfg.backendAllowedIps.filter(Boolean) : [];
  if (!allowed.length) return cfg.allowAnyBackendIp === true;
  return allowed.includes(clientIp(req));
}

function requireInternalAuth(req, res, next) {
  const expected = (cfg.nodeApiKey || '').trim();
  const auth = (req.headers.authorization || '').trim();
  if (!expected) return res.status(503).json({ ok: false, error: 'nodeApiKey is not configured' });
  if (!isIpAllowed(req)) return res.status(403).json({ ok: false, error: 'source IP is not allowed' });
  if (auth !== `Bearer ${expected}`) return res.status(401).json({ ok: false, error: 'invalid bearer token' });
  next();
}

function apiUser(u) {
  if (!u) return null;
  const { passHash, password, ...safe } = u;
  const parsed = parseUserRow(safe);
  return {
    ...parsed,
    subscriptionUrl: parsed.subscriptionToken ? subscriptionUrlFor(parsed) : null
  };
}

function apiUserWithTraffic(u, options = {}) {
  return attachTrafficToUserPayload(apiUser(u), options);
}

function getUserProtocols(user) {
  try { return JSON.parse(user.protocols || '[]'); } catch { return []; }
}

function enrichUserForList(u) {
  const safe = apiUserWithTraffic(u);
  const summary = getSessionSummary(u.id, u.username);
  return {
    ...safe,
    activeIpCount: summary.trackingAvailable ? summary.uniqueActiveIps : null,
    uniqueIpCount24h: summary.trackingAvailable ? summary.uniqueIpCount24h : null,
    trackingAvailable: summary.trackingAvailable,
    trackingReason: summary.reason || '',
    lastSeen: summary.lastSeen || safe.lastSeen
  };
}

function activeCutoffIso() {
  return new Date(Date.now() - (parseInt(cfg.sessionTtlMinutes, 10) || 10) * 60000).toISOString();
}

function activeCutoffMs() {
  return Date.now() - (parseInt(cfg.sessionTtlMinutes, 10) || 10) * 60000;
}

function ipHistoryTtlHours() {
  return parseInt(cfg.ipHistoryTtlHours, 10) || 24;
}

function ipHistoryCutoffMs() {
  return Date.now() - ipHistoryTtlHours() * 3600000;
}

function parseAccessLogTimestamp(value) {
  if (value === undefined || value === null || value === '') return new Date();
  const raw = String(value).trim();
  if (/^\d+(\.\d+)?$/.test(raw)) {
    const numeric = Number(raw);
    if (!Number.isFinite(numeric)) return null;
    return new Date(numeric < 1000000000000 ? numeric * 1000 : numeric);
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function isActiveNodeSession(session, cutoffMs = activeCutoffMs()) {
  const lastSeenMs = Date.parse(session?.lastSeen || '');
  return Number.isFinite(lastSeenMs) && lastSeenMs >= cutoffMs;
}

function refreshActiveSessionsFromLog() {
  // Per-user Naive sessions are derived on demand from auth_audit_log.
  // access.log is intentionally used only for node-level IP visibility.
}

function readLogTail(filePath, maxBytes = 1024 * 1024 * 10) {
  if (!filePath || !fs.existsSync(filePath)) return '';
  let fd = null;
  try {
    const st = fs.statSync(filePath);
    fd = fs.openSync(filePath, 'r');
    const len = Math.min(st.size, maxBytes);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, Math.max(0, st.size - len));
    return buf.toString('utf8');
  } catch {
    return '';
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

let trafficAuditCache = { key: '', readAtMs: 0, stats: new Map(), diagnostics: null };

function trafficAuditLogPath() {
  return String(cfg.trafficAuditLogPath || LOG_TRAFFIC_AUDIT).trim();
}

function toFiniteNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function emptyTrafficAuditDiagnostics(logPath, available) {
  return {
    trafficAuditLogAvailable: available,
    trafficAuditLogPath: logPath,
    trafficAuditLogLastReadAt: null,
    trafficAuditLogRecords: 0,
    lastTrafficEvent: null
  };
}

function getNaiveTrafficStats() {
  const logPath = trafficAuditLogPath();
  const now = Date.now();
  let stat = null;
  try { if (logPath && fs.existsSync(logPath)) stat = fs.statSync(logPath); } catch {}
  if (!logPath || !stat) {
    const diagnostics = emptyTrafficAuditDiagnostics(logPath, false);
    trafficAuditCache = { key: '', readAtMs: now, stats: new Map(), diagnostics };
    return { stats: trafficAuditCache.stats, diagnostics };
  }

  const key = `${logPath}:${stat.size}:${stat.mtimeMs}`;
  if (trafficAuditCache.key === key && now - trafficAuditCache.readAtMs < 10000) {
    return { stats: trafficAuditCache.stats, diagnostics: trafficAuditCache.diagnostics };
  }

  const stats = new Map();
  let records = 0;
  let lastTrafficEvent = null;
  const content = readLogTail(logPath, 1024 * 1024 * 25);
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    if (row.event && row.event !== 'connect_closed') continue;
    const username = String(row.username || '').trim();
    if (!username) continue;

    const uploadedBytes = toFiniteNumber(row.bytes_client_to_target);
    const downloadedBytes = toFiniteNumber(row.bytes_target_to_client);
    const totalBytes = toFiniteNumber(row.bytes_total, uploadedBytes + downloadedBytes);
    const parsedTs = parseAccessLogTimestamp(row.ts ?? row.time ?? row.timestamp);
    const lastSeen = parsedTs ? parsedTs.toISOString() : null;
    if (lastSeen && (!lastTrafficEvent || lastSeen > lastTrafficEvent)) lastTrafficEvent = lastSeen;

    const current = stats.get(username) || {
      username,
      uploadedMB: 0,
      downloadedMB: 0,
      usedMB: 0,
      records: 0,
      lastSeen: null
    };
    current.uploadedMB += uploadedBytes / 1048576;
    current.downloadedMB += downloadedBytes / 1048576;
    current.usedMB += totalBytes / 1048576;
    current.records += 1;
    if (lastSeen && (!current.lastSeen || lastSeen > current.lastSeen)) current.lastSeen = lastSeen;
    stats.set(username, current);
    records += 1;
  }

  const diagnostics = {
    trafficAuditLogAvailable: true,
    trafficAuditLogPath: logPath,
    trafficAuditLogLastReadAt: new Date(now).toISOString(),
    trafficAuditLogRecords: records,
    lastTrafficEvent
  };
  trafficAuditCache = { key, readAtMs: now, stats, diagnostics };
  return { stats, diagnostics };
}

function trafficForUsername(username) {
  return getNaiveTrafficStats().stats.get(username) || {
    username,
    uploadedMB: 0,
    downloadedMB: 0,
    usedMB: 0,
    records: 0,
    lastSeen: null
  };
}

function applyTrafficToUserPayload(payload, naive, options = {}) {
  if (!payload) return payload;
  const mieru = options.mieruTraffic || {};
  const storedMieruUsed = options.useStoredMieru === false ? 0 : toFiniteNumber(payload.usedMB);
  const mieruUploadedMB = toFiniteNumber(mieru.uploadMB ?? mieru.uploadedMB);
  const mieruDownloadedMB = toFiniteNumber(mieru.downloadMB ?? mieru.downloadedMB);
  const mieruUsedMB = toFiniteNumber(mieru.usedMB, storedMieruUsed);
  const naiveUsedMB = toFiniteNumber(naive.usedMB);
  const uploadedMB = toFiniteNumber(naive.uploadedMB) + mieruUploadedMB;
  const downloadedMB = toFiniteNumber(naive.downloadedMB) + mieruDownloadedMB;
  return {
    ...payload,
    usedMB: naiveUsedMB + mieruUsedMB,
    uploadedMB,
    downloadedMB,
    uploadMB: uploadedMB,
    downloadMB: downloadedMB,
    naiveUsedMB,
    naiveUploadedMB: toFiniteNumber(naive.uploadedMB),
    naiveDownloadedMB: toFiniteNumber(naive.downloadedMB),
    mieruUsedMB,
    mieruUploadedMB,
    mieruDownloadedMB,
    trafficSource: naiveUsedMB > 0 ? 'naive-traffic-audit' : (mieruUsedMB > 0 ? 'mieru' : 'none'),
    lastSeen: naive.lastSeen || mieru.lastSeen || payload.lastSeen
  };
}

function attachTrafficToUserPayload(payload, options = {}) {
  return applyTrafficToUserPayload(payload, trafficForUsername(payload?.username), options);
}

function getNodeSessionsFromCaddyLog() {
  const content = readLogTail(LOG_CADDY, 1024 * 1024 * 5);
  if (!content) return [];

  const byIp = new Map();
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    const req = row.request || {};
    const method = row.method || req.method || '';
    if (method && method !== 'CONNECT') continue;
    const remoteIp = String(req.remote_ip || row.remote_ip || row.remote_addr || '').replace(/^::ffff:/, '');
    if (!remoteIp) continue;
    const tsRaw = row.ts ?? row.time ?? row.timestamp ?? new Date().toISOString();
    const parsed = parseAccessLogTimestamp(tsRaw);
    if (!parsed) continue;
    const seen = parsed.toISOString();
    const host = row.host || req.host || req.uri || '';
    const existing = byIp.get(remoteIp) || {
      remoteIp,
      firstSeen: seen,
      lastSeen: seen,
      requestCount: 0,
      hosts: new Set(),
      protocol: 'naive',
      username: null
    };
    existing.requestCount += 1;
    if (host) existing.hosts.add(String(host));
    if (seen < existing.firstSeen) existing.firstSeen = seen;
    if (seen > existing.lastSeen) existing.lastSeen = seen;
    byIp.set(remoteIp, existing);
  }
  return [...byIp.values()]
    .map(s => ({ ...s, hosts: [...s.hosts].slice(-10) }))
    .sort((a, b) => b.lastSeen.localeCompare(a.lastSeen));
}

function authAuditLogPath() {
  return String(cfg.authAuditLogPath || '').trim();
}

function authAuditUnavailableReason() {
  const logPath = authAuditLogPath();
  if (!logPath || !fs.existsSync(logPath)) return AUTH_AUDIT_LOG_UNCONFIGURED_REASON;
  return '';
}

function sessionResetCutoffMs(username) {
  if (!db || !username) return 0;
  try {
    const row = db.prepare('SELECT reset_at FROM session_resets WHERE username = ?').get(username);
    const ms = Date.parse(row?.reset_at || '');
    return Number.isFinite(ms) ? ms : 0;
  } catch {
    return 0;
  }
}

function normalizeAuditIp(value) {
  const raw = String(value || '').trim().replace(/^::ffff:/, '');
  if (!raw) return '';
  const split = raw.match(/^\[?([0-9a-fA-F:.]+)\]?:(\d+)$/);
  return split ? split[1] : raw;
}

let authAuditCache = { key: '', readAtMs: 0, payload: null };

function emptyAuthAuditDiagnostics(logPath, available, records = 0) {
  return {
    authAuditLogAvailable: available,
    authAuditLogPath: logPath,
    authAuditLogRecords: records,
    lastAuthEvent: null
  };
}

function getSessionResetMap() {
  const map = new Map();
  if (!db) return map;
  try {
    for (const row of db.prepare('SELECT username, reset_at FROM session_resets').all()) {
      const ms = Date.parse(row.reset_at || '');
      if (row.username && Number.isFinite(ms)) map.set(row.username, ms);
    }
  } catch {}
  return map;
}

function buildAuthAuditHistoryPayload() {
  const reason = authAuditUnavailableReason();
  const logPath = authAuditLogPath();
  if (reason) {
    return {
      trackingAvailable: false,
      reason,
      ttlMinutes: parseInt(cfg.sessionTtlMinutes, 10) || 10,
      ttlHours: ipHistoryTtlHours(),
      ips: [],
      sessions: [],
      activeIpCount: null,
      uniqueActiveIps: null,
      uniqueIpCount24h: null,
      users: [],
      diagnostics: emptyAuthAuditDiagnostics(logPath, false, 0)
    };
  }

  const now = Date.now();
  let stat = null;
  try { if (logPath && fs.existsSync(logPath)) stat = fs.statSync(logPath); } catch {}
  const key = stat ? `${logPath}:${stat.size}:${stat.mtimeMs}:${cfg.sessionTtlMinutes}:${cfg.ipHistoryTtlHours}` : '';
  if (authAuditCache.key === key && authAuditCache.payload && now - authAuditCache.readAtMs < 10000) {
    return authAuditCache.payload;
  }

  const cutoffMs = activeCutoffMs();
  const historyCutoffMs = ipHistoryCutoffMs();
  const resetMap = getSessionResetMap();
  const content = readLogTail(logPath, AUTH_AUDIT_MAX_BYTES);
  if (!content) {
    const payload = {
      trackingAvailable: true,
      ttlMinutes: parseInt(cfg.sessionTtlMinutes, 10) || 10,
      ttlHours: ipHistoryTtlHours(),
      ips: [],
      activeIpCount: 0,
      uniqueActiveIps: 0,
      uniqueIpCount24h: 0,
      users: [],
      diagnostics: emptyAuthAuditDiagnostics(logPath, true, 0)
    };
    authAuditCache = { key, readAtMs: now, payload };
    return payload;
  }

  const byUserIp = new Map();
  let records = 0;
  let lastAuthEvent = null;
  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }

    const username = String(row.username || '').trim();
    if (!username) continue;

    const parsed = parseAccessLogTimestamp(row.ts ?? row.time ?? row.timestamp);
    if (!parsed) continue;
    const seenMs = parsed.getTime();
    const seen = parsed.toISOString();
    const resetMs = resetMap.get(username) || 0;
    if (resetMs && seenMs <= resetMs) continue;
    records += 1;
    if (!lastAuthEvent || seen > lastAuthEvent) lastAuthEvent = seen;
    if (seenMs < historyCutoffMs) continue;

    const ip = normalizeAuditIp(row.remote_ip || row.remoteIp || row.remote_addr);
    if (!ip) continue;

    const host = String(row.host || row.uri || '').trim();
    const key = `${username}\n${ip}`;
    const existing = byUserIp.get(key) || {
      username,
      ip,
      remoteIp: ip,
      protocol: 'naive',
      firstSeen: seen,
      lastSeen: seen,
      requestCount: 0,
      hosts: new Set(),
      active: false
    };
    existing.requestCount += 1;
    if (host) existing.hosts.add(host);
    if (seen < existing.firstSeen) existing.firstSeen = seen;
    if (seen > existing.lastSeen) existing.lastSeen = seen;
    existing.active = Date.parse(existing.lastSeen) >= cutoffMs;
    byUserIp.set(key, existing);
  }

  const ips = [...byUserIp.values()]
    .map(s => ({ ...s, hosts: [...s.hosts].slice(-10) }))
    .sort((a, b) => {
      const byUser = a.username.localeCompare(b.username);
      return byUser || b.lastSeen.localeCompare(a.lastSeen);
    });
  const usersMap = new Map();
  for (const s of ips) {
    if (!usersMap.has(s.username)) usersMap.set(s.username, []);
    usersMap.get(s.username).push(s);
  }
  const users = [...usersMap.entries()].map(([username, userSessions]) => ({
    username,
    activeIpCount: userSessions.filter(s => s.active).length,
    uniqueActiveIps: userSessions.filter(s => s.active).length,
    uniqueIpCount24h: userSessions.length,
    sessions: userSessions.filter(s => s.active),
    ips: userSessions
  }));
  const activeIps = ips.filter(s => s.active);
  const payload = {
    trackingAvailable: true,
    ttlMinutes: parseInt(cfg.sessionTtlMinutes, 10) || 10,
    ttlHours: ipHistoryTtlHours(),
    ips,
    sessions: activeIps,
    activeIpCount: new Set(activeIps.map(s => s.ip)).size,
    uniqueActiveIps: new Set(activeIps.map(s => s.ip)).size,
    uniqueIpCount24h: new Set(ips.map(s => s.ip)).size,
    users,
    diagnostics: { ...emptyAuthAuditDiagnostics(logPath, true, records), lastAuthEvent }
  };
  authAuditCache = { key, readAtMs: now, payload };
  return payload;
}

function filterAuthAuditHistory(payload, targetUsername = '') {
  if (!targetUsername || !payload.trackingAvailable) return payload;
  const ips = (payload.ips || []).filter(s => s.username === targetUsername);
  const sessions = ips.filter(s => s.active);
  return {
    ...payload,
    ips,
    sessions,
    activeIpCount: new Set(sessions.map(s => s.ip)).size,
    uniqueActiveIps: new Set(sessions.map(s => s.ip)).size,
    uniqueIpCount24h: new Set(ips.map(s => s.ip)).size,
    users: ips.length ? [{
      username: targetUsername,
      activeIpCount: new Set(sessions.map(s => s.ip)).size,
      uniqueActiveIps: new Set(sessions.map(s => s.ip)).size,
      uniqueIpCount24h: new Set(ips.map(s => s.ip)).size,
      sessions,
      ips
    }] : []
  };
}

function parseAuthAuditSessions(targetUsername = '') {
  return filterAuthAuditHistory(buildAuthAuditHistoryPayload(), targetUsername);
}

function nodeSessionsPayload() {
  const cutoffMs = activeCutoffMs();
  const sessions = getNodeSessionsFromCaddyLog()
    .map(s => ({ ...s, active: isActiveNodeSession(s, cutoffMs) }))
    .filter(s => s.active);
  return {
    sessions,
    uniqueActiveIps: new Set(sessions.map(s => s.remoteIp)).size,
    note: 'Node-level IPs from Caddy access.log; per-user attribution uses auth_audit_log'
  };
}

function getUserSessions(id, username) {
  void id;
  return parseAuthAuditSessions(username);
}

function getSessionSummary(id, username) {
  const payload = getUserSessions(id, username);
  const lastSeen = payload.sessions.reduce((latest, s) => (
    !latest || s.lastSeen > latest ? s.lastSeen : latest
  ), null);
  return { ...payload, lastSeen };
}

function getUserIpHistory(id, username) {
  void id;
  return parseAuthAuditSessions(username);
}

function formatSessionsForApi(sessions) {
  return sessions.map(s => ({
    username: s.username,
    protocol: s.protocol || 'naive',
    ip: s.ip || s.remoteIp || s.remote_ip,
    remoteIp: s.remoteIp || s.ip || s.remote_ip,
    firstSeen: s.firstSeen || s.first_seen,
    lastSeen: s.lastSeen || s.last_seen,
    requestCount: s.requestCount || 0,
    hosts: Array.isArray(s.hosts) ? s.hosts : []
  }));
}

function formatIpHistoryForApi(ips) {
  return ips.map(s => ({
    ip: s.ip || s.remoteIp || s.remote_ip,
    remoteIp: s.remoteIp || s.ip || s.remote_ip,
    firstSeen: s.firstSeen || s.first_seen,
    lastSeen: s.lastSeen || s.last_seen,
    requestCount: s.requestCount || 0,
    active: s.active === true,
    hosts: Array.isArray(s.hosts) ? s.hosts : []
  }));
}

let nodeExplorerCache = { key: '', readAtMs: 0, snapshot: null };

function emptyNaiveTraffic(username) {
  return {
    username,
    uploadedMB: 0,
    downloadedMB: 0,
    usedMB: 0,
    records: 0,
    lastSeen: null
  };
}

function latestIso(...values) {
  return values.filter(Boolean).reduce((latest, value) => (
    !latest || value > latest ? value : latest
  ), null);
}

function getNodeExplorerSnapshot() {
  const now = Date.now();
  const users = getAllUsers();
  const authPayload = buildAuthAuditHistoryPayload();
  const trafficPayload = getNaiveTrafficStats();
  const trafficStats = trafficPayload.stats || new Map();
  const authDiag = authPayload.diagnostics || emptyAuthAuditDiagnostics(authAuditLogPath(), false, 0);
  const trafficDiag = trafficPayload.diagnostics || emptyTrafficAuditDiagnostics(trafficAuditLogPath(), false);
  const key = [
    users.length,
    users.map(u => `${u.id}:${u.updatedAt || ''}:${u.enabled}:${u.suspicious || 0}`).join('|'),
    authAuditCache.key,
    trafficAuditCache.key,
    cfg.sessionTtlMinutes,
    cfg.ipHistoryTtlHours
  ].join('\n');

  if (nodeExplorerCache.key === key && nodeExplorerCache.snapshot && now - nodeExplorerCache.readAtMs < NODE_EXPLORER_CACHE_TTL_MS) {
    return nodeExplorerCache.snapshot;
  }

  const authByUsername = new Map();
  for (const row of authPayload.users || []) authByUsername.set(row.username, row);

  const activeIpSet = new Set();
  const historyIpSet = new Set();
  const ipIndex = new Map();
  let trafficUsedMB = 0;

  const explorerUsers = users.map(user => {
    const auth = authByUsername.get(user.username) || { sessions: [], ips: [], activeIpCount: 0, uniqueIpCount24h: 0 };
    const naiveTraffic = trafficStats.get(user.username) || emptyNaiveTraffic(user.username);
    const safe = applyTrafficToUserPayload(apiUser(user), naiveTraffic);
    const ips = auth.ips || [];
    const sessions = auth.sessions || ips.filter(ip => ip.active);
    const activeIpCount = sessions.length;
    const uniqueIpCount24h = ips.length;
    const lastSeen = latestIso(
      safe.lastSeen,
      naiveTraffic.lastSeen,
      ...ips.map(ip => ip.lastSeen)
    );

    trafficUsedMB += toFiniteNumber(safe.usedMB);
    for (const ip of ips) {
      if (ip.active) activeIpSet.add(ip.ip);
      historyIpSet.add(ip.ip);
      const current = ipIndex.get(ip.ip) || {
        ip: ip.ip,
        users: new Set(),
        active: false,
        lastSeen: null,
        firstSeen: null,
        requestCount: 0,
        hosts: new Set()
      };
      current.users.add(user.username);
      current.active = current.active || ip.active === true;
      current.lastSeen = latestIso(current.lastSeen, ip.lastSeen);
      current.firstSeen = !current.firstSeen || (ip.firstSeen && ip.firstSeen < current.firstSeen) ? ip.firstSeen : current.firstSeen;
      current.requestCount += toFiniteNumber(ip.requestCount);
      for (const host of ip.hosts || []) current.hosts.add(host);
      ipIndex.set(ip.ip, current);
    }

    return {
      id: safe.id,
      username: safe.username,
      enabled: safe.enabled !== false,
      suspicious: safe.suspicious === true || safe.suspicious === 1,
      protocols: safe.protocols,
      quotaMB: safe.quotaMB,
      activeIpCount,
      uniqueIpCount24h,
      usedMB: safe.usedMB,
      uploadedMB: safe.uploadedMB,
      downloadedMB: safe.downloadedMB,
      trafficSource: safe.trafficSource,
      lastSeen,
      ips: formatIpHistoryForApi(ips)
    };
  });

  const usersActive = explorerUsers.filter(u => u.activeIpCount > 0).length;
  const snapshot = {
    generatedAt: new Date(now).toISOString(),
    cache: {
      ttlMs: NODE_EXPLORER_CACHE_TTL_MS,
      refreshedAt: new Date(now).toISOString()
    },
    node: {
      domain: cfg.domain,
      serverIp: cfg.serverIp
    },
    summary: {
      usersTotal: users.length,
      usersActive,
      activeIpsTotal: activeIpSet.size,
      uniqueIps24hTotal: historyIpSet.size,
      trafficUsedMB
    },
    users: explorerUsers,
    ipIndex,
    logs: {
      authAuditLogAvailable: authDiag.authAuditLogAvailable,
      trafficAuditLogAvailable: trafficDiag.trafficAuditLogAvailable,
      authAuditLogPath: authDiag.authAuditLogPath,
      trafficAuditLogPath: trafficDiag.trafficAuditLogPath,
      authAuditLogRecords: authDiag.authAuditLogRecords,
      trafficAuditLogRecords: trafficDiag.trafficAuditLogRecords,
      lastAuthEvent: authDiag.lastAuthEvent || null,
      lastTrafficEvent: trafficDiag.lastTrafficEvent || null
    }
  };
  nodeExplorerCache = { key, readAtMs: now, snapshot };
  return snapshot;
}

function publicExplorerSnapshot(snapshot = getNodeExplorerSnapshot()) {
  const { ipIndex, ...publicPayload } = snapshot;
  void ipIndex;
  return publicPayload;
}

function userExplorerDetails(user) {
  const snapshot = getNodeExplorerSnapshot();
  const explorerUser = snapshot.users.find(u => u.id === user.id);
  const traffic = explorerUser ? {
    usedMB: explorerUser.usedMB,
    uploadedMB: explorerUser.uploadedMB,
    downloadedMB: explorerUser.downloadedMB,
    trafficSource: explorerUser.trafficSource
  } : {};
  return {
    user: explorerUser || internalUserPayload(user),
    traffic,
    sessions: (explorerUser?.ips || []).filter(ip => ip.active),
    ipHistory: explorerUser?.ips || [],
    generatedAt: snapshot.generatedAt,
    node: snapshot.node
  };
}

function ipExplorerDetails(ip) {
  const normalized = normalizeAuditIp(ip);
  const snapshot = getNodeExplorerSnapshot();
  const found = snapshot.ipIndex.get(normalized);
  if (!found) {
    return {
      ip: normalized,
      users: [],
      active: false,
      lastSeen: null,
      requestCount: 0,
      hosts: []
    };
  }
  return {
    ip: normalized,
    users: [...found.users].sort(),
    active: found.active,
    firstSeen: found.firstSeen,
    lastSeen: found.lastSeen,
    requestCount: found.requestCount,
    hosts: [...found.hosts].slice(-20)
  };
}

function unavailableUserSessionPayload() {
  const reason = authAuditUnavailableReason() || AUTH_AUDIT_LOG_UNCONFIGURED_REASON;
  return { sessions: [], uniqueActiveIps: null, trackingAvailable: false, reason };
}

function resetUserSessions(id, username) {
  if (db) db.prepare('DELETE FROM active_sessions WHERE user_id = ? OR username = ?').run(id, username);
  if (db && username) {
    db.prepare(`
      INSERT INTO session_resets (username, reset_at)
      VALUES (?, ?)
      ON CONFLICT(username) DO UPDATE SET reset_at = excluded.reset_at
    `).run(username, new Date().toISOString());
  }
  authAuditCache = { key: '', readAtMs: 0, payload: null };
  nodeExplorerCache = { key: '', readAtMs: 0, snapshot: null };
}

function dashboardSessionStats() {
  const payload = parseAuthAuditSessions();
  const users = payload.users || [];
  const activeUsers = users.filter(u => u.sessions.length > 0).length;
  const maxIps = parseInt(cfg.maxUniqueIpsPerUser, 10) || 5;
  const exceeded = users.filter(u => u.uniqueActiveIps > maxIps).length;
  const nodeSessions = nodeSessionsPayload();
  return {
    activeUsers: payload.trackingAvailable ? activeUsers : null,
    activeIps: nodeSessions.uniqueActiveIps,
    perUserActiveIps: payload.trackingAvailable ? payload.uniqueActiveIps : null,
    ipLimitExceededUsers: payload.trackingAvailable ? exceeded : null
  };
}

function assertCaddyApplied(status) {
  if (!status.caddyOk) {
    const err = new Error(status.caddyError || 'caddy-naive failed to validate or apply config');
    err.status = 500;
    throw err;
  }
  if (status.mitaRequired && !status.mitaOk) {
    const err = new Error(status.mitaError || 'mita failed to apply config');
    err.status = 500;
    throw err;
  }
}

// ── Users API ─────────────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  const users = getAllUsers().map(enrichUserForList);
  res.json(users);
});

app.get('/api/users/sessions', requireAuth, (_req, res) => {
  const payload = parseAuthAuditSessions();
  res.json({
    ok: true,
    trackingAvailable: payload.trackingAvailable,
    reason: payload.reason,
    ttlMinutes: payload.ttlMinutes,
    ttlHours: payload.ttlHours,
    uniqueActiveIps: payload.uniqueActiveIps,
    uniqueIpCount24h: payload.uniqueIpCount24h,
    users: (payload.users || []).map(u => ({
      username: u.username,
      uniqueActiveIps: u.uniqueActiveIps,
      activeIpCount: u.activeIpCount,
      uniqueIpCount24h: u.uniqueIpCount24h,
      sessions: formatSessionsForApi(u.sessions),
      ips: formatIpHistoryForApi(u.ips || [])
    }))
  });
});

app.get('/api/users/:id', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(enrichUserForList(user));
});

app.get('/api/node-api/settings', requireAuth, (req, res) => {
  res.json({
    ok: true,
    nodeApiKey: cfg.nodeApiKey || '',
    status: (cfg.nodeApiKey && (cfg.allowAnyBackendIp || (Array.isArray(cfg.backendAllowedIps) && cfg.backendAllowedIps.length > 0))) ? 'ready' : 'locked',
    version: nodeAgentVersionPayload(),
    settings: safeNodeSettings()
  });
});

app.patch('/api/node-api/settings', requireAuth, (req, res) => {
  const result = applyNodeSettingsPatch(req.body);
  if (result.error) return res.status(400).json({ ok: false, error: result.error });
  res.json({ ok: true, settings: result.settings });
});

app.post('/api/node-api/regenerate-key', requireAuth, (_req, res) => {
  cfg.nodeApiKey = crypto.randomBytes(32).toString('hex');
  saveConfig();
  res.json({ ok: true, nodeApiKey: cfg.nodeApiKey });
});

app.post('/api/users', requireAuth, (req, res) => {
  const { email, username, password, protocols, quotaMB, quotaGb, enabled } = req.body;
  const expiry = req.body.expiry ?? req.body.expiresAt;
  const validation = validateUserInput(
    { email, username, password, protocols, quotaMB, quotaGb, enabled }, true);
  if (validation.error)
    return res.status(400).json({ error: validation.error });

  if (getUserByUsername(username))
    return res.status(409).json({ error: 'Username already exists' });

  if (expiry && isNaN(Date.parse(expiry)))
    return res.status(400).json({ error: 'expiry must be a valid ISO date string' });

  const now  = new Date().toISOString();
  const user = {
    id:        uuidv4(),
    // Email is optional: store NULL (not '') so the UNIQUE constraint allows
    // multiple users without an email.
    email:     (email && email.trim()) ? email.trim() : null,
    username,
    passHash:  bcrypt.hashSync(password, 12),
    password,
    expiry:    expiry || null,
    protocols: JSON.stringify(validation.protocols),
    quotaMB:   validation.quotaMB,
    enabled:   validation.enabled === undefined ? 1 : (validation.enabled ? 1 : 0),
    suspicious: 0,
    subscriptionToken: generateSubscriptionToken(),
    usedMB:    0,
    createdAt: now, updatedAt: now, lastSeen: null
  };
  upsertUser(user);

  // Bug 6: rebuild Caddyfile + reload Caddy; rebuild mita state; report status
  const svcStatus = applyAllConfigs();
  try { assertCaddyApplied(svcStatus); }
  catch (e) {
    deleteUser(user.id);
    applyAllConfigs();
    return res.status(e.status || 500).json({ ok: false, error: e.message, ...svcStatus });
  }

  res.status(201).json({ ok: true, ...apiUserWithTraffic(user), ...svcStatus });
});

function handleUserUpdate(req, res) {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const { email, username, password, protocols, quotaMB, quotaGb, enabled } = req.body;
  const expiry = req.body.expiry ?? req.body.expiresAt;
  const validation = validateUserInput(
    { email: email ?? user.email,
      username: username ?? user.username,
      password,
      protocols,
      quotaMB: quotaMB !== undefined ? quotaMB : undefined,
      quotaGb: quotaGb !== undefined ? quotaGb : undefined,
      enabled }, false);
  if (validation.error)
    return res.status(400).json({ error: validation.error });

  if (expiry !== undefined && expiry !== null && isNaN(Date.parse(expiry)))
    return res.status(400).json({ error: 'expiry must be a valid ISO date string' });

  const updated = {
    ...user,
    email:     email !== undefined ? ((email && email.trim()) ? email.trim() : null) : user.email,
    username:  username  ?? user.username,
    expiry:    expiry    !== undefined ? (expiry || null) : user.expiry,
    protocols: protocols
      ? JSON.stringify(validation.protocols)
      : user.protocols,
    quotaMB:   (quotaMB !== undefined || quotaGb !== undefined)
      ? validation.quotaMB
      : user.quotaMB,
    enabled:   validation.enabled === undefined ? user.enabled : (validation.enabled ? 1 : 0),
    updatedAt: new Date().toISOString()
  };
  if (password) {
    updated.passHash = bcrypt.hashSync(password, 12);
    updated.password = password;
  }
  upsertUser(updated);

  const svcStatus = applyAllConfigs();
  try { assertCaddyApplied(svcStatus); }
  catch (e) {
    upsertUser(user);
    applyAllConfigs();
    return res.status(e.status || 500).json({ ok: false, error: e.message, ...svcStatus });
  }

  res.json({ ok: true, ...apiUserWithTraffic(updated), ...svcStatus });
}

app.put('/api/users/:id', requireAuth, handleUserUpdate);
app.patch('/api/users/:id', requireAuth, handleUserUpdate);

app.delete('/api/users/:id', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  deleteUser(req.params.id);
  const svcStatus = applyAllConfigs();
  try { assertCaddyApplied(svcStatus); }
  catch (e) {
    upsertUser(user);
    applyAllConfigs();
    return res.status(e.status || 500).json({ ok: false, error: e.message, ...svcStatus });
  }
  res.json({ ok: true, ...svcStatus });
});

app.get('/api/users/:id/sessions', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const payload = getUserSessions(user.id, user.username);
  res.json({
    ok: true,
    trackingAvailable: payload.trackingAvailable,
    reason: payload.reason,
    ttlMinutes: payload.ttlMinutes,
    ttlHours: payload.ttlHours,
    uniqueActiveIps: payload.uniqueActiveIps,
    uniqueIpCount24h: payload.uniqueIpCount24h,
    sessions: formatSessionsForApi(payload.sessions)
  });
});

app.get('/api/users/:id/ip-history', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const payload = getUserIpHistory(user.id, user.username);
  res.json({
    ok: true,
    trackingAvailable: payload.trackingAvailable,
    reason: payload.reason,
    username: user.username,
    ttlMinutes: payload.ttlMinutes,
    ttlHours: payload.ttlHours,
    activeIpCount: payload.activeIpCount,
    uniqueActiveIps: payload.uniqueActiveIps,
    uniqueIpCount24h: payload.uniqueIpCount24h,
    ips: formatIpHistoryForApi(payload.ips || [])
  });
});

app.post('/api/users/:id/reset-sessions', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  resetUserSessions(user.id, user.username);
  res.json({ ok: true });
});

app.get('/api/node/sessions', requireAuth, (_req, res) => {
  res.json({ ok: true, ...nodeSessionsPayload() });
});

app.post('/api/users/:id/rotate-subscription-token', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const updated = { ...user, subscriptionToken: generateSubscriptionToken(), updatedAt: new Date().toISOString() };
  upsertUser(updated);
  res.json({ ok: true, user: apiUserWithTraffic(updated) });
});

// ── Server settings ───────────────────────────────────────────────────────────

// Caddy port: rebuild Caddyfile + full restart (port binding change)
// Bug 52: verify caddy-naive is active after restart; return HTTP 500 if not
app.post('/api/settings/naive-port', requireAuth, (req, res) => {
  const p = parseInt(req.body.port, 10);
  if (!p || p < 1 || p > 65535)
    return res.status(400).json({ error: 'Invalid port (1–65535)' });
  cfg.naivePort = p; saveConfig();
  try {
    const content = buildCaddyfile(cfg, getAllUsers());
    writeCaddyfileAtomic(content);
    const validation = validateCaddyfile();
    if (!validation.ok) return res.status(500).json({ ok: false, error: validation.error });
    const restarted = restartCaddy();
    if (!restarted.ok) return res.status(500).json({ ok: false, error: restarted.error });
    // Bug 52: confirm the service is actually running after restart
    let active = false;
    try { execSync('systemctl is-active caddy-naive', { timeout: 8000 }); active = true; } catch {}
    if (!active) {
      return res.status(500).json({
        ok: false,
        error: 'caddy-naive failed to start after port change — run: journalctl -u caddy-naive -n 30'
      });
    }
    res.json({ ok: true, message: `NaiveProxy port changed to ${p}. Clients must download new configs.` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Mieru ports: UFW update + full restart
app.post('/api/settings/mieru-ports', requireAuth, (req, res) => {
  const s = parseInt(req.body.portStart, 10);
  const e = parseInt(req.body.portEnd,   10);
  if (!s || !e || s < 1025 || e > 65535 || e < s)
    return res.status(400).json({ error: 'Invalid port range (1025–65535, end ≥ start)' });

  const oldS = cfg.mieruPortStart, oldE = cfg.mieruPortEnd;
  cfg.mieruPortStart = s; cfg.mieruPortEnd = e; saveConfig();

  try {
    // Bug 7: use single-port helper to avoid UFW crash when start===end
    ufwMieruRule('delete', oldS, oldE, 'tcp', '');
    ufwMieruRule('delete', oldS, oldE, 'udp', '');
    ufwMieruRule('',       s,    e,    'tcp', 'Mieru TCP');
    if (cfg.udpEnabled) ufwMieruRule('', s, e, 'udp', 'Mieru UDP');
  } catch {}

  try {
    const mita = applyMitaConfigDetailed();
    if (mita.required && !mita.ok) return res.status(500).json({ ok: false, error: mita.error });
    res.json({ ok: true, mitaOk: mita.ok, mitaRequired: mita.required, mitaIdle: mita.idle, mitaError: mita.error || '',
      message: mita.idle
        ? 'Mieru не может быть запущен: нет активных Mieru-пользователей'
        : `Mieru ports changed to ${s}–${e}. Service restarted. Clients must download new configs.` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Traffic pattern + MTU: mita reload
app.post('/api/settings/traffic-pattern', requireAuth, (req, res) => {
  const validPatterns = ['NOOP', 'RANDOM_PADDING', 'RANDOM_PADDING_AGGRESSIVE'];
  const { pattern, mtu } = req.body;
  if (!validPatterns.includes(pattern))
    return res.status(400).json({ error: `Invalid pattern. Valid: ${validPatterns.join(', ')}` });
  if (mtu !== undefined) {
    const m = parseInt(mtu, 10);
    if (m < 1280 || m > 1400) return res.status(400).json({ error: 'MTU must be 1280–1400' });
    cfg.mtu = m;
  }
  cfg.trafficPattern = pattern; saveConfig();
  try {
    const mita = applyMitaConfigDetailed();
    if (mita.required && !mita.ok) return res.status(500).json({ ok: false, error: mita.error, pattern, mtu: cfg.mtu });
    res.json({ ok: true, mitaOk: mita.ok, mitaRequired: mita.required, mitaIdle: mita.idle, mitaError: mita.error || '', pattern, mtu: cfg.mtu });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// UDP toggle: requires full Mieru restart (port bindings change)
app.post('/api/settings/udp-toggle', requireAuth, (req, res) => {
  const enable = req.body.enabled === true || req.body.enabled === 'true';
  cfg.udpEnabled = enable; saveConfig();
  try {
    const s = cfg.mieruPortStart, e = cfg.mieruPortEnd;
    // Bug 7: use single-port helper to avoid UFW crash when start===end
    if (enable) {
      ufwMieruRule('', s, e, 'udp', 'Mieru UDP');
    } else {
      ufwMieruRule('delete', s, e, 'udp', '');
    }
  } catch {}
  try {
    const mita = applyMitaConfigDetailed();
    if (mita.required && !mita.ok) return res.status(500).json({ ok: false, error: mita.error, udpEnabled: enable });
    res.json({ ok: true, mitaOk: mita.ok, mitaRequired: mita.required, mitaIdle: mita.idle, mitaError: mita.error || '', udpEnabled: enable,
      message: mita.idle
        ? 'Mieru не может быть запущен: нет активных Mieru-пользователей'
        : `UDP ${enable ? 'enabled' : 'disabled'}. Mieru restarted.` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Language setting
app.post('/api/settings/language', requireAuth, (req, res) => {
  const { language } = req.body;
  if (!['ru', 'en'].includes(language))
    return res.status(400).json({ error: 'Supported languages: ru, en' });
  cfg.language = language;
  saveConfig();
  res.json({ ok: true, language });
});

// Probe secret update — rebuilds Caddyfile and reloads Caddy.
// Setting a secret also switches probeMode to 'secret'.
app.post('/api/settings/probe-secret', requireAuth, (req, res) => {
  const { probeSecret } = req.body;
  if (!probeSecret || probeSecret.length < 8)
    return res.status(400).json({ error: 'probe_secret must be at least 8 characters' });
  cfg.probeSecret = probeSecret;
  cfg.probeMode = 'secret';          // Bug 81: setting a secret implies secret mode
  saveConfig();
  // Persist to file for install.sh smoke tests
  try {
    fs.writeFileSync(path.join(resolvedCaddyCfgDir, 'probe_secret'), probeSecret, { mode: 0o600 });
  } catch {}
  try {
    const content = buildCaddyfile(cfg, getAllUsers());
    writeCaddyfileAtomic(content);
    const validation = validateCaddyfile();
    if (!validation.ok) return res.status(500).json({ ok: false, error: validation.error });
    const applied = reloadCaddy();
    if (!applied.ok) return res.status(500).json({ ok: false, error: applied.error });
    res.json({ ok: true, caddyAction: applied.action, message: 'Probe secret updated. Caddy reloaded.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bug 81: probe_resistance mode toggle ('off' | 'bare' | 'secret').
//   'off'    → remove probe_resistance entirely
//   'bare'   → bare  probe_resistance  (no secret) — matches known-good ref server
//   'secret' → probe_resistance <secret>  (requires an existing/provided secret)
app.post('/api/settings/probe-mode', requireAuth, (req, res) => {
  const { probeMode, probeSecret } = req.body || {};
  const mode = String(probeMode || '').trim().toLowerCase();
  if (!['off', 'bare', 'secret'].includes(mode))
    return res.status(400).json({ error: "probeMode must be one of: off, bare, secret" });

  if (mode === 'secret') {
    // A secret is required — either provided now or already stored.
    const newSecret = (probeSecret || '').trim();
    if (newSecret) {
      if (newSecret.length < 8)
        return res.status(400).json({ error: 'probe_secret must be at least 8 characters' });
      cfg.probeSecret = newSecret;
      try {
        fs.writeFileSync(path.join(resolvedCaddyCfgDir, 'probe_secret'), newSecret, { mode: 0o600 });
      } catch {}
    } else if (!(cfg.probeSecret || '').trim()) {
      return res.status(400).json({ error: "secret mode requires a probe_secret (>= 8 chars)" });
    }
  }

  cfg.probeMode = mode;
  saveConfig();
  try {
    const content = buildCaddyfile(cfg, getAllUsers());
    writeCaddyfileAtomic(content);
    const validation = validateCaddyfile();
    if (!validation.ok) return res.status(500).json({ ok: false, error: validation.error });
    const applied = reloadCaddy();
    if (!applied.ok) return res.status(500).json({ ok: false, error: applied.error });
    res.json({ ok: true, caddyAction: applied.action, probeMode: mode, message: `probe_resistance mode set to '${mode}'. Caddy reloaded.` });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bug 15: /api/services/rebuild-all — used by update.sh --repair
app.post('/api/services/rebuild-all', requireAuth, (req, res) => {
  try {
    const content = buildCaddyfile(cfg, getAllUsers());
    writeCaddyfileAtomic(content);
    const validation = validateCaddyfile();
    if (!validation.ok) return res.status(500).json({ ok: false, error: validation.error });
    const caddy = reloadCaddy();
    if (!caddy.ok) return res.status(500).json({ ok: false, error: caddy.error });
    const mita = applyMitaConfigDetailed();
    if (mita.required && !mita.ok) return res.status(500).json({ ok: false, caddyOk: true, caddyAction: caddy.action, mitaOk: false, error: mita.error });
    res.json({ ok: true, caddyOk: true, caddyAction: caddy.action, mitaOk: mita.ok,
      mitaRequired: mita.required, mitaIdle: mita.idle, mitaError: mita.error || '',
      message: 'Caddyfile and Mieru config rebuilt/applied from database.' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── v1.2.6: Cascade settings (Variant B) ──────────────────────────────────────
// Naive cascade  → Caddyfile `upstream` (handled by buildCaddyfile).
// Mieru cascade  → Variant B (mieru-client + redsocks + iptables) orchestrated
//                  by scripts/cascade_mieru.sh. The entry mita stays plain.
app.get('/api/settings/cascade', requireAuth, (req, res) => {
  const m = cfg.cascadeMieru || {};
  res.json({
    cascadeEnabled: !!cfg.cascadeEnabled,
    cascadeNaiveUpstream: cfg.cascadeNaiveUpstream || '',
    cascadeMieru: {
      host:      m.host || '',
      portStart: m.portStart || 2012,
      portEnd:   m.portEnd   || 2022,
      user:      m.user || '',
      // never return the stored exit password; UI shows a placeholder
      hasPass:   !!m.pass
    }
  });
});

// Live cascade status (calls cascade_mieru.sh status).
app.get('/api/settings/cascade/status', requireAuth, (req, res) => {
  const r = runCascadeMieru('status');
  res.json({ ok: r.ok, output: r.output });
});

app.post('/api/settings/cascade', requireAuth, (req, res) => {
  const { cascadeEnabled, cascadeNaiveUpstream, cascadeMieru } = req.body;
  const enabled = !!cascadeEnabled;
  cfg.cascadeEnabled = enabled;
  if (cascadeNaiveUpstream !== undefined) {
    cfg.cascadeNaiveUpstream = String(cascadeNaiveUpstream || '').trim();
  }

  // Merge Mieru exit settings. A blank password means "keep existing".
  const prev = cfg.cascadeMieru || {};
  if (cascadeMieru !== undefined) {
    const m = cascadeMieru || {};
    cfg.cascadeMieru = {
      host:      String(m.host ?? prev.host ?? '').trim(),
      portStart: parseInt(m.portStart ?? prev.portStart ?? 2012, 10) || 2012,
      portEnd:   parseInt(m.portEnd   ?? prev.portEnd   ?? 2022, 10) || 2022,
      user:      String(m.user ?? prev.user ?? '').trim(),
      pass:      (m.pass !== undefined && String(m.pass).length > 0)
                   ? String(m.pass)
                   : (prev.pass || '')
    };
  }
  saveConfig();

  try {
    // 1) Naive leg — rebuild Caddyfile (upstream applied when enabled).
    const content = buildCaddyfile(cfg, getAllUsers());
    writeCaddyfileAtomic(content);
    const validation = validateCaddyfile();
    if (!validation.ok) return res.status(500).json({ ok: false, error: validation.error });
    const caddy = reloadCaddy();
    if (!caddy.ok) return res.status(500).json({ ok: false, error: caddy.error });

    // 2) Mieru leg — Variant B orchestration.
    let cascadeOk = true, cascadeOut = '';
    const m = cfg.cascadeMieru || {};
    const hasMieruExit = enabled && m.host && m.user && m.pass;
    if (hasMieruExit) {
      const r = runCascadeMieru('setup', {
        host: m.host, portStart: m.portStart, portEnd: m.portEnd,
        user: m.user, pass: m.pass
      });
      cascadeOk = r.ok; cascadeOut = r.output;
    } else {
      // Cascade disabled (or no Mieru exit configured) → ensure relay is down.
      const r = runCascadeMieru('teardown');
      cascadeOk = r.ok; cascadeOut = r.output;
    }

    // Entry mita stays a plain server in Variant B — just re-apply its config.
    const mita = applyMitaConfigDetailed();
    if (mita.required && !mita.ok) return res.status(500).json({ ok: false, caddyOk: true, caddyAction: caddy.action, mitaOk: false, cascadeOk, cascadeOutput: cascadeOut, error: mita.error });

    res.json({
      ok: cascadeOk,
      caddyOk: true, caddyAction: caddy.action, mitaOk: mita.ok, mitaRequired: mita.required, mitaIdle: mita.idle, mitaError: mita.error || '', cascadeOk,
      cascadeOutput: cascadeOut,
      message: enabled
        ? (hasMieruExit
            ? 'Cascade enabled. Naive upstream + Mieru relay (Variant B) applied.'
            : 'Cascade enabled for Naive only (no Mieru exit configured).')
        : 'Cascade disabled. Relay torn down.'
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Client configs ────────────────────────────────────────────────────────────

// Naive link (used with caddy-forwardproxy)
app.get('/api/users/:id/config/naive', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.enabled === 0 || !getUserProtocols(user).includes('naive'))
    return res.status(404).json({ error: 'Naive protocol is not active for this user' });
  const password = req.query.password || user.password || 'YOUR_PASSWORD';
  // naive+https:// link for caddy-forwardproxy-naive
  const link = `naive+https://${user.username}:${encodeURIComponent(password)}@${cfg.domain}:${cfg.naivePort}`;
  res.json({ link, username: user.username });
});

// Bug 5: transport field (not protocol); Bug 12: server_ports array
// P3 (selectable mieru port): validate a requested port against the configured
//   range. mita listens on the WHOLE range (portRange "start-end"), so any port
//   inside [start,end] is valid for the client to dial. Returns `start` when the
//   request is absent, non-numeric, or outside the range.
function pickMieruPort(requested, start, end) {
  const p = parseInt(requested, 10);
  if (Number.isInteger(p) && p >= start && p <= end) return p;
  return start;
}

app.get('/api/users/:id/config/mieru', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.enabled === 0 || !getUserProtocols(user).includes('mieru'))
    return res.status(404).json({ error: 'Mieru protocol is not active for this user' });
  const password = req.query.password || user.password || 'YOUR_PASSWORD';

  // Build server_ports array (Bug 12)
  // Bug 70: mieruPortStart/End may be strings or undefined; parseInt prevents
  // an infinite for-loop when NaN comparisons silently return false
  const _portStart70a = parseInt(cfg.mieruPortStart, 10) || 2000;
  const _portEnd70a   = parseInt(cfg.mieruPortEnd,   10) || 2010;
  const serverPorts = [];
  for (let p = _portStart70a; p <= _portEnd70a; p++) {
    serverPorts.push(p);
  }
  // P3 (selectable port): allow the client to pick which port from the
  //   configured mieru range is written into server_port. Falls back to the
  //   range start when ?port= is absent or out of range.
  const mieruPort = pickMieruPort(req.query.port, _portStart70a, _portEnd70a);

  // Bug 74: align mieru outbound with the field-tested working client format
  // (Karing / sing-box mieru):
  //   - use `multiplexing: "MULTIPLEXING_HIGH"` (string enum), NOT
  //     `multiplex: { enabled: false }` (that object form is for other
  //     protocols' stream multiplexing and silently breaks the mieru parser);
  //   - use a single `server_port` (the working config does NOT send a
  //     `server_ports` array — sending both confuses the client);
  //   - prefer the raw server IP (mieru is IP-based, no SNI/TLS).
  const singboxCfg = {
    log: { level: 'info' },
    dns: {
      servers: [
        { tag: 'google', address: '8.8.8.8' },
        { tag: 'local',  address: '1.1.1.1', detour: 'direct' }
      ]
    },
    outbounds: [
      {
        type: 'mieru', tag: 'mieru-out',
        server: cfg.serverIp || cfg.domain,
        server_port: mieruPort,
        // Bug 5: transport field (TCP/UDP) — not protocol
        transport: 'TCP',
        username: user.username, password,
        // Bug 74: string enum, not an object
        multiplexing: 'MULTIPLEXING_HIGH'
      },
      { type: 'direct', tag: 'direct' }
    ],
    route: { final: 'mieru-out' }
  };
  // Keep the full port range available for clients/tooling that want it.
  void serverPorts;
  const filename = `mieru-${user.username}-${cfg.domain}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/json');
  res.json(singboxCfg);
});

app.get('/api/users/:id/config/universal', requireAuth, (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.enabled === 0) return res.status(403).json({ error: 'User is disabled' });
  const password = req.query.password || user.password || 'YOUR_PASSWORD';
  const protocols = getUserProtocols(user);
  const hasNaive = protocols.includes('naive');
  const hasMieru = protocols.includes('mieru');
  if (!hasNaive && !hasMieru) return res.status(404).json({ error: 'No active protocol for this user' });

  // Bug 70: parseInt guard prevents an infinite loop when values are strings/NaN
  const _portStart70b = parseInt(cfg.mieruPortStart, 10) || 2000;
  const _portEnd70b   = parseInt(cfg.mieruPortEnd,   10) || 2010;
  // P3 (selectable port): honour ?port= within the configured range.
  const mieruPortU = pickMieruPort(req.query.port, _portStart70b, _portEnd70b);

  const outbounds = [];
  const routeFinal = hasNaive && hasMieru ? 'select' : (hasNaive ? 'node-naive' : 'mieru-out');
  if (hasNaive && hasMieru) {
    outbounds.push({
      type: 'urltest', tag: 'select',
      outbounds: ['node-naive', 'mieru-out'],
      url: 'https://www.gstatic.com/generate_204',
      interval: '3m', tolerance: 50
    });
  }
  if (hasNaive) {
    outbounds.push({
      type: 'naive', tag: 'node-naive',
      server: cfg.domain, server_port: cfg.naivePort,
      username: user.username, password,
      quic: false,
      tls: { enabled: true, server_name: cfg.domain }
    });
  }
  if (hasMieru) {
    outbounds.push({
      type: 'mieru', tag: 'mieru-out',
      server: cfg.serverIp || cfg.domain,
      server_port: mieruPortU,
      transport: 'TCP',
      username: user.username, password,
      multiplexing: 'MULTIPLEXING_HIGH'
    });
  }
  outbounds.push({ type: 'direct', tag: 'direct' }, { type: 'dns', tag: 'dns-out' });

  const universalCfg = {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { tag: 'remote', address: 'tls://8.8.8.8',               detour: 'select' },
        { tag: 'local',  address: 'https://223.5.5.5/dns-query',  detour: 'direct' }
      ],
      rules:  [{ outbound: 'any', server: 'local' }],
      final:  'remote'
    },
    outbounds,
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { geoip: 'cn',     outbound: 'direct'  },
        { geosite: 'cn',   outbound: 'direct'  }
      ],
      final: routeFinal,
      auto_detect_interface: true
    }
  };
  const filename = `universal-${user.username}-${cfg.domain}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/json');
  res.json(universalCfg);
});

// Back-compat aliases
app.get('/api/users/:id/naive-link', requireAuth, (req, res) => {
  res.redirect(307, `/api/users/${req.params.id}/config/naive${req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''}`);
});
app.get('/api/users/:id/mieru-config', requireAuth, (req, res) => {
  res.redirect(307, `/api/users/${req.params.id}/config/mieru${req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''}`);
});
app.get('/api/users/:id/universal-config', requireAuth, (req, res) => {
  res.redirect(307, `/api/users/${req.params.id}/config/universal${req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''}`);
});

const internalRouter = express.Router();
internalRouter.use(apiLimiter, requireInternalAuth);

function internalOk(res, payload = {}) { res.json({ ok: true, ...payload }); }
function internalUserPayload(user) {
  const summary = getSessionSummary(user.id, user.username);
  const safe = apiUserWithTraffic(user);
  return {
    ...safe,
    activeIpCount: summary.uniqueActiveIps,
    uniqueIpCount24h: summary.uniqueIpCount24h,
    lastSeen: summary.lastSeen || safe.lastSeen || user.lastSeen
  };
}
function buildNaiveConfig(user) {
  return {
    protocol: 'naive',
    domain: cfg.domain,
    port: cfg.naivePort || 443,
    username: user.username,
    password: user.password || '',
    enabled: !(user.enabled === 0 || user.enabled === false),
    outbound: {
      type: 'naive',
      tag: 'node-naive',
      server: cfg.domain,
      server_port: cfg.naivePort || 443,
      username: user.username,
      password: user.password || '',
      quic: false,
      tls: { enabled: true, server_name: cfg.domain }
    }
  };
}
function buildMieruOutbound(user, requestedPort) {
  const start = parseInt(cfg.mieruPortStart, 10) || 2000;
  const end = parseInt(cfg.mieruPortEnd, 10) || 2010;
  return {
    type: 'mieru',
    tag: 'mieru-out',
    server: cfg.serverIp || cfg.domain,
    server_port: pickMieruPort(requestedPort, start, end),
    transport: 'TCP',
    username: user.username,
    password: user.password || '',
    multiplexing: 'MULTIPLEXING_HIGH'
  };
}
function buildUniversalConfig(user, requestedPort) {
  const protocols = getUserProtocols(user);
  const hasNaive = protocols.includes('naive');
  const hasMieru = protocols.includes('mieru');
  const final = hasNaive && hasMieru ? 'select' : (hasNaive ? 'node-naive' : 'mieru-out');
  const outbounds = [];
  if (hasNaive && hasMieru) {
    outbounds.push({
      type: 'urltest', tag: 'select',
      outbounds: ['node-naive', 'mieru-out'],
      url: 'https://www.gstatic.com/generate_204',
      interval: '3m', tolerance: 50
    });
  }
  if (hasNaive) outbounds.push(buildNaiveConfig(user).outbound);
  if (hasMieru) outbounds.push(buildMieruOutbound(user, requestedPort));
  outbounds.push({ type: 'direct', tag: 'direct' }, { type: 'dns', tag: 'dns-out' });
  return {
    log: { level: 'info', timestamp: true },
    dns: {
      servers: [
        { tag: 'remote', address: 'tls://8.8.8.8', detour: final },
        { tag: 'local', address: 'https://223.5.5.5/dns-query', detour: 'direct' }
      ],
      rules: [{ outbound: 'any', server: 'local' }],
      final: 'remote'
    },
    outbounds,
    route: {
      rules: [
        { protocol: 'dns', outbound: 'dns-out' },
        { geoip: 'cn', outbound: 'direct' },
        { geosite: 'cn', outbound: 'direct' }
      ],
      final,
      auto_detect_interface: true
    }
  };
}

function userIsExpired(user) {
  return !!(user && user.expiry && new Date(user.expiry).getTime() <= Date.now());
}

function assertSubscriptionUserUsable(user) {
  if (!user) return { status: 404, error: 'Subscription not found' };
  if (user.enabled === 0 || user.enabled === false) return { status: 403, error: 'User is disabled' };
  if (userIsExpired(user)) return { status: 403, error: 'User subscription is expired' };
  return null;
}

function setUserEnabled(req, res, enabled) {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const updated = { ...user, enabled: enabled ? 1 : 0, updatedAt: new Date().toISOString() };
  upsertUser(updated);
  const status = applyAllConfigs();
  try { assertCaddyApplied(status); }
  catch (e) {
    upsertUser(user);
    applyAllConfigs();
    return res.status(e.status || 500).json({ ok: false, error: e.message, ...status });
  }
  internalOk(res, { user: internalUserPayload(updated), ...status });
}

internalRouter.get('/health', (_req, res) => internalOk(res));
internalRouter.get('/version', (_req, res) => internalOk(res, nodeAgentVersionPayload()));
internalRouter.get('/settings', (_req, res) => internalOk(res, { settings: safeNodeSettings() }));
internalRouter.patch('/settings', (req, res) => {
  const result = applyNodeSettingsPatch(req.body);
  if (result.error) return res.status(400).json({ ok: false, error: result.error });
  internalOk(res, { settings: result.settings });
});
internalRouter.get('/node/info', (_req, res) => internalOk(res, {
  node: {
    domain: cfg.domain,
    serverIp: cfg.serverIp,
    naivePort: cfg.naivePort || 443,
    mieruPortStart: cfg.mieruPortStart,
    mieruPortEnd: cfg.mieruPortEnd,
    sessionTtlMinutes: cfg.sessionTtlMinutes,
    trafficAuditLogPath: cfg.trafficAuditLogPath || LOG_TRAFFIC_AUDIT,
    ipHistoryTtlHours: parseInt(cfg.ipHistoryTtlHours, 10) || 24,
    maxUniqueIpsPerUser: cfg.maxUniqueIpsPerUser,
    enforceIpLimit: !!cfg.enforceIpLimit,
    subscriptionBaseUrl: cfg.subscriptionBaseUrl || subscriptionBaseUrl()
  }
}));
internalRouter.get('/node/sessions', (_req, res) => internalOk(res, nodeSessionsPayload()));
internalRouter.get('/sessions/explorer', (_req, res) => internalOk(res, publicExplorerSnapshot()));
internalRouter.get('/logs/status', (_req, res) => internalOk(res, getNodeExplorerSnapshot().logs));
internalRouter.get('/ip/:ip', (req, res) => {
  const ip = normalizeAuditIp(req.params.ip);
  if (!ip) return res.status(400).json({ ok: false, error: 'ip is required' });
  internalOk(res, ipExplorerDetails(ip));
});
internalRouter.get('/users', (_req, res) => internalOk(res, { users: getAllUsers().map(internalUserPayload) }));
internalRouter.get('/users/sessions', (_req, res) => {
  const payload = parseAuthAuditSessions();
  internalOk(res, {
    trackingAvailable: payload.trackingAvailable,
    reason: payload.reason,
    ttlMinutes: payload.ttlMinutes,
    ttlHours: payload.ttlHours,
    uniqueActiveIps: payload.uniqueActiveIps,
    uniqueIpCount24h: payload.uniqueIpCount24h,
    users: (payload.users || []).map(u => ({
      username: u.username,
      uniqueActiveIps: u.uniqueActiveIps,
      activeIpCount: u.activeIpCount,
      uniqueIpCount24h: u.uniqueIpCount24h,
      sessions: formatSessionsForApi(u.sessions),
      ips: formatIpHistoryForApi(u.ips || [])
    }))
  });
});
internalRouter.get('/users/:id/details', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  internalOk(res, userExplorerDetails(user));
});
internalRouter.get('/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  internalOk(res, { user: internalUserPayload(user) });
});
internalRouter.post('/users', (req, res) => {
  const body = req.body || {};
  const expiry = body.expiresAt ?? body.expiry;
  const validation = validateUserInput(body, true);
  if (validation.error) return res.status(400).json({ ok: false, error: validation.error });
  if (getUserByUsername(body.username)) return res.status(409).json({ ok: false, error: 'Username already exists' });
  if (expiry && isNaN(Date.parse(expiry))) return res.status(400).json({ ok: false, error: 'expiresAt must be a valid ISO date string' });
  const now = new Date().toISOString();
  const user = {
    id: uuidv4(),
    email: (body.email && body.email.trim()) ? body.email.trim() : null,
    username: body.username,
    passHash: bcrypt.hashSync(body.password, 12),
    password: body.password,
    expiry: expiry || null,
    protocols: JSON.stringify(validation.protocols),
    quotaMB: validation.quotaMB,
    usedMB: 0,
    enabled: validation.enabled === undefined ? 1 : (validation.enabled ? 1 : 0),
    suspicious: 0,
    subscriptionToken: generateSubscriptionToken(),
    createdAt: now,
    updatedAt: now,
    lastSeen: null
  };
  upsertUser(user);
  const status = applyAllConfigs();
  try { assertCaddyApplied(status); }
  catch (e) {
    deleteUser(user.id);
    applyAllConfigs();
    return res.status(e.status || 500).json({ ok: false, error: e.message, ...status });
  }
  res.status(201).json({ ok: true, user: internalUserPayload(user), ...status });
});
internalRouter.patch('/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const body = req.body || {};
  const expiry = body.expiresAt ?? body.expiry;
  const validation = validateUserInput({
    email: body.email ?? user.email,
    username: body.username ?? user.username,
    password: body.password,
    protocols: body.protocols,
    quotaGb: body.quotaGb,
    quotaMB: body.quotaMB,
    enabled: body.enabled
  }, false);
  if (validation.error) return res.status(400).json({ ok: false, error: validation.error });
  if (expiry !== undefined && expiry !== null && isNaN(Date.parse(expiry)))
    return res.status(400).json({ ok: false, error: 'expiresAt must be a valid ISO date string' });
  const updated = {
    ...user,
    email: body.email !== undefined ? ((body.email && body.email.trim()) ? body.email.trim() : null) : user.email,
    username: body.username ?? user.username,
    expiry: expiry !== undefined ? (expiry || null) : user.expiry,
    protocols: body.protocols ? JSON.stringify(validation.protocols) : user.protocols,
    quotaMB: (body.quotaMB !== undefined || body.quotaGb !== undefined) ? validation.quotaMB : user.quotaMB,
    enabled: validation.enabled === undefined ? user.enabled : (validation.enabled ? 1 : 0),
    updatedAt: new Date().toISOString()
  };
  if (body.password) {
    updated.passHash = bcrypt.hashSync(body.password, 12);
    updated.password = body.password;
  }
  upsertUser(updated);
  const status = applyAllConfigs();
  try { assertCaddyApplied(status); }
  catch (e) {
    upsertUser(user);
    applyAllConfigs();
    return res.status(e.status || 500).json({ ok: false, error: e.message, ...status });
  }
  internalOk(res, { user: internalUserPayload(updated), ...status });
});
internalRouter.delete('/users/:id', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  deleteUser(req.params.id);
  resetUserSessions(user.id, user.username);
  const status = applyAllConfigs();
  try { assertCaddyApplied(status); }
  catch (e) {
    upsertUser(user);
    applyAllConfigs();
    return res.status(e.status || 500).json({ ok: false, error: e.message, ...status });
  }
  internalOk(res, status);
});
internalRouter.post('/users/:id/enable', (req, res) => setUserEnabled(req, res, true));
internalRouter.post('/users/:id/disable', (req, res) => setUserEnabled(req, res, false));
internalRouter.get('/users/:id/config/naive', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  if (user.enabled === 0 || !getUserProtocols(user).includes('naive')) return res.status(404).json({ ok: false, error: 'Naive protocol is not active for this user' });
  internalOk(res, { config: buildNaiveConfig(user) });
});
internalRouter.get('/users/:id/config/mieru', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  if (user.enabled === 0 || !getUserProtocols(user).includes('mieru')) return res.status(404).json({ ok: false, error: 'Mieru protocol is not active for this user' });
  internalOk(res, { config: buildMieruOutbound(user, req.query.port) });
});
internalRouter.get('/users/:id/config/universal', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  if (user.enabled === 0) return res.status(403).json({ ok: false, error: 'User is disabled' });
  internalOk(res, { config: buildUniversalConfig(user, req.query.port) });
});
internalRouter.get('/users/:id/sessions', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const payload = getUserSessions(user.id, user.username);
  internalOk(res, {
    trackingAvailable: payload.trackingAvailable,
    reason: payload.reason,
    ttlMinutes: payload.ttlMinutes,
    ttlHours: payload.ttlHours,
    uniqueActiveIps: payload.uniqueActiveIps,
    uniqueIpCount24h: payload.uniqueIpCount24h,
    sessions: formatSessionsForApi(payload.sessions)
  });
});
internalRouter.get('/users/:id/ip-history', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const payload = getUserIpHistory(user.id, user.username);
  internalOk(res, {
    trackingAvailable: payload.trackingAvailable,
    reason: payload.reason,
    username: user.username,
    ttlMinutes: payload.ttlMinutes,
    ttlHours: payload.ttlHours,
    activeIpCount: payload.activeIpCount,
    uniqueActiveIps: payload.uniqueActiveIps,
    uniqueIpCount24h: payload.uniqueIpCount24h,
    ips: formatIpHistoryForApi(payload.ips || [])
  });
});
internalRouter.post('/users/:id/reset-sessions', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  resetUserSessions(user.id, user.username);
  internalOk(res);
});
internalRouter.post('/users/:id/rotate-subscription-token', (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const updated = { ...user, subscriptionToken: generateSubscriptionToken(), updatedAt: new Date().toISOString() };
  upsertUser(updated);
  internalOk(res, { user: internalUserPayload(updated) });
});

app.use('/internal', internalRouter);

app.get('/sub/:token', (req, res) => {
  const user = getUserBySubscriptionToken(req.params.token);
  const blocked = assertSubscriptionUserUsable(user);
  if (blocked) return res.status(blocked.status).json({ ok: false, error: blocked.error });
  res.setHeader('Content-Type', 'application/json');
  res.json(buildUniversalConfig(user, req.query.port));
});

// ── Monitoring — /api/status ──────────────────────────────────────────────────
app.get('/api/status', requireAuth, async (req, res) => {
  try {
    const [cpu, mem, disk, osInfo] = await Promise.all([
      si.currentLoad(), si.mem(), si.fsSize(), si.osInfo()
    ]);
    const exec_ = cmd => { try { return execSync(cmd, { timeout: 3000 }).toString().trim(); } catch { return ''; } };

    // v1.2.3: check caddy-naive service (not legacy naive)
    const caddyActive  = exec_('systemctl is-active caddy-naive') === 'active';
    const caddyVersion = exec_(`${resolvedCaddyBin} version 2>/dev/null | head -1`) ||
                         exec_(`${resolvedCaddyBin} --version 2>/dev/null | head -1`);
    const sessionStats = dashboardSessionStats();

    res.json({
      services: {
        naive: {   // kept as 'naive' key for front-end compatibility
          active:  caddyActive,
          version: caddyVersion
        },
        mieru: {
          active:  exec_('systemctl is-active mita') === 'active',
          version: exec_('mita version 2>/dev/null | head -1')
        },
        panel: { active: true }
      },
      system: {
        cpuPercent:  Math.round(cpu.currentLoad),
        ramUsedMB:   Math.round((mem.total - mem.available) / 1048576),
        ramTotalMB:  Math.round(mem.total / 1048576),
        diskUsedGB:  disk.length ? Math.round(disk[0].used / 1073741824) : 0,
        diskTotalGB: disk.length ? Math.round(disk[0].size / 1073741824) : 0,
        uptime: Math.floor(process.uptime()),
        os:   osInfo.distro + ' ' + osInfo.release,
        arch: osInfo.arch
      },
      panel:    {
        userCount: getAllUsers().length,
        activeUsers: sessionStats.activeUsers,
        activeIps: sessionStats.activeIps,
        ipLimitExceededUsers: sessionStats.ipLimitExceededUsers,
        version: cfg.version || '1.2.5'
      },
      domain:   cfg.domain,
      serverIp: cfg.serverIp,
      language: cfg.language || 'ru'
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// User traffic stats
app.get('/api/stats/users', requireAuth, (req, res) => {
  const exec_ = cmd => { try { return execSync(cmd, { timeout: 8000 }).toString(); } catch { return ''; } };
  // Bug 78: the real mieru server command is `mita get users` (NOT the
  //   non-existent `mita describe users`, which always returned '' → traffic 0).
  //   Output is a table: User  LastActive  1DayDownload  1DayUpload  30DaysDownload  30DaysUpload
  const raw   = exec_('mita get users 2>/dev/null');
  const live  = parseMitaUsers(raw);
  const users = getAllUsers().map(u => {
    const s = live.find(x => x.username === u.username) || {};
    return attachTrafficToUserPayload({
      username:   u.username,
      email:      u.email,
      expiry:     u.expiry,
      protocols:  JSON.parse(u.protocols || '[]'),
      quotaMB:    u.quotaMB,
      usedMB:     u.usedMB || 0,
      // Prefer the live LastActive reported by mita; fall back to stored value.
      lastSeen:   s.lastSeen || u.lastSeen
    }, { mieruTraffic: s });
  });
  res.json(users);
});

// Bug 78: parse the `mita get users` table.
//   User  LastActive            1DayDownload  1DayUpload  30DaysDownload  30DaysUpload
//   abcd  2025-04-23T01:02:03Z  938.1MiB      12.9MiB     4.0GiB          31.8MiB
//   "used" = 30-day download + 30-day upload (best per-key cumulative metric mita exposes).
//   Sizes use binary IEC units (B / KiB / MiB / GiB / TiB) and may also appear as KB/MB/GB.
function parseMitaUsers(raw) {
  const users = [];
  if (!raw) return users;
  const sizeRe = /^([\d.]+)\s*([KMGT]?i?B)$/i;
  for (const rawLine of raw.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    // skip header / separator rows
    if (/^user\b/i.test(line) || /^[-=\s]+$/.test(line)) continue;
    const cols = line.split(/\s+/);
    if (cols.length < 6) continue;
    const username = cols[0];
    const lastActive = cols[1];
    // last 4 columns are the size figures
    const sizeCols = cols.slice(-4);
    const vals = sizeCols.map(c => {
      const m = c.match(sizeRe);
      return m ? toMB(parseFloat(m[1]), m[2]) : null;
    });
    if (vals.some(v => v === null)) continue; // not a data row
    const [d1, u1, d30, u30] = vals;
    void d1; void u1;
    const downloadMB = d30;
    const uploadMB   = u30;
    users.push({
      username,
      uploadMB,
      downloadMB,
      usedMB:   uploadMB + downloadMB,
      lastSeen: /^\d{4}-\d{2}-\d{2}T/.test(lastActive) ? lastActive : null
    });
  }
  return users;
}
// Convert a size value to MB. Accepts both IEC (KiB/MiB/GiB/TiB) and
//   decimal-ish (KB/MB/GB/TB) unit spellings; bare "B" → bytes.
function toMB(v, unit) {
  switch ((unit || '').toUpperCase()) {
    case 'B':                return v / 1048576;
    case 'KB': case 'KIB':   return v / 1024;
    case 'GB': case 'GIB':   return v * 1024;
    case 'TB': case 'TIB':   return v * 1048576;
    default:                 return v; // MB / MiB
  }
}

// ── Logs API ──────────────────────────────────────────────────────────────────
app.get('/api/logs/:service', requireAuth, (req, res) => {
  const { service } = req.params;
  const lines = Math.min(parseInt(req.query.lines || '100', 10), 1000);
  let cmd;
  switch (service) {
    // v1.2.3: caddy-naive logs (supports legacy 'naive' and 'caddy' aliases)
    case 'naive':
    case 'caddy':
      cmd = `journalctl -u caddy-naive -n ${lines} --no-pager 2>/dev/null || tail -n ${lines} ${LOG_CADDY} 2>/dev/null`;
      break;
    case 'mieru': cmd = `journalctl -u mita -n ${lines} --no-pager 2>/dev/null || mita describe log 2>/dev/null`; break;
    case 'panel': cmd = `tail -n ${lines} ${LOG_PANEL} 2>/dev/null`; break;
    default: return res.status(400).json({ error: 'Unknown service' });
  }
  try { res.json({ logs: execSync(cmd, { timeout: 6000 }).toString() }); }
  catch { res.json({ logs: '(no logs available)' }); }
});

// ── Diagnostics ───────────────────────────────────────────────────────────────
app.get('/api/diagnostics', requireAuth, async (_req, res) => {
  const exec_ = cmd => { try { return execSync(cmd, { timeout: 4000 }).toString().trim(); } catch { return ''; } };

  const chkPort = p => {
    try {
      return parseInt(
        execSync(`ss -tlnup sport = :${p} 2>/dev/null | grep -c :${p}`, { timeout: 3000 }).toString().trim(),
        10) > 0;
    } catch { return false; }
  };

  // v1.2.3: caddy-naive version check (replaces naive --version)
  let caddyVersionOk = false, caddyVersionStr = '';
  try {
    caddyVersionStr = execSync(`${resolvedCaddyBin} version 2>&1`, { timeout: 6000 }).toString().trim() ||
                     execSync(`${resolvedCaddyBin} --version 2>&1`, { timeout: 6000 }).toString().trim();
    caddyVersionOk  = caddyVersionStr.length > 0;
  } catch (e) { caddyVersionStr = e.message; }

  const mieruPortsListening = [];
  for (const p of [cfg.mieruPortStart, cfg.mieruPortEnd]) {
    if (p && chkPort(p)) mieruPortsListening.push(p);
  }
  const trafficDiag = getNaiveTrafficStats().diagnostics || emptyTrafficAuditDiagnostics(trafficAuditLogPath(), false);
  const authDiag = buildAuthAuditHistoryPayload().diagnostics || emptyAuthAuditDiagnostics(authAuditLogPath(), false, 0);

  res.json({
    ports: {
      naive:       chkPort(cfg.naivePort),
      mieru:       chkPort(cfg.mieruPortStart),
      mieruPorts:  mieruPortsListening
    },
    naiveVersionOk:    caddyVersionOk,
    naiveVersion:      caddyVersionStr,    // kept as 'naiveVersion' for front-end compat
    naiveConfigExists: fs.existsSync(resolvedCaddyFile),
    htpasswdExists:    false,              // htpasswd removed in v1.2.3 (users in Caddyfile)
    htpasswdUsers:     0,
    caddyfileExists:   fs.existsSync(resolvedCaddyFile),
    caddyfileUsers:    (() => {
      if (!fs.existsSync(resolvedCaddyFile)) return 0;
      const content = fs.readFileSync(resolvedCaddyFile, 'utf8');
      // Bug 23: directive is now "basic_auth" (underscore), not "basicauth"
      return (content.match(/^\s*basic_auth\s+\S+\s+\S+/gm) || []).length;
    })(),
    mitaStatus:   exec_('mita status 2>/dev/null'),
    mitaConfig:   exec_('mita describe config 2>/dev/null'),
    timeSynced:   exec_('timedatectl status 2>/dev/null').includes('synchronized: yes'),
    mitaStateFile: resolvedMitaFile,
    trafficAuditLogAvailable: trafficDiag.trafficAuditLogAvailable,
    trafficAuditLogPath: trafficDiag.trafficAuditLogPath,
    trafficAuditLogLastReadAt: trafficDiag.trafficAuditLogLastReadAt,
    trafficAuditLogRecords: trafficDiag.trafficAuditLogRecords,
    ipHistoryTtlHours: parseInt(cfg.ipHistoryTtlHours, 10) || 24,
    authAuditLogAvailable: authDiag.authAuditLogAvailable,
    authAuditLogPath: authDiag.authAuditLogPath,
    authAuditLogRecords: authDiag.authAuditLogRecords,
    probeSecretSet: !!(cfg.probeSecret),
    probeMode: (cfg.probeMode || (cfg.probeSecret ? 'secret' : 'bare'))
  });
});

// ── Service control ───────────────────────────────────────────────────────────
app.post('/api/service/:name/:action', requireAuth, (req, res) => {
  const { name, action } = req.params;
  // Map legacy 'naive' name to 'caddy-naive'; keep 'mita' as-is
  const svcMap = { 'naive': 'caddy-naive', 'caddy-naive': 'caddy-naive', 'mita': 'mita' };
  const svcName = svcMap[name];
  if (!svcName)
    return res.status(400).json({ error: 'Unknown service (valid: naive/caddy-naive, mita)' });
  if (!['start','stop','restart','reload'].includes(action))
    return res.status(400).json({ error: 'Unknown action' });
  try {
    execSync(`systemctl ${action} ${svcName} 2>&1`, { timeout: 15000 });
    res.json({ ok: true, service: svcName, action });
  } catch (e) { res.status(500).json({ error: e.stdout?.toString() || e.message }); }
});

// ── WebSocket — real-time metrics ─────────────────────────────────────────────
const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', ws => {
  const exec_ = cmd => { try { return execSync(cmd, { timeout: 2000 }).toString().trim(); } catch { return ''; } };
  let iv;
  const push = async () => {
    if (ws.readyState !== ws.OPEN) { clearInterval(iv); return; }
    try {
      const [cpu, mem] = await Promise.all([si.currentLoad(), si.mem()]);
      ws.send(JSON.stringify({
        type:       'metrics',
        ts:         Date.now(),
        cpu:        Math.round(cpu.currentLoad),
        ramUsedMB:  Math.round((mem.total - mem.available) / 1048576),
        ramTotalMB: Math.round(mem.total / 1048576),
        // v1.2.3: check caddy-naive service
        naive:      exec_('systemctl is-active caddy-naive') === 'active',
        mieru:      exec_('systemctl is-active mita')        === 'active'
      }));
    } catch {}
  };
  iv = setInterval(push, 5000);
  push();
  ws.on('message', d => { try { const m = JSON.parse(d); if (m.type==='ping') ws.send(JSON.stringify({type:'pong'})); } catch {} });
  ws.on('close',  () => clearInterval(iv));
  ws.on('error',  () => clearInterval(iv));
});

// ── Expiry cron — every 5 min ─────────────────────────────────────────────────
cron.schedule('*/5 * * * *', () => {
  const now = new Date().toISOString();
  let changed = false;
  getAllUsers().forEach(u => {
    if (u.expiry && u.expiry < now) {
      console.log('[CRON] Removing expired user:', u.username);
      deleteUser(u.id); changed = true;
    }
  });
  if (changed) {
    try {
      const content = buildCaddyfile(cfg, getAllUsers());
      writeCaddyfileAtomic(content);
      reloadCaddy();
    } catch {}
    try { applyMitaConfig(); } catch {}
  }
});

// ── Traffic snapshot cron — every 60 s ───────────────────────────────────────
cron.schedule('* * * * *', () => {
  if (!db) return;
  try {
    // Bug 78: use `mita get users` (the real command); `mita describe users`
    //   does not exist and always produced empty output.
    const raw  = execSync('mita get users 2>/dev/null', { timeout: 5000 }).toString();
    const live = parseMitaUsers(raw);
    if (!live.length) return;
    const ts   = new Date().toISOString();
    const ins  = db.prepare('INSERT INTO traffic_snapshots (username,uploadMB,downloadMB,ts) VALUES (?,?,?,?)');
    live.forEach(s => ins.run(s.username, s.uploadMB, s.downloadMB, ts));
    live.forEach(s => {
      const u = getUserByUsername(s.username);
      if (u) upsertUser({ ...u, usedMB: s.usedMB, lastSeen: s.lastSeen || ts, updatedAt: ts });
    });
  } catch {}
});

// ── SPA catch-all ─────────────────────────────────────────────────────────────
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

// ── Start ─────────────────────────────────────────────────────────────────────
const HOST = process.env.PANEL_HOST || cfg.panelHost || '127.0.0.1';
const PORT = parseInt(process.env.PANEL_PORT || String(cfg.panelPort || 3000), 10);

server.listen(PORT, HOST, () => {
  const lines = [
    '',
    '  ██████╗  ██╗ ██╗  ██╗ ██╗  ██╗ ██╗  ██╗',
    '  ██╔══██╗ ██║ ╚██╗██╔╝ ╚██╗██╔╝ ╚██╗██╔╝',
    '  ██████╔╝ ██║  ╚███╔╝   ╚███╔╝   ╚███╔╝ ',
    '  ██╔══██╗ ██║  ██╔██╗   ██╔██╗   ██╔██╗ ',
    '  ██║  ██║ ██║ ██╔╝ ██╗ ██╔╝ ██╗ ██╔╝ ██╗',
    '  ╚═╝  ╚═╝ ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝  ╚═╝',
    '',
    `  Panel Naive + Mieru v${cfg.version || '1.2.5'} by RIXXX  (Caddy-forwardproxy-naive)`,
    `  http://${HOST}:${PORT}/`,
    HOST === '127.0.0.1' ? `  ⚠  SSH-only: ssh -L 3000:127.0.0.1:3000 root@<server>` : '',
    ''
  ];
  lines.forEach(l => console.log(l));
});

module.exports = app;
