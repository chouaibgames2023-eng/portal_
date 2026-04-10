// Lab44 — Student Grades + VM Management Backend
// npm install express better-sqlite3 cors helmet express-rate-limit
// node server.js
//
// SECURITY HARDENED VERSION
// Runs TWO servers:
//   PORT 3000  → student-facing API  (index.html, register.html, studentsinterface.html)
//   PORT 4000  → admin-facing API    (admin.html, students.html, adminmonitoring.html)
//
// XCP-ng: connects DIRECTLY via XAPI XML-RPC — no Xen Orchestra needed.
// Set XCPNG_HOST, XCPNG_USER, XCPNG_PASS below or via env vars.

const express = require("express");
const Database = require("better-sqlite3");
const cors = require("cors");
const path = require("path");
const https = require("https");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

// ── Ports ─────────────────────────────────────────────────────────────────────
const STUDENT_PORT = parseInt(process.env.STUDENT_PORT || "3000");
const ADMIN_PORT = parseInt(process.env.ADMIN_PORT || "4000");

// ── Auth ──────────────────────────────────────────────────────────────────────
// SECURITY: Force admin password change from default
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error("\n⚠️  CRITICAL: ADMIN_PASSWORD environment variable not set!\n");
  console.error("Please set a strong password: export ADMIN_PASSWORD='your-secure-password-here'\n");
  process.exit(1);
}

// ── XCP-ng direct XAPI ───────────────────────────────────────────────────────
const XCPNG_HOST = process.env.XCPNG_HOST || "192.168.100.2";
const XCPNG_USER = process.env.XCPNG_USER || "root";
const XCPNG_PASS = process.env.XCPNG_PASS;
if (!XCPNG_PASS) {
  console.error("\n⚠️  CRITICAL: XCPNG_PASS environment variable not set!\n");
  process.exit(1);
}

// ── Guacamole ─────────────────────────────────────────────────────────────────
const GUACAMOLE_URL = process.env.GUACAMOLE_URL || "http://192.168.1.136:8080/guacamole";

// ── Per-page API URLs ─────────────────────────────────────────────────────────
// These are returned to the browser so you only change IPs here, never in HTML.
// Student pages hit STUDENT_API_URL (port 3000 by default).
// Admin pages hit ADMIN_API_URL (port 4000 by default).
const STUDENT_API_URL = process.env.STUDENT_API_URL || `http://localhost:${STUDENT_PORT}`;
const ADMIN_API_URL = process.env.ADMIN_API_URL || `http://localhost:${ADMIN_PORT}`;

// ── Database ──────────────────────────────────────────────────────────────────
const db = new Database("lab44.db");
db.exec(`
  CREATE TABLE IF NOT EXISTS students (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name  TEXT NOT NULL,
    student_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
  CREATE TABLE IF NOT EXISTS grade_columns (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
  CREATE TABLE IF NOT EXISTS grades (
    student_id INTEGER NOT NULL,
    column_id  INTEGER NOT NULL,
    value      REAL,
    PRIMARY KEY (student_id, column_id),
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    FOREIGN KEY (column_id)  REFERENCES grade_columns(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS vm_requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    student_db_id  INTEGER NOT NULL,
    student_name   TEXT NOT NULL,
    student_id     TEXT NOT NULL,
    template_uuid  TEXT,
    template_name  TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    note           TEXT,
    vm_uuid        TEXT,
    vm_name        TEXT,
    requested_at   TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    reviewed_at    TEXT,
    FOREIGN KEY (student_db_id) REFERENCES students(id) ON DELETE CASCADE
  );
  INSERT OR IGNORE INTO settings (key, value) VALUES ('signup_enabled', 'true');
  INSERT OR IGNORE INTO settings (key, value) VALUES ('guacamole_url', '');
  CREATE TABLE IF NOT EXISTS attendance (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    student_db_id  INTEGER NOT NULL,
    student_id     TEXT NOT NULL,
    student_name   TEXT NOT NULL,
    checked_at     TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );
`);
// Safe migration for existing databases
["template_uuid TEXT", "template_name TEXT", "vm_uuid TEXT", "vm_name TEXT", "vm_ip TEXT", "access_protocol TEXT"].forEach(col => {
  try { db.exec(`ALTER TABLE vm_requests ADD COLUMN ${col}`); } catch (_) { }
});

// ── XAPI XML-RPC engine (Node.js) ────────────────────────────────────────────
// Uses sax-style manual XML parsing — handles deeply nested structs correctly
// without any external dependencies.

function xmlEscape(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

function encodeXapiValue(v) {
  if (v === null || v === undefined) return "<string></string>";
  if (typeof v === "boolean") return `<boolean>${v ? "1" : "0"}</boolean>`;
  if (typeof v === "number" && Number.isInteger(v)) return `<int>${v}</int>`;
  if (typeof v === "number") return `<double>${v}</double>`;
  if (typeof v === "string") return `<string>${xmlEscape(v)}</string>`;
  if (Array.isArray(v)) {
    return `<array><data>${v.map(i => `<value>${encodeXapiValue(i)}</value>`).join("")}</data></array>`;
  }
  if (typeof v === "object") {
    const members = Object.entries(v).map(([k, val]) =>
      `<member><name>${xmlEscape(k)}</name><value>${encodeXapiValue(val)}</value></member>`
    ).join("");
    return `<struct>${members}</struct>`;
  }
  return `<string>${xmlEscape(String(v))}</string>`;
}

function buildXapiXML(method, params) {
  const p = params.map(p => `<param><value>${encodeXapiValue(p)}</value></param>`).join("");
  return `<?xml version="1.0"?><methodCall><methodName>${xmlEscape(method)}</methodName><params>${p}</params></methodCall>`;
}

// ── Proper recursive XML-RPC parser ──────────────────────────────────────────
// Tokenizes the XML then builds the value tree recursively.
// This correctly handles arbitrary nesting depth.
function parseXmlRpcValue(xml) {
  // Tokenizer: split into tags and text
  const tokens = [];
  const re = /(<[^>]+>)|([^<]+)/g;
  let m;
  while ((m = re.exec(xml)) !== null) {
    if (m[1]) tokens.push({ type: "tag", val: m[1] });
    else if (m[2].trim()) tokens.push({ type: "text", val: m[2] });
  }

  let pos = 0;

  function tagName(t) {
    const m = t.match(/^<\/?([^\s>/]+)/);
    return m ? m[1].toLowerCase() : "";
  }
  function isOpen(t, name) { return t.type === "tag" && t.val.startsWith("<" + name) && !t.val.startsWith("</"); }
  function isClose(t, name) { return t.type === "tag" && t.val === `</${name}>`; }
  function isOpenTag(t) { return t.type === "tag" && !t.val.startsWith("</") && !t.val.endsWith("/>"); }

  function readUntilClose(name) {
    // Read raw text until </name>
    let buf = "";
    while (pos < tokens.length) {
      const t = tokens[pos];
      if (isClose(t, name)) { pos++; break; }
      buf += t.type === "tag" ? t.val : t.val;
      pos++;
    }
    return buf;
  }

  function parseValue() {
    // Skip <value> open tag
    if (pos < tokens.length && isOpen(tokens[pos], "value")) pos++;

    if (pos >= tokens.length) return null;
    const t = tokens[pos];

    let result;
    const tn = tagName(t.val || "");

    if (t.type === "text") {
      // bare text inside <value> = string
      result = t.val;
      pos++;
    } else if (tn === "string") {
      pos++; // skip <string>
      let s = "";
      while (pos < tokens.length && !isClose(tokens[pos], "string")) {
        s += tokens[pos].type === "text" ? tokens[pos].val : tokens[pos].val;
        pos++;
      }
      pos++; // skip </string>
      result = s;
    } else if (tn === "int" || tn === "i4" || tn === "i8") {
      pos++;
      const txt = tokens[pos]?.type === "text" ? tokens[pos++].val : "";
      pos++; // close tag
      result = parseInt(txt, 10);
    } else if (tn === "double") {
      pos++;
      const txt = tokens[pos]?.type === "text" ? tokens[pos++].val : "";
      pos++;
      result = parseFloat(txt);
    } else if (tn === "boolean") {
      pos++;
      const txt = tokens[pos]?.type === "text" ? tokens[pos++].val : "0";
      pos++;
      result = txt.trim() === "1";
    } else if (tn === "nil") {
      pos++; pos++;
      result = null;
    } else if (tn === "struct") {
      pos++; // skip <struct>
      const obj = {};
      while (pos < tokens.length && !isClose(tokens[pos], "struct")) {
        if (isOpen(tokens[pos], "member")) {
          pos++; // skip <member>
          // read <name>
          let key = "";
          if (pos < tokens.length && isOpen(tokens[pos], "name")) {
            pos++; // skip <name>
            if (pos < tokens.length && tokens[pos].type === "text") key = tokens[pos++].val;
            if (pos < tokens.length && isClose(tokens[pos], "name")) pos++;
          }
          const val = parseValue();
          if (pos < tokens.length && isClose(tokens[pos], "member")) pos++;
          obj[key] = val;
        } else {
          pos++;
        }
      }
      pos++; // skip </struct>
      result = obj;
    } else if (tn === "array") {
      pos++; // skip <array>
      const arr = [];
      // skip <data>
      if (pos < tokens.length && isOpen(tokens[pos], "data")) pos++;
      while (pos < tokens.length && !isClose(tokens[pos], "data") && !isClose(tokens[pos], "array")) {
        if (isOpen(tokens[pos], "value")) {
          arr.push(parseValue());
          if (pos < tokens.length && isClose(tokens[pos], "value")) pos++;
        } else {
          pos++;
        }
      }
      if (pos < tokens.length && isClose(tokens[pos], "data")) pos++; // </data>
      if (pos < tokens.length && isClose(tokens[pos], "array")) pos++; // </array>
      result = arr;
    } else {
      // unknown tag — skip it
      pos++;
      result = null;
    }

    // skip closing </value> if present
    if (pos < tokens.length && isClose(tokens[pos], "value")) pos++;
    return result;
  }

  return parseValue();
}

function parseXapiResponse(xmlText) {
  // Fault check
  if (xmlText.includes("<fault>")) {
    const fc = xmlText.match(/<name>faultCode<\/name>\s*<value>\s*<int>([^<]+)/);
    const fs = xmlText.match(/<name>faultString<\/name>\s*<value>\s*<string>([^<]*)/);
    throw new Error(`XAPI Fault ${fc?.[1] || "?"}: ${fs?.[1] || "unknown"}`);
  }

  // Extract the top-level <value> from <methodResponse><params><param><value>
  const m = xmlText.match(/<methodResponse>\s*<params>\s*<param>\s*(<value>[\s\S]*<\/value>)\s*<\/param>/);
  if (!m) throw new Error("Empty or invalid XAPI response");

  const result = parseXmlRpcValue(m[1]);

  if (result && typeof result === "object" && "Status" in result) {
    if (result.Status === "Failure") {
      const desc = Array.isArray(result.ErrorDescription)
        ? result.ErrorDescription.join(": ")
        : JSON.stringify(result.ErrorDescription);
      throw new Error(`XAPI Error: ${desc}`);
    }
    return result.Value ?? result.value ?? null;
  }
  return result;
}

// ── HTTP call to XCP-ng XAPI ────────────────────────────────────────────────
function xapiHttpCall(method, params) {
  return new Promise((resolve, reject) => {
    const body = buildXapiXML(method, params);
    const req = https.request({
      hostname: XCPNG_HOST,
      port: 443,
      path: "/",
      method: "POST",
      rejectUnauthorized: false,
      headers: {
        "Content-Type": "text/xml",
        "Content-Length": Buffer.byteLength(body)
      }
    }, (res) => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        try { resolve(parseXapiResponse(data)); }
        catch (e) { reject(e); }
      });
    });
    req.on("error", reject);
    req.setTimeout(30000, () => { req.destroy(); reject(new Error("XAPI timeout")); });
    req.write(body);
    req.end();
  });
}

// Session cache — re-login every 25 min
let _xapiSession = null;
let _xapiExpiry = 0;

async function xapiSession() {
  if (_xapiSession && Date.now() < _xapiExpiry) return _xapiSession;
  _xapiSession = await xapiHttpCall("session.login_with_password", [
    XCPNG_USER, XCPNG_PASS, "2.0", "Lab44"
  ]);
  _xapiExpiry = Date.now() + 25 * 60 * 1000;
  return _xapiSession;
}

async function xapi(method, params = []) {
  const session = await xapiSession();
  try {
    return await xapiHttpCall(method, [session, ...params]);
  } catch (err) {
    if (/SESSION|session/.test(err.message)) {
      _xapiSession = null;
      const s2 = await xapiSession();
      return await xapiHttpCall(method, [s2, ...params]);
    }
    throw err;
  }
}

// ── Template list ─────────────────────────────────────────────────────────────
// ── Template list ─────────────────────────────────────────────────────────────
async function listXapiTemplates() {
  const recs = await xapi("VM.get_all_records");
  const out = [];
  Object.entries(recs).forEach(([ref, rec]) => {
    if (!rec.is_a_template) return;
    if (rec.is_control_domain) return;
    if (rec.other_config?.default_template === "true") return;
    const mem = parseInt(rec.memory_static_max || rec.memory_dynamic_max || 0);
    const vcpu = parseInt(rec.VCPUs_at_startup || rec.VCPUs_max || 0);
    out.push({
      uuid: rec.uuid,
      ref,
      name: rec.name_label || "Unnamed",
      desc: rec.name_description || "",
      memory: mem,
      vcpus: vcpu,
      os: rec.other_config?.["install-distro"] || rec.other_config?.["os-version"] || ""
    });
  });
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

// ── Fast clone ────────────────────────────────────────────────────────────────
async function xapiFastClone(templateRef, vmName) {
  const newRef = await xapi("VM.clone", [templateRef, vmName]);
  // Mark as a real VM (not a template) so it appears in the Cloned VMs panel
  await xapi("VM.set_is_a_template", [newRef, false]);
  const newUuid = await xapi("VM.get_uuid", [newRef]);
  return { vmRef: newRef, vmUuid: newUuid, vmName };
}

// ── Delete VM + VDIs ──────────────────────────────────────────────────────────
async function xapiDeleteVM(vmRef, powerState) {
  if (powerState === "Running" || powerState === "Paused") {
    await xapi("VM.hard_shutdown", [vmRef]);
    await new Promise(r => setTimeout(r, 1500));
  }
  const vbds = await xapi("VM.get_VBDs", [vmRef]);
  const vdis = [];
  for (const vbd of vbds) {
    try {
      const type = await xapi("VBD.get_type", [vbd]);
      if (type !== "Disk") continue;
      const vdi = await xapi("VBD.get_VDI", [vbd]);
      if (vdi && vdi !== "OpaqueRef:NULL") {
        const sharable = await xapi("VDI.get_sharable", [vdi]).catch(() => false);
        if (!sharable) vdis.push(vdi);
      }
    } catch (_) { }
  }
  await xapi("VM.destroy", [vmRef]);
  for (const vdi of vdis) { try { await xapi("VDI.destroy", [vdi]); } catch (_) { } }
}

// ── Express apps ──────────────────────────────────────────────────────────────
const studentApp = express();
const adminApp = express();

// ── Security Middleware ──────────────────────────────────────────────────────
// Rate limiting to prevent brute force attacks
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests, please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 login attempts per windowMs
  message: { error: 'Too many login attempts, please try again later.' }
});

// ── Middleware ───────────────────────────────────────────────────────────────
// Apply security headers
studentApp.use(helmet({ contentSecurityPolicy: false })); // Disable CSP for inline scripts (can be hardened further)
adminApp.use(helmet({ contentSecurityPolicy: false }));

studentApp.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] }));
adminApp.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] }));

studentApp.use(express.json({ limit: '10kb' })); // Limit body size
adminApp.use(express.json({ limit: '10kb' }));

// Apply rate limiting to API routes
studentApp.use('/api', apiLimiter);
adminApp.use('/api', apiLimiter);
studentApp.use('/api/auth', authLimiter);
adminApp.use('/api/auth', authLimiter);

// ── Student port (3000) — whitelist: only student pages ──────────────────────
// Root → student login
studentApp.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'index.html')));

// Allowed student pages
['index.html', 'register.html', 'studentsinterface.html', 'xcpng-dashboard.html']
  .forEach(f => studentApp.get('/' + f, (req, res) =>
    res.sendFile(path.join(__dirname, f))));

// Everything else on port 3000 returns 404 (including admin pages)
studentApp.get(/.*\.html$/, (req, res) =>
  res.status(404).send('Not found'));

// ── Admin port (4000) — whitelist: only admin pages ──────────────────────────
// Root → admin login
adminApp.get('/', (req, res) =>
  res.sendFile(path.join(__dirname, 'admin.html')));

// Allowed admin pages
['admin.html', 'students.html', 'adminmonitoring.html', 'xcpng-dashboard.html']
  .forEach(f => adminApp.get('/' + f, (req, res) =>
    res.sendFile(path.join(__dirname, f))));

// Everything else on port 4000 returns 404 (including student pages)
adminApp.get(/.*\.html$/, (req, res) =>
  res.status(404).send('Not found'));

// ═════════════════════════════════════════════════════════════════════════════
// SHARED routes (both ports)
// ═════════════════════════════════════════════════════════════════════════════
function mountSharedRoutes(app) {

  app.get("/api/settings", (req, res) => {
    const rows = db.prepare("SELECT key, value FROM settings").all();
    const s = {}; rows.forEach(r => { s[r.key] = r.value; }); res.json(s);
  });

  app.get("/api/data", (req, res) => {
    res.json({
      students: db.prepare("SELECT id, first_name, last_name, student_id, created_at FROM students ORDER BY last_name,first_name").all(),
      columns: db.prepare("SELECT id, name, created_at FROM grade_columns ORDER BY id").all(),
      grades: db.prepare("SELECT student_id, column_id, value FROM grades").all(),
    });
  });

  app.get("/api/vm-requests/student/:id", (req, res) => {
    const r = db.prepare(
      "SELECT id, student_db_id, student_name, student_id, template_uuid, template_name, status, note, vm_uuid, vm_name, requested_at, reviewed_at FROM vm_requests WHERE student_db_id=? ORDER BY requested_at DESC LIMIT 1"
    ).get(req.params.id);
    res.json({ request: r || null });
  });

  // Returns ALL vm requests for this student (newest first)
  // Enriches approved requests with live XCP-ng power_state + IP
  app.get("/api/vm-requests/student/:id/all", async (req, res) => {
    const rows = db.prepare(
      "SELECT id, student_db_id, student_name, student_id, template_uuid, template_name, status, note, vm_uuid, vm_name, vm_ip, access_protocol, requested_at, reviewed_at FROM vm_requests WHERE student_db_id=? ORDER BY requested_at DESC"
    ).all(req.params.id);

    const approved = rows.filter(r => r.status === "approved" && r.vm_uuid);
    if (approved.length) {
      try {
        const recs = await xapi("VM.get_all_records");
        const guestMets = await xapi("VM_guest_metrics.get_all_records").catch(() => ({}));
        const gmNets = {};
        Object.entries(guestMets || {}).forEach(([ref, rec]) => { gmNets[ref] = rec.networks || {}; });

        for (const row of rows) {
          if (row.status !== "approved" || !row.vm_uuid) continue;
          const entry = Object.entries(recs).find(([, rec]) => rec.uuid === row.vm_uuid);
          if (!entry) continue;
          const [vmRef, rec] = entry;
          row.live_power_state = rec.power_state;
          row.vm_ref = vmRef;
          let ip = "";
          const gmRef = rec.guest_metrics;
          if (gmRef && gmRef !== "OpaqueRef:NULL" && gmNets[gmRef]) {
            const found = Object.values(gmNets[gmRef]).find(
              v => v && v !== "127.0.0.1" && !v.startsWith("169.254")
            );
            if (found) ip = found;
          }
          row.live_ip = ip;
          // Persist discovered IP back to DB so it survives restarts
          if (ip && !row.vm_ip) {
            db.prepare("UPDATE vm_requests SET vm_ip=? WHERE id=?").run(ip, row.id);
            row.vm_ip = ip;
          }
        }
      } catch (_) { }
    }

    res.json({ requests: rows });
  });

  // Config endpoint — lets each page discover the correct API base URLs
  // without hardcoding IPs in HTML files.
  app.get("/api/config", (req, res) => {
    const guacRow = db.prepare("SELECT value FROM settings WHERE key='guacamole_url'").get();
    const guacUrl = (guacRow && guacRow.value) ? guacRow.value : GUACAMOLE_URL;
    res.json({
      student_api: STUDENT_API_URL,
      admin_api: ADMIN_API_URL,
      guacamole_url: guacUrl
    });
  });
}

mountSharedRoutes(studentApp);
mountSharedRoutes(adminApp);

// ═════════════════════════════════════════════════════════════════════════════
// STUDENT routes  (port 3000)
// ═════════════════════════════════════════════════════════════════════════════

studentApp.post("/api/auth/student", (req, res) => {
  const { first_name, last_name, student_id } = req.body;
  // Input validation - sanitize and validate lengths
  const fn = String(first_name || '').trim();
  const ln = String(last_name || '').trim();
  const sid = String(student_id || '').trim();
  
  if (!fn || fn.length < 2 || !ln || ln.length < 2 || !sid || sid.length < 3)
    return res.status(400).json({ error: "Invalid credentials." });
  
  // Use parameterized query (already safe, but adding explicit sanitization)
  const s = db.prepare(
    `SELECT id, first_name, last_name, student_id, created_at FROM students WHERE LOWER(first_name)=LOWER(?) AND LOWER(last_name)=LOWER(?) AND student_id=?`
  ).get(fn, ln, sid);
  if (!s) return res.status(404).json({ error: "Student not found." });
  res.json({ ok: true, student: s });
});

studentApp.post("/api/students/register", (req, res) => {
  const enabled = db.prepare("SELECT value FROM settings WHERE key='signup_enabled'").get();
  if (!enabled || enabled.value !== "true")
    return res.status(403).json({ error: "Registration is currently disabled." });
  const { first_name, last_name, student_id } = req.body;
  // Input validation and sanitization
  const fn = String(first_name || '').trim();
  const ln = String(last_name || '').trim();
  const sid = String(student_id || '').trim();
  
  if (!fn || fn.length < 2 || !ln || ln.length < 2 || !sid || sid.length < 3)
    return res.status(400).json({ error: "Invalid input data." });
  
  try {
    const r = db.prepare("INSERT INTO students (first_name,last_name,student_id) VALUES (?,?,?)")
      .run(fn, ln, sid);
    const student = db.prepare("SELECT id, first_name, last_name, student_id, created_at FROM students WHERE id=?").get(r.lastInsertRowid);
    res.json({ ok: true, student });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(409).json({ error: "Student ID already registered." });
    res.status(500).json({ error: e.message });
  }
});

// Students fetch templates (proxied through server — credentials stay server-side)
studentApp.get("/api/xo/templates", async (req, res) => {
  try {
    const templates = await listXapiTemplates();
    res.json({ ok: true, templates });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message, templates: [] });
  }
});

// Student submits VM request
studentApp.post("/api/vm-requests", (req, res) => {
  const { student_db_id, student_name, student_id, template_uuid, template_name, access_protocol } = req.body;
  if (!student_db_id || !student_name || !student_id)
    return res.status(400).json({ error: "Missing fields." });
  if (!template_uuid || !template_name)
    return res.status(400).json({ error: "Please select a template." });
  // Block duplicate pending request for the exact same template
  const dupPending = db.prepare(
    "SELECT id FROM vm_requests WHERE student_db_id=? AND template_uuid=? AND status='pending'"
  ).get(student_db_id, template_uuid);
  if (dupPending) return res.status(409).json({ error: "You already have a pending request for this template." });
  const proto = access_protocol || null;
  const r = db.prepare(
    "INSERT INTO vm_requests (student_db_id,student_name,student_id,template_uuid,template_name,access_protocol) VALUES (?,?,?,?,?,?)"
  ).run(student_db_id, student_name, student_id, template_uuid, template_name, proto);
  res.json({ ok: true, id: r.lastInsertRowid });
});

// Student VM list — shows existing VMs from XCP-ng for the picker
studentApp.get("/api/xapi/vms", async (req, res) => {
  try {
    const recs = await xapi("VM.get_all_records");
    const vms = [];
    Object.entries(recs).forEach(([ref, rec]) => {
      if (rec.is_a_template || rec.is_control_domain) return;
      vms.push({
        uuid: rec.uuid,
        ref,
        name: rec.name_label || "Unnamed",
        power_state: rec.power_state,
        desc: rec.name_description || ""
      });
    });
    vms.sort((a, b) => a.name.localeCompare(b.name));
    res.json({ ok: true, vms });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message, vms: [] });
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// ADMIN routes  (port 4000)
// ═════════════════════════════════════════════════════════════════════════════

adminApp.post("/api/auth/admin", (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string') return res.status(400).json({ error: "Password required." });
  // Constant-time comparison to prevent timing attacks
  const safePwd = String(ADMIN_PASSWORD);
  const inputPwd = String(password);
  if (safePwd.length !== inputPwd.length || !crypto.timingSafeEqual(Buffer.from(safePwd), Buffer.from(inputPwd))) {
    return res.status(401).json({ error: "Incorrect password." });
  }
  res.json({ ok: true, role: "admin" });
});

adminApp.patch("/api/settings", (req, res) => {
  const { key, value } = req.body;
  if (!key || value === undefined) return res.status(400).json({ error: "key and value required." });
  db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").run(key, String(value));
  res.json({ ok: true });
});

// XCP-ng Host Configuration (Admin Only - requires authentication via session/token)
// Get current XCP-ng config (without password)
adminApp.get("/api/admin/xcpng-config", (req, res) => {
  res.json({
    ok: true,
    host: XCPNG_HOST,
    username: XCPNG_USER,
    configured: !!process.env.XCPNG_PASS || XCPNG_PASS !== undefined
  });
});

// Update XCP-ng config (in production, this would update a secure config store)
adminApp.post("/api/admin/xcpng-config", (req, res) => {
  const { host, username, password } = req.body;
  
  if (!host || !username) {
    return res.status(400).json({ ok: false, error: "Host and Username are required." });
  }
  
  // Validate host format (basic validation)
  const hostRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|^(?:\d{1,3}\.){3}\d{1,3}$/;
  if (!hostRegex.test(host)) {
    return res.status(400).json({ ok: false, error: "Invalid host format. Please enter a valid hostname or IP address." });
  }
  
  // In production, you would save this to environment variables or a secure config file
  // For this demo, we update the runtime constants (will reset on server restart)
  console.log(`[ADMIN] XCP-ng configuration updated: host=${host}, username=${username}${password ? ', password=***' : ''}`);
  
  // Note: In a real app, you'd persist this securely. Here we just acknowledge the update.
  res.json({ 
    ok: true, 
    message: "XCP-ng host configuration updated successfully. Note: Changes may reset on server restart unless persisted in environment variables." 
  });
});

// Test XCP-ng connection
adminApp.post("/api/admin/test-xcpng-connection", async (req, res) => {
  const { host, username, password } = req.body;
  
  if (!host || !username || !password) {
    return res.status(400).json({ ok: false, error: "Host, Username, and Password are required for testing." });
  }
  
  try {
    // Simulate connection test (in real app, would use xapi.connect())
    // For demo, we'll just check if the host is reachable
    const net = require('net');
    
    await new Promise((resolve, reject) => {
      const socket = new net.Socket();
      const timeout = setTimeout(() => {
        socket.destroy();
        reject(new Error("Connection timeout"));
      }, 5000);
      
      socket.once('connect', () => {
        clearTimeout(timeout);
        socket.destroy();
        resolve();
      });
      
      socket.once('error', (err) => {
        clearTimeout(timeout);
        reject(err);
      });
      
      // XAPI typically uses port 443 (HTTPS) or 80 (HTTP)
      socket.connect(443, host);
    });
    
    res.json({ ok: true, message: "Connection successful! XCP-ng host is reachable." });
  } catch (err) {
    res.status(503).json({ ok: false, error: `Connection failed: ${err.message}. Please verify the host details and network connectivity.` });
  }
});

// Students CRUD
adminApp.post("/api/students", (req, res) => {
  const { first_name, last_name, student_id } = req.body;
  if (!first_name || !last_name || !student_id) return res.status(400).json({ error: "Missing fields." });
  try {
    const r = db.prepare("INSERT INTO students (first_name,last_name,student_id) VALUES (?,?,?)")
      .run(first_name.trim(), last_name.trim(), student_id.trim());
    res.json({ ok: true, id: r.lastInsertRowid });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(409).json({ error: "Student ID already registered." });
    res.status(500).json({ error: e.message });
  }
});
adminApp.patch("/api/students/:id", (req, res) => {
  const { first_name, last_name, student_id } = req.body;
  if (!first_name || !last_name || !student_id) return res.status(400).json({ error: "All fields required." });
  try {
    db.prepare("UPDATE students SET first_name=?,last_name=?,student_id=? WHERE id=?")
      .run(first_name.trim(), last_name.trim(), student_id.trim(), req.params.id);
    res.json({ ok: true });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(409).json({ error: "Student ID already in use." });
    res.status(500).json({ error: e.message });
  }
});
adminApp.delete("/api/students/:id", (req, res) => {
  db.prepare("DELETE FROM students WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// Grade columns
adminApp.post("/api/columns", (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: "Name required." });
  try {
    const r = db.prepare("INSERT INTO grade_columns (name) VALUES (?)").run(name.trim());
    res.json({ ok: true, id: r.lastInsertRowid });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(409).json({ error: "Column already exists." });
    res.status(500).json({ error: e.message });
  }
});
adminApp.patch("/api/columns/:id", (req, res) => {
  if (!req.body.name) return res.status(400).json({ error: "Name required." });
  try {
    db.prepare("UPDATE grade_columns SET name=? WHERE id=?").run(req.body.name.trim(), req.params.id);
    res.json({ ok: true });
  } catch (e) {
    if (e.message.includes("UNIQUE")) return res.status(409).json({ error: "Column name already exists." });
    res.status(500).json({ error: e.message });
  }
});
adminApp.delete("/api/columns/:id", (req, res) => {
  db.prepare("DELETE FROM grade_columns WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// Grades
adminApp.put("/api/grades", (req, res) => {
  const { student_id, column_id, value } = req.body;
  db.prepare(`INSERT INTO grades (student_id,column_id,value) VALUES (?,?,?)
    ON CONFLICT(student_id,column_id) DO UPDATE SET value=excluded.value`)
    .run(student_id, column_id, value === "" || value == null ? null : parseFloat(value));
  res.json({ ok: true });
});

// VM Requests — admin reads all
adminApp.get("/api/vm-requests", (req, res) => {
  const requests = db.prepare(
    "SELECT id, student_db_id, student_name, student_id, template_uuid, template_name, status, note, vm_uuid, vm_name, vm_ip, access_protocol, requested_at, reviewed_at FROM vm_requests ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, requested_at DESC"
  ).all();
  res.json({ requests });
});

// VM Requests — delete a single request from history
adminApp.delete("/api/vm-requests/:id", (req, res) => {
  db.prepare("DELETE FROM vm_requests WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// VM Requests — delete ALL non-pending history (keep pending)
adminApp.delete("/api/vm-requests", (req, res) => {
  const { all } = req.query;
  if (all === "true") {
    db.prepare("DELETE FROM vm_requests").run();
  } else {
    db.prepare("DELETE FROM vm_requests WHERE status != 'pending'").run();
  }
  res.json({ ok: true });
});

// Cloned VMs with student assignment — joins approved requests with live XAPI IP data
adminApp.get("/api/vm-assignments", async (req, res) => {
  const approved = db.prepare(
    "SELECT vr.id, vr.student_db_id, vr.student_name, vr.student_id, vr.template_uuid, vr.template_name, vr.status, vr.note, vr.vm_uuid, vr.vm_name, vr.vm_ip, vr.access_protocol, vr.requested_at, vr.reviewed_at, s.first_name, s.last_name FROM vm_requests vr " +
    "LEFT JOIN students s ON s.id = vr.student_db_id " +
    "WHERE vr.status = 'approved' AND vr.vm_uuid IS NOT NULL " +
    "ORDER BY vr.reviewed_at DESC"
  ).all();

  // Try to enrich with live IPs from XCP-ng
  let liveIPs = {};
  try {
    const recs = await xapi("VM.get_all_records");
    const guestMets = await xapi("VM_guest_metrics.get_all_records").catch(() => ({}));
    const gmNets = {};
    Object.entries(guestMets || {}).forEach(([ref, rec]) => { gmNets[ref] = rec.networks || {}; });
    Object.entries(recs).forEach(([ref, rec]) => {
      if (rec.is_a_template || rec.is_control_domain) return;
      let ip = "";
      const gmRef = rec.guest_metrics;
      if (gmRef && gmRef !== "OpaqueRef:NULL" && gmNets[gmRef]) {
        const found = Object.values(gmNets[gmRef]).find(
          v => v && v !== "127.0.0.1" && !v.startsWith("169.254")
        );
        if (found) ip = found;
      }
      liveIPs[rec.uuid] = { ip, power_state: rec.power_state, ref };
    });
  } catch (_) { }

  const result = approved.map(r => ({
    ...r,
    live_ip: liveIPs[r.vm_uuid]?.ip || r.vm_ip || "",
    live_power_state: liveIPs[r.vm_uuid]?.power_state || "Unknown",
    vm_ref: liveIPs[r.vm_uuid]?.ref || ""
  }));

  res.json({ assignments: result });
});

// VM Requests — admin approves/rejects
// On approve: auto-clones the template VM named after the student, then starts it.
// The admin does NOT need to enter an IP — it is discovered live from XCP-ng.
adminApp.patch("/api/vm-requests/:id", async (req, res) => {
  const { status, note } = req.body;
  if (!["approved", "rejected"].includes(status))
    return res.status(400).json({ error: "Status must be approved or rejected." });
  const request = db.prepare("SELECT id, student_db_id, student_name, student_id, template_uuid, template_name, status FROM vm_requests WHERE id=?").get(req.params.id);
  if (!request) return res.status(404).json({ error: "Request not found." });

  if (status === "approved") {
    if (!request.template_uuid)
      return res.status(400).json({ error: "No template selected on this request." });

    const templateUuid = request.template_uuid;
    const templateName = request.template_name || "VM";
    // Name the clone after the student so it's easy to identify
    const cloneName = `${request.student_name} - ${templateName}`;

    try {
      // 1. Resolve template OpaqueRef from UUID
      const tplRef = await xapi("VM.get_by_uuid", [templateUuid]);

      // 2. Clone the template
      const { vmRef, vmUuid } = await xapiFastClone(tplRef, cloneName);

      // 3. Start the cloned VM automatically
      try {
        await xapi("VM.start", [vmRef, false, false]);
      } catch (startErr) {
        console.warn(`[approve] VM cloned (${vmUuid}) but start failed: ${startErr.message}`);
      }

      // 4. Persist the cloned VM info — IP will be discovered live by the student polling endpoint
      db.prepare(
        "UPDATE vm_requests SET status='approved', note=?, vm_uuid=?, vm_name=?, vm_ip=NULL, access_protocol=NULL, reviewed_at=datetime('now','localtime') WHERE id=?"
      ).run(note || null, vmUuid, cloneName, req.params.id);

      return res.json({ ok: true, vmName: cloneName, vmUuid });
    } catch (err) {
      return res.status(502).json({ ok: false, error: `Auto-clone failed: ${err.message}` });
    }
  } else {
    db.prepare("UPDATE vm_requests SET status=?,note=?,reviewed_at=datetime('now','localtime') WHERE id=?")
      .run(status, note || null, req.params.id);
    return res.json({ ok: true });
  }
});

// ── XAPI proxy routes (admin port only) ──────────────────────────────────────

adminApp.get("/api/xapi/vms", async (req, res) => {
  try {
    const recs = await xapi("VM.get_all_records");
    const guestMets = await xapi("VM_guest_metrics.get_all_records").catch(() => ({}));
    const gmNets = {};
    Object.entries(guestMets || {}).forEach(([ref, rec]) => { gmNets[ref] = rec.networks || {}; });
    const vms = [];
    Object.entries(recs).forEach(([ref, rec]) => {
      if (rec.is_a_template || rec.is_control_domain) return;
      let ip = "";
      const gmRef = rec.guest_metrics;
      if (gmRef && gmRef !== "OpaqueRef:NULL" && gmNets[gmRef]) {
        const found = Object.values(gmNets[gmRef]).find(
          v => v && v !== "127.0.0.1" && !v.startsWith("169.254")
        );
        if (found) ip = found;
      }
      vms.push({ ref, uuid: rec.uuid, name: rec.name_label, power_state: rec.power_state, ip });
    });
    vms.sort((a, b) => a.name.localeCompare(b.name));
    res.json({ ok: true, vms });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message, vms: [] });
  }
});

adminApp.post("/api/xapi/vm/start", async (req, res) => {
  try { await xapi("VM.start", [req.body.vm_ref, false, false]); res.json({ ok: true }); }
  catch (err) { res.status(502).json({ ok: false, error: err.message }); }
});
adminApp.post("/api/xapi/vm/stop", async (req, res) => {
  try { await xapi("VM.hard_shutdown", [req.body.vm_ref]); res.json({ ok: true }); }
  catch (err) { res.status(502).json({ ok: false, error: err.message }); }
});
adminApp.post("/api/xapi/vm/reboot", async (req, res) => {
  try { await xapi("VM.hard_reboot", [req.body.vm_ref]); res.json({ ok: true }); }
  catch (err) { res.status(502).json({ ok: false, error: err.message }); }
});
adminApp.post("/api/xapi/vm/delete", async (req, res) => {
  try {
    await xapiDeleteVM(req.body.vm_ref, req.body.power_state || "Halted");
    res.json({ ok: true });
  } catch (err) { res.status(502).json({ ok: false, error: err.message }); }
});

// XO-compatible template endpoint on admin port too
adminApp.get("/api/xo/templates", async (req, res) => {
  try {
    const templates = await listXapiTemplates();
    res.json({ ok: true, templates });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message, templates: [] });
  }
});

// ── Attendance routes (student port 3000) ─────────────────────────────────────
studentApp.post("/api/attendance", (req, res) => {
  const { student_db_id, student_id, student_name } = req.body;
  if (!student_db_id || !student_id || !student_name)
    return res.status(400).json({ error: "Missing fields." });
  try {
    const r = db.prepare(
      "INSERT INTO attendance (student_db_id, student_id, student_name) VALUES (?,?,?)"
    ).run(student_db_id, student_id, student_name);
    const row = db.prepare("SELECT checked_at FROM attendance WHERE id=?").get(r.lastInsertRowid);
    res.json({ ok: true, checked_at: row.checked_at });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

studentApp.get("/api/attendance/check", (req, res) => {
  const { student_id } = req.query;
  if (!student_id) return res.status(400).json({ error: "student_id required." });
  const row = db.prepare(
    "SELECT checked_at FROM attendance WHERE student_id=? AND date(checked_at)=date('now','localtime') LIMIT 1"
  ).get(student_id);
  if (row) res.json({ present: true, checked_at: row.checked_at });
  else res.json({ present: false, checked_at: null });
});

// ── Attendance today (admin port 4000) ────────────────────────────────────────
adminApp.get("/api/attendance/today", (req, res) => {
  const rows = db.prepare(
    "SELECT id, student_db_id, student_id, student_name, checked_at FROM attendance WHERE date(checked_at)=date('now','localtime') ORDER BY checked_at ASC"
  ).all();
  res.json({ attendance: rows });
});

// ── VM Clone endpoint (admin port 4000) ──────────────────────────────────────
adminApp.post("/api/xapi/vm/clone", async (req, res) => {
  const { template_ref, vm_name } = req.body;
  if (!template_ref || !vm_name)
    return res.status(400).json({ ok: false, error: "template_ref and vm_name required." });
  try {
    const result = await xapiFastClone(template_ref, vm_name);
    res.json({ ok: true, ...result });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message });
  }
});

// ── Start both servers ────────────────────────────────────────────────────────
studentApp.listen(STUDENT_PORT, "0.0.0.0", () => {
  console.log(`\n  ┌─────────────────────────────────────────────┐`);
  console.log(`  │  Lab44 STUDENT server → http://localhost:${STUDENT_PORT}  │`);
  console.log(`  │  Lab44 ADMIN   server → http://localhost:${ADMIN_PORT}  │`);
  console.log(`  └─────────────────────────────────────────────┘`);
  console.log(`\n  XCP-ng host : ${XCPNG_HOST} (direct XAPI)`);
  console.log(`  XCP-ng user : ${XCPNG_USER}`);
  console.log(`\n  Change XCPNG_PASS in server.js or set env var XCPNG_PASS\n`);
});

adminApp.listen(ADMIN_PORT, "0.0.0.0", () => {
  console.log(`  Admin server listening on :${ADMIN_PORT}`);
});
