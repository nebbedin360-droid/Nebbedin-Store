require("dotenv").config();
const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
// Render runs behind a reverse proxy; trust it so secure session cookies work in production.
app.set("trust proxy", 1);
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(ROOT, "uploads");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "nebbedin-store.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  google_id TEXT UNIQUE,
  email_verified INTEGER NOT NULL DEFAULT 1,
  verification_token_hash TEXT,
  verification_expires_at INTEGER,
  role TEXT NOT NULL DEFAULT 'developer',
  bio TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL,
  platform TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0',
  file_name TEXT NOT NULL,
  original_name TEXT NOT NULL,
  file_size INTEGER NOT NULL,
  mime_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  payment_status TEXT NOT NULL DEFAULT 'not_required',
  fee_etb INTEGER NOT NULL DEFAULT 0,
  downloads INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
  comment TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(project_id, user_id),
  FOREIGN KEY(project_id) REFERENCES projects(id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER NOT NULL,
  user_id INTEGER,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(project_id) REFERENCES projects(id)
);
`);
// Safe additive migrations for databases created by earlier versions.
const userColumns = new Set(db.prepare("PRAGMA table_info(users)").all().map(c => c.name));
if (!userColumns.has("google_id")) db.exec("ALTER TABLE users ADD COLUMN google_id TEXT");
if (!userColumns.has("email_verified")) db.exec("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1");
if (!userColumns.has("verification_token_hash")) db.exec("ALTER TABLE users ADD COLUMN verification_token_hash TEXT");
if (!userColumns.has("verification_expires_at")) db.exec("ALTER TABLE users ADD COLUMN verification_expires_at INTEGER");

if (process.env.NODE_ENV === "production" && (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || !process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) {
  throw new Error("Production requires ADMIN_EMAIL, ADMIN_PASSWORD, and a SESSION_SECRET of at least 32 characters.");
}
const adminEmail = (process.env.ADMIN_EMAIL || "admin@example.com").trim().toLowerCase();
const adminPassword = process.env.ADMIN_PASSWORD || "ChangeThisAdminPassword123!";
const existingAdmin = db.prepare("SELECT id FROM users WHERE email = ?").get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,'admin')")
    .run("admin", adminEmail, hash);
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));
app.use(express.urlencoded({ extended: false, limit: "30kb" }));
app.use(express.json({ limit: "30kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || "development-only-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 24 * 30 }, rolling: true
}));
app.use(express.static(path.join(ROOT, "public")));
app.use("/uploads", (req, res, next) => {
  // Files are intentionally not exposed as a public static directory.
  res.status(404).send("Not found");
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const emailConfigured = Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.SMTP_FROM);
const mailer = emailConfigured ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || "false") === "true",
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;
function publicUser(user) {
  return user ? { id: user.id, username: user.username, email: user.email, role: user.role, bio: user.bio } : null;
}
function saveSession(req) {
  return new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
}
async function sendVerificationEmail(email, token, req) {
  const base = (process.env.APP_URL || `${req.protocol}://${req.get("host")}`).replace(/\/$/, "");
  const link = `${base}/api/verify-email?token=${encodeURIComponent(token)}`;
  await mailer.sendMail({
    from: process.env.SMTP_FROM,
    to: email,
    subject: "Verify your Nebbedin Store email",
    text: `Welcome to Nebbedin Store. Verify your email using this link (valid for 30 minutes): ${link}`,
    html: `<p>Welcome to Nebbedin Store.</p><p><a href="${link}">Verify your email address</a></p><p>This link expires in 30 minutes. If you did not create this account, ignore this message.</p>`
  });
}

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare("SELECT id, username, email, role, bio FROM users WHERE id = ?").get(req.session.userId) || null;
}
function requireAuth(req, res, next) {
  if (!currentUser(req)) return res.status(401).json({ error: "Please sign in first." });
  next();
}
function requireAdmin(req, res, next) {
  const user = currentUser(req);
  if (!user || user.role !== "admin") return res.status(403).json({ error: "Admin access required." });
  next();
}
function safeProject(row) {
  if (!row) return row;
  const rating = db.prepare("SELECT ROUND(AVG(rating),1) AS average, COUNT(*) AS count FROM reviews WHERE project_id = ?").get(row.id);
  return {
    id: row.id, title: row.title, description: row.description, category: row.category,
    platform: row.platform, version: row.version, original_name: row.original_name,
    file_size: row.file_size, status: row.status, downloads: row.downloads,
    created_at: row.created_at, username: row.username || "Developer",
    rating: rating.average || 0, rating_count: rating.count || 0
  };
}
function mb(value) { return Math.max(1, Number(value || 1)) * 1024 * 1024; }
const maxByPlatform = {
  android: mb(process.env.MAX_APK_MB || 250),
  pc: mb(process.env.MAX_PC_GAME_MB || 1000),
  browser: mb(process.env.MAX_WEB_GAME_MB || 100),
  other: mb(process.env.MAX_OTHER_MB || 250)
};
const allowedExt = {
  android: new Set([".apk"]),
  pc: new Set([".zip", ".7z", ".rar", ".exe", ".msi", ".dmg", ".appimage"]),
  browser: new Set([".zip"]),
  other: new Set([".zip", ".7z", ".rar", ".pdf", ".exe", ".msi", ".dmg", ".appimage"])
};
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, crypto.randomBytes(20).toString("hex") + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: Math.max(...Object.values(maxByPlatform)) },
  fileFilter: (req, file, cb) => {
    const platform = req.body.platform;
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExt[platform] || !allowedExt[platform].has(ext)) {
      return cb(new Error("File type is not allowed for the selected platform."));
    }
    cb(null, true);
  }
});

app.get("/api/config", (_req, res) => {
  res.json({
    feeEtb: 0,
    googleSignInEnabled: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.APP_URL),
    emailVerificationEnabled: emailConfigured,
    limitsMb: {
      android: Math.round(maxByPlatform.android / 1024 / 1024),
      pc: Math.round(maxByPlatform.pc / 1024 / 1024),
      browser: Math.round(maxByPlatform.browser / 1024 / 1024),
      other: Math.round(maxByPlatform.other / 1024 / 1024)
    }
  });
});
app.get("/api/me", (req, res) => res.json({ user: currentUser(req) }));

app.post("/api/register", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3–24 letters, numbers, or underscores." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Enter a valid email address." });
  if (password.length < 10) return res.status(400).json({ error: "Password must be at least 10 characters." });
  if (password.length > 200) return res.status(400).json({ error: "Password is too long." });
  // If SMTP is configured, require email verification. Otherwise keep registration usable,
  // but clearly expose that verification is not active in deployment configuration.
  if (process.env.REQUIRE_EMAIL_VERIFICATION === "true" && !emailConfigured) {
    return res.status(503).json({ error: "Email verification is required but not configured yet. Please try again later." });
  }
  try {
    const hash = await bcrypt.hash(password, 12);
    const verified = emailConfigured ? 0 : 1;
    const token = emailConfigured ? crypto.randomBytes(32).toString("hex") : null;
    const tokenHash = token ? crypto.createHash("sha256").update(token).digest("hex") : null;
    const info = db.prepare(`INSERT INTO users (username,email,password_hash,email_verified,verification_token_hash,verification_expires_at) VALUES (?,?,?,?,?,?)`)
      .run(username, email, hash, verified, tokenHash, token ? Date.now() + 30 * 60 * 1000 : null);
    if (token) {
      try { await sendVerificationEmail(email, token, req); }
      catch (mailError) {
        db.prepare("DELETE FROM users WHERE id=?").run(Number(info.lastInsertRowid));
        console.error("Verification email failed:", mailError.message);
        return res.status(503).json({ error: "We could not send a verification email. Check the email service configuration and try again." });
      }
      return res.json({ ok: true, requiresVerification: true, message: "Check your email for a verification link. It expires in 30 minutes." });
    }
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: "Account created, but we could not start your session. Please sign in." });
      req.session.userId = Number(info.lastInsertRowid);
      req.session.save(saveErr => {
        if (saveErr) return res.status(500).json({ error: "Account created, but the session could not be saved. Please sign in." });
        res.json({ ok: true, user: publicUser(currentUser(req)), emailVerificationEnabled: false });
      });
    });
  } catch (e) {
    if (String(e.code || "").includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "That username or email is already registered." });
    console.error(e);
    res.status(500).json({ error: "Could not create your account. Please try again." });
  }
});
app.get("/api/verify-email", async (req, res) => {
  const token = String(req.query.token || "");
  if (!/^[a-f0-9]{64}$/.test(token)) return res.status(400).send("This verification link is invalid or expired. Please register again.");
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  const user = db.prepare("SELECT id FROM users WHERE verification_token_hash=? AND verification_expires_at>? ").get(hash, Date.now());
  if (!user) return res.status(400).send("This verification link is invalid or expired. Please request a new one.");
  db.prepare("UPDATE users SET email_verified=1,verification_token_hash=NULL,verification_expires_at=NULL WHERE id=?").run(user.id);
  res.send(`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>Email verified</title><style>body{font:16px system-ui;background:#101116;color:#fff;display:grid;place-items:center;min-height:90vh}main{max-width:520px;padding:32px;border:1px solid #333;border-radius:18px}a{color:#a8e6a1}</style></head><body><main><h1>Email verified</h1><p>Your Nebbedin Store email is verified. You can now sign in.</p><a href="/">Return to Nebbedin Store</a></main></body></html>`);
});
app.post("/api/login", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Email or password is incorrect." });
  if (!user.email_verified) return res.status(403).json({ error: "Please verify your email using the link we sent before signing in." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start your session." });
    req.session.userId = user.id;
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: "Could not save your session. Please try again." });
      res.json({ ok: true, user: publicUser(user) });
    });
  });
});
// Optional Google OAuth 2.0 using Google's OpenID Connect endpoints (no passport dependency).
app.get("/auth/google", (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.APP_URL) return res.status(503).send("Google sign-in is not configured yet.");
  const state = crypto.randomBytes(24).toString("hex");
  req.session.googleOAuthState = state;
  req.session.save(err => {
    if (err) return res.status(500).send("Could not start Google sign-in.");
    const params = new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID, redirect_uri: `${process.env.APP_URL.replace(/\/$/, "")}/auth/google/callback`, response_type: "code", scope: "openid email profile", state, prompt: "select_account" });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  });
});
app.get("/auth/google/callback", async (req, res) => {
  const state = String(req.query.state || "");
  if (!state || !req.session.googleOAuthState || state !== req.session.googleOAuthState) return res.status(400).send("Google sign-in state did not match. Please try again.");
  delete req.session.googleOAuthState;
  if (req.query.error || !req.query.code) return res.redirect("/?auth=google-cancelled");
  try {
    const redirectUri = `${process.env.APP_URL.replace(/\/$/, "")}/auth/google/callback`;
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code: String(req.query.code), client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri, grant_type: "authorization_code" }) });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) throw new Error("Google did not return an access token.");
    const profileResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.email || profile.email_verified !== true) throw new Error("Google account must have a verified email address.");
    let user = db.prepare("SELECT * FROM users WHERE email=? OR google_id=?").get(String(profile.email).toLowerCase(), profile.sub);
    if (!user) {
      const base = String(profile.name || profile.given_name || "developer").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 18) || "developer";
      let username = base, suffix = 1;
      while (db.prepare("SELECT id FROM users WHERE username=?").get(username)) { username = `${base.slice(0, 20)}${suffix++}`; }
      const randomPassword = await bcrypt.hash(crypto.randomBytes(32).toString("hex"), 12);
      const result = db.prepare("INSERT INTO users (username,email,password_hash,google_id,email_verified) VALUES (?,?,?,?,1)").run(username, String(profile.email).toLowerCase(), randomPassword, profile.sub);
      user = db.prepare("SELECT * FROM users WHERE id=?").get(Number(result.lastInsertRowid));
    } else {
      if (user.google_id && user.google_id !== profile.sub) throw new Error("This email is connected to a different Google account.");
      db.prepare("UPDATE users SET google_id=?,email_verified=1 WHERE id=?").run(profile.sub, user.id);
      user = db.prepare("SELECT * FROM users WHERE id=?").get(user.id);
    }
    req.session.regenerate(err => {
      if (err) return res.status(500).send("Could not start your session.");
      req.session.userId = user.id;
      req.session.save(saveErr => { if (saveErr) return res.status(500).send("Could not save your session."); res.redirect("/"); });
    });
  } catch (err) {
    console.error("Google OAuth failed:", err.message);
    res.status(401).send("Google sign-in failed. Please return to Nebbedin Store and try again.");
  }
});
app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/projects", (req, res) => {
  const search = String(req.query.q || "").trim().slice(0, 80);
  const category = String(req.query.category || "").trim();
  const platform = String(req.query.platform || "").trim();
  const order = req.query.sort === "downloads" ? "p.downloads DESC, p.created_at DESC" : "p.created_at DESC";
  let sql = `SELECT p.*, u.username FROM projects p JOIN users u ON u.id=p.user_id WHERE p.status='approved'`;
  const args = [];
  if (search) { sql += " AND (p.title LIKE ? OR p.description LIKE ? OR u.username LIKE ?)"; args.push(`%${search}%`,`%${search}%`,`%${search}%`); }
  if (category && ["Games","Education","Productivity","Entertainment","Tools","Other"].includes(category)) { sql += " AND p.category=?"; args.push(category); }
  if (platform && ["android","pc","browser","other"].includes(platform)) { sql += " AND p.platform=?"; args.push(platform); }
  sql += ` ORDER BY ${order} LIMIT 100`;
  const rows = db.prepare(sql).all(...args).map(safeProject);
  res.json({ projects: rows });
});
app.get("/api/projects/:id", (req, res) => {
  const row = db.prepare(`SELECT p.*, u.username FROM projects p JOIN users u ON u.id=p.user_id WHERE p.id=? AND p.status='approved'`).get(Number(req.params.id));
  if (!row) return res.status(404).json({ error: "Project not found." });
  res.json({ project: safeProject(row), reviews: db.prepare(`SELECT r.rating,r.comment,r.created_at,u.username FROM reviews r JOIN users u ON u.id=r.user_id WHERE r.project_id=? ORDER BY r.created_at DESC LIMIT 50`).all(row.id) });
});
app.get("/api/developer/:username", (req, res) => {
  const dev = db.prepare("SELECT id,username,bio,created_at FROM users WHERE username=?").get(req.params.username);
  if (!dev) return res.status(404).json({ error: "Developer not found." });
  const projects = db.prepare(`SELECT p.*, u.username FROM projects p JOIN users u ON u.id=p.user_id WHERE p.user_id=? AND p.status='approved' ORDER BY p.created_at DESC`).all(dev.id).map(safeProject);
  res.json({ developer: dev, projects });
});
app.post("/api/developer/profile", requireAuth, (req, res) => {
  const bio = String(req.body.bio || "").trim().slice(0, 300);
  db.prepare("UPDATE users SET bio=? WHERE id=?").run(bio, req.session.userId);
  res.json({ ok: true, user: currentUser(req) });
});

app.post("/api/projects", requireAuth, uploadLimiter, (req, res, next) => {
  upload.single("file")(req, res, err => {
    if (err) {
      const message = err.code === "LIMIT_FILE_SIZE" ? "That file exceeds the upload limit for this server." : err.message;
      return res.status(400).json({ error: message });
    }
    next();
  });
}, (req, res) => {
  const title = String(req.body.title || "").trim().slice(0, 80);
  const description = String(req.body.description || "").trim().slice(0, 1500);
  const category = String(req.body.category || "Other");
  const platform = String(req.body.platform || "");
  const version = String(req.body.version || "1.0").trim().slice(0, 30);
  if (!title || title.length < 2 || !description || description.length < 10) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "Add a title and a description of at least 10 characters." });
  }
  if (!["Games","Education","Productivity","Entertainment","Tools","Other"].includes(category) || !["android","pc","browser","other"].includes(platform)) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "Choose a valid category and platform." });
  }
  if (!req.file) return res.status(400).json({ error: "Choose a file to upload." });
  if (req.file.size > maxByPlatform[platform]) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "This file exceeds the size limit for the selected platform." });
  }
  const userId = req.session.userId;
  // Developers may submit any number of projects. Per-file size limits and moderation still apply.
  const paymentStatus = "not_required";
  const status = "pending";
  const result = db.prepare(`INSERT INTO projects (user_id,title,description,category,platform,version,file_name,original_name,file_size,mime_type,status,payment_status,fee_etb)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(userId,title,description,category,platform,version,req.file.filename,path.basename(req.file.originalname).slice(0,180),req.file.size,req.file.mimetype,status,paymentStatus,0);
  res.json({
    ok: true, projectId: Number(result.lastInsertRowid),
    message: "Project submitted successfully. It is waiting for admin review before it appears publicly."
  });
});
app.get("/api/my/projects", requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT p.*, u.username FROM projects p JOIN users u ON u.id=p.user_id WHERE p.user_id=? ORDER BY p.created_at DESC`).all(req.session.userId);
  const publishedCount = db.prepare("SELECT COUNT(*) AS n FROM projects WHERE user_id=? AND status='approved'").get(req.session.userId).n;
  res.json({ projects: rows.map(safeProject), publishedCount, freeSlotsRemaining: null });
});
app.get("/api/download/:id", (req, res) => {
  const project = db.prepare("SELECT * FROM projects WHERE id=? AND status='approved'").get(Number(req.params.id));
  if (!project) return res.status(404).send("This download is unavailable.");
  const filePath = path.join(UPLOAD_DIR, path.basename(project.file_name));
  if (!fs.existsSync(filePath)) return res.status(404).send("The file is missing from storage.");
  db.prepare("UPDATE projects SET downloads=downloads+1 WHERE id=?").run(project.id);
  res.download(filePath, path.basename(project.original_name));
});
app.post("/api/projects/:id/reviews", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const project = db.prepare("SELECT id FROM projects WHERE id=? AND status='approved'").get(id);
  if (!project) return res.status(404).json({ error: "Project not found." });
  const rating = Number(req.body.rating);
  const comment = String(req.body.comment || "").trim().slice(0, 500);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: "Choose a rating from 1 to 5." });
  try {
    db.prepare("INSERT INTO reviews (project_id,user_id,rating,comment) VALUES (?,?,?,?)").run(id,req.session.userId,rating,comment);
    res.json({ ok: true });
  } catch {
    res.status(409).json({ error: "You have already reviewed this project." });
  }
});
app.post("/api/projects/:id/report", (req, res) => {
  const id = Number(req.params.id);
  const project = db.prepare("SELECT id FROM projects WHERE id=? AND status='approved'").get(id);
  if (!project) return res.status(404).json({ error: "Project not found." });
  const reason = String(req.body.reason || "").trim().slice(0, 300);
  if (reason.length < 5) return res.status(400).json({ error: "Please explain the reason for your report." });
  db.prepare("INSERT INTO reports (project_id,user_id,reason) VALUES (?,?,?)").run(id, currentUser(req)?.id || null, reason);
  res.json({ ok: true });
});

app.get("/api/admin/overview", requireAdmin, (_req, res) => {
  res.json({
    projects: db.prepare(`SELECT p.*,u.username,u.email FROM projects p JOIN users u ON u.id=p.user_id WHERE p.status!='approved' ORDER BY p.created_at ASC`).all(),
    reports: db.prepare(`SELECT r.*,p.title,u.username FROM reports r JOIN projects p ON p.id=r.project_id LEFT JOIN users u ON u.id=r.user_id WHERE r.status='open' ORDER BY r.created_at DESC`).all(),
    stats: {
      users: db.prepare("SELECT COUNT(*) AS n FROM users WHERE role!='admin'").get().n,
      published: db.prepare("SELECT COUNT(*) AS n FROM projects WHERE status='approved'").get().n,
      pending: db.prepare("SELECT COUNT(*) AS n FROM projects WHERE status IN ('pending','awaiting_payment')").get().n
    }
  });
});
app.post("/api/admin/projects/:id/approve", requireAdmin, (req, res) => {
  const p = db.prepare("SELECT * FROM projects WHERE id=?").get(Number(req.params.id));
  if (!p) return res.status(404).json({ error: "Project not found." });
  if (p.payment_status === "required" && p.payment_status !== "paid") return res.status(400).json({ error: "Verify the upload fee first." });
  db.prepare("UPDATE projects SET status='approved' WHERE id=?").run(p.id);
  res.json({ ok: true });
});
app.post("/api/admin/projects/:id/paid", requireAdmin, (req, res) => {
  const p = db.prepare("SELECT * FROM projects WHERE id=?").get(Number(req.params.id));
  if (!p) return res.status(404).json({ error: "Project not found." });
  db.prepare("UPDATE projects SET payment_status='paid',status='pending' WHERE id=?").run(p.id);
  res.json({ ok: true });
});
app.post("/api/admin/projects/:id/reject", requireAdmin, (req, res) => {
  const p = db.prepare("SELECT * FROM projects WHERE id=?").get(Number(req.params.id));
  if (!p) return res.status(404).json({ error: "Project not found." });
  db.prepare("UPDATE projects SET status='rejected' WHERE id=?").run(p.id);
  res.json({ ok: true });
});
app.post("/api/admin/reports/:id/close", requireAdmin, (req, res) => {
  db.prepare("UPDATE reports SET status='closed' WHERE id=?").run(Number(req.params.id));
  res.json({ ok: true });
});

app.get("*", (_req, res) => res.sendFile(path.join(ROOT, "public", "index.html")));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Something went wrong. Please try again." });
});

app.listen(PORT, () => console.log(`Nebbedin Store running on http://localhost:${PORT}`));
