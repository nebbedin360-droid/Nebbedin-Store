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

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "uploads");
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
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use(express.static(path.join(ROOT, "public")));
app.use("/uploads", (req, res, next) => {
  // Files are intentionally not exposed as a public static directory.
  res.status(404).send("Not found");
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

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
    feeEtb: Number(process.env.EXTRA_UPLOAD_FEE_ETB || 100),
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
  try {
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users (username,email,password_hash) VALUES (?,?,?)").run(username, email, hash);
    req.session.userId = Number(info.lastInsertRowid);
    res.json({ ok: true, user: currentUser(req) });
  } catch (e) {
    res.status(409).json({ error: "That username or email is already registered." });
  }
});
app.post("/api/login", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Email or password is incorrect." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "Could not start your session." });
    req.session.userId = user.id;
    res.json({ ok: true, user: { id: user.id, username: user.username, email: user.email, role: user.role, bio: user.bio } });
  });
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
  // Count all prior submissions so repeated pending/rejected uploads cannot bypass the free-upload policy.
  const uploadCount = db.prepare("SELECT COUNT(*) AS n FROM projects WHERE user_id=?").get(userId).n;
  const publishedCount = db.prepare("SELECT COUNT(*) AS n FROM projects WHERE user_id=? AND status='approved'").get(userId).n;
  const pendingCount = db.prepare("SELECT COUNT(*) AS n FROM projects WHERE user_id=? AND status IN ('pending','awaiting_payment')").get(userId).n;
  if (publishedCount + pendingCount >= 20) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: "To protect storage, each developer can have up to 20 published or pending projects in this MVP." });
  }
  const fee = Number(process.env.EXTRA_UPLOAD_FEE_ETB || 100);
  const paymentStatus = uploadCount < 2 ? "not_required" : "required";
  const status = paymentStatus === "required" ? "awaiting_payment" : "pending";
  const result = db.prepare(`INSERT INTO projects (user_id,title,description,category,platform,version,file_name,original_name,file_size,mime_type,status,payment_status,fee_etb)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(userId,title,description,category,platform,version,req.file.filename,path.basename(req.file.originalname).slice(0,180),req.file.size,req.file.mimetype,status,paymentStatus,paymentStatus==="required"?fee:0);
  res.json({
    ok: true, projectId: Number(result.lastInsertRowid),
    message: paymentStatus === "required"
      ? `Upload received. The ${fee} ETB fee must be verified by an administrator before moderation. This demo does not collect payments automatically.`
      : "Upload received. It is waiting for admin review before it appears publicly."
  });
});
app.get("/api/my/projects", requireAuth, (req, res) => {
  const rows = db.prepare(`SELECT p.*, u.username FROM projects p JOIN users u ON u.id=p.user_id WHERE p.user_id=? ORDER BY p.created_at DESC`).all(req.session.userId);
  const publishedCount = db.prepare("SELECT COUNT(*) AS n FROM projects WHERE user_id=? AND status='approved'").get(req.session.userId).n;
  res.json({ projects: rows.map(safeProject), publishedCount, freeSlotsRemaining: Math.max(0, 2-publishedCount) });
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
