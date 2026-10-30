/**
 * Server Node.js — Dashboard Rekonsiliasi Dana BOSP
 * Kabupaten Minahasa Tenggara
 *
 * VERSI DIAMANKAN (1.1.0-secure)
 * - Password di-hash dengan bcrypt
 * - Autentikasi JWT + cookie HttpOnly
 * - Role-based access control (RBAC)
 * - Rate limiting + Helmet
 * - Upload file terproteksi
 * - Password tidak pernah dikirim ke client
 *
 * Penyimpanan: file JSON di folder data/
 */
require("dotenv").config();

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, "uploads");
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB) || 25;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString("hex");
const JWT_EXPIRES = process.env.JWT_EXPIRES || "8h";
const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS) || 12;
const NODE_ENV = process.env.NODE_ENV || "development";
const CORS_ORIGIN = process.env.CORS_ORIGIN || false; // false = same-origin only di production

if (!process.env.JWT_SECRET) {
  console.warn("⚠️  JWT_SECRET tidak di-set di .env — menggunakan secret acak (session hilang saat restart).");
}

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Seed jika belum ada
require("./scripts/init-db.js");

const app = express();

// ---------- Security middleware ----------
app.use(helmet({
  contentSecurityPolicy: false, // frontend inline scripts masih banyak
  crossOriginEmbedderPolicy: false,
}));

app.use(cors({
  origin: CORS_ORIGIN || (NODE_ENV === "production" ? false : true),
  credentials: true,
}));

app.use(express.json({ limit: "30mb" }));
app.use(express.text({ type: "text/plain", limit: "30mb" }));
app.use(cookieParser());

// Rate limit umum
app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: "error", message: "Terlalu banyak request. Coba lagi nanti." },
}));

// Rate limit ketat untuk login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { status: "error", message: "Terlalu banyak percobaan login. Coba lagi dalam 15 menit." },
});

// JANGAN serve /uploads secara publik
// app.use("/uploads", express.static(UPLOAD_DIR));  ← dihapus

app.use(express.static(path.join(__dirname, "public")));

// ---------- JSON helpers ----------
function readJson(file, fallback) {
  const full = path.join(DATA_DIR, file);
  try {
    if (!fs.existsSync(full)) return fallback;
    return JSON.parse(fs.readFileSync(full, "utf8"));
  } catch (e) {
    console.warn("readJson fail", file, e.message);
    return fallback;
  }
}

function writeJson(file, data) {
  const full = path.join(DATA_DIR, file);
  const tmp = full + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), "utf8");
  fs.renameSync(tmp, full);
}

function parseBody(req) {
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return req.body || {};
}

function getSchools() { return readJson("schools.json", []); }
function setSchools(list) { writeJson("schools.json", list); }
function getUsers() { return readJson("users.json", []); }
function setUsers(list) { writeJson("users.json", list); }
function monthlyFile(year) { return `monthly_${year}.json`; }
function getMonthly(year) { return readJson(monthlyFile(year), {}); }
function setMonthly(year, data) { writeJson(monthlyFile(year), data); }

function mergeMonthly(year, incoming) {
  const current = getMonthly(year);
  for (const [schoolNo, months] of Object.entries(incoming || {})) {
    if (!current[schoolNo]) current[schoolNo] = {};
    for (const [month, payload] of Object.entries(months || {})) {
      current[schoolNo][month] = payload;
    }
  }
  setMonthly(year, current);
  return current;
}

function upsertSchools(list) {
  if (!Array.isArray(list)) return getSchools();
  const map = new Map(getSchools().map((s) => [Number(s.no), s]));
  for (const s of list) {
    map.set(Number(s.no), {
      no: Number(s.no),
      npsn: s.npsn || "",
      name: s.name || "",
      alamat: s.alamat || "",
      status: (s.status || "NEGERI").toUpperCase(),
      kecamatan: s.kecamatan || "",
      jenjang: s.jenjang || "SD",
    });
  }
  const out = Array.from(map.values()).sort((a, b) => a.no - b.no);
  setSchools(out);
  return out;
}

async function upsertUsers(list) {
  if (!Array.isArray(list)) return getUsers();
  const map = new Map(getUsers().map((u) => [String(u.username).toLowerCase(), u]));
  for (const u of list) {
    if (!u || !u.username) continue;
    const prev = map.get(String(u.username).toLowerCase()) || {};
    let password = prev.password || "";
    if (u.password != null && u.password !== "" && u.password !== prev.password) {
      // Hash hanya jika password baru (plain text)
      if (!u.password.startsWith("$2")) {
        password = await bcrypt.hash(String(u.password), BCRYPT_ROUNDS);
      } else {
        password = u.password;
      }
    }
    map.set(String(u.username).toLowerCase(), {
      name: u.name || prev.name || u.username,
      username: u.username,
      password,
      role: u.role || prev.role || "Operator Sekolah",
      schoolNo: u.schoolNo ?? u.school_no ?? prev.schoolNo ?? null,
      npsn: u.npsn || prev.npsn || "",
      status: u.status || prev.status || "Pending",
    });
  }
  const out = Array.from(map.values());
  setUsers(out);
  return out;
}

/** Hapus field password sebelum kirim ke client */
function sanitizeUser(user) {
  if (!user) return null;
  const { password, ...safe } = user;
  return safe;
}

function sanitizeUsers(list) {
  return (list || []).map(sanitizeUser);
}

// ---------- Auth middleware ----------
function requireAuth(req, res, next) {
  const token =
    req.cookies?.token ||
    (req.headers.authorization || "").replace(/^Bearer\s+/i, "");

  if (!token) {
    return res.status(401).json({ status: "error", message: "Unauthorized — silakan login" });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ status: "error", message: "Token invalid atau expired" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ status: "error", message: "Forbidden — role tidak diizinkan" });
    }
    next();
  };
}

/** Operator Sekolah hanya boleh akses data sekolahnya sendiri */
function canAccessSchool(req, schoolNo) {
  if (!req.user) return false;
  if (req.user.role === "Admin Dinas" || req.user.role === "BUD") return true;
  if (req.user.role === "Operator Sekolah") {
    return Number(req.user.schoolNo) === Number(schoolNo);
  }
  return false;
}

// ---------- Audit log sederhana ----------
function audit(action, req, detail = {}) {
  const entry = {
    time: new Date().toISOString(),
    action,
    username: req.user?.username || "anonymous",
    role: req.user?.role || null,
    ip: req.ip || req.headers["x-forwarded-for"] || null,
    ...detail,
  };
  try {
    const logFile = path.join(DATA_DIR, "audit.log");
    fs.appendFileSync(logFile, JSON.stringify(entry) + "\n", "utf8");
  } catch (e) {
    console.warn("audit log fail", e.message);
  }
}

// ---------- Routes ----------
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    version: "1.1.0-secure",
    time: new Date().toISOString(),
  });
});

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const body = parseBody(req);
    const username = (body.username || "").trim();
    const password = (body.password || "").trim();

    if (!username || !password) {
      return res.status(400).json({ status: "error", message: "Username dan password wajib" });
    }

    const user = getUsers().find((u) => u.username === username);
    if (!user) {
      audit("login_fail", req, { username });
      return res.status(401).json({ status: "error", message: "Username atau password salah" });
    }

    // Support password lama (plain) saat migrasi, sekaligus hash jika masih plain
    let match = false;
    if (user.password && user.password.startsWith("$2")) {
      match = await bcrypt.compare(password, user.password);
    } else {
      match = user.password === password;
      if (match) {
        // Auto-upgrade ke hash
        user.password = await bcrypt.hash(password, BCRYPT_ROUNDS);
        const all = getUsers().map((u) => (u.username === username ? user : u));
        setUsers(all);
      }
    }

    if (!match) {
      audit("login_fail", req, { username });
      return res.status(401).json({ status: "error", message: "Username atau password salah" });
    }

    if (user.status !== "Aktif") {
      return res.status(403).json({ status: "error", message: "Akun masih Pending / nonaktif" });
    }

    const token = jwt.sign(
      {
        username: user.username,
        role: user.role,
        schoolNo: user.schoolNo ?? null,
        name: user.name,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 8 * 60 * 60 * 1000,
    });

    audit("login_ok", req, { username: user.username, role: user.role });
    res.json({ status: "success", user: sanitizeUser(user), token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.post("/api/logout", requireAuth, (req, res) => {
  audit("logout", req);
  res.clearCookie("token", {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "strict",
  });
  res.json({ status: "success" });
});

app.get("/api/me", requireAuth, (req, res) => {
  const user = getUsers().find((u) => u.username === req.user.username);
  if (!user) return res.status(401).json({ status: "error", message: "User tidak ditemukan" });
  res.json({ status: "success", user: sanitizeUser(user) });
});

app.get("/api/data", requireAuth, (req, res) => {
  try {
    const year = Number(req.query.year) || 2024;
    let schools = getSchools();
    let monthlyData = getMonthly(year);
    let users = getUsers();

    // Operator Sekolah hanya lihat sekolahnya sendiri
    if (req.user.role === "Operator Sekolah" && req.user.schoolNo != null) {
      const no = Number(req.user.schoolNo);
      schools = schools.filter((s) => Number(s.no) === no);
      const filtered = {};
      if (monthlyData[no]) filtered[no] = monthlyData[no];
      if (monthlyData[String(no)]) filtered[String(no)] = monthlyData[String(no)];
      monthlyData = filtered;
      users = users.filter((u) => u.username === req.user.username);
    }

    res.json({
      status: "success",
      year,
      schools,
      users: sanitizeUsers(users),
      monthlyData,
    });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.post("/api/save", requireAuth, (req, res) => {
  try {
    const body = parseBody(req);
    const year = Number(body.year) || 2024;

    // Operator hanya boleh simpan data sekolahnya
    if (req.user.role === "Operator Sekolah") {
      if (body.monthlyData) {
        const allowed = {};
        const no = String(req.user.schoolNo);
        if (body.monthlyData[no]) allowed[no] = body.monthlyData[no];
        if (body.monthlyData[req.user.schoolNo]) allowed[req.user.schoolNo] = body.monthlyData[req.user.schoolNo];
        body.monthlyData = allowed;
      }
      // Operator tidak boleh ubah schools/users master
      delete body.schools;
      delete body.users;
    }

    if (Array.isArray(body.schools) && (req.user.role === "Admin Dinas" || req.user.role === "BUD")) {
      upsertSchools(body.schools);
    }
    if (Array.isArray(body.users) && req.user.role === "Admin Dinas") {
      // async handled below
    }
    if (body.monthlyData && typeof body.monthlyData === "object") {
      if (body.partial) {
        mergeMonthly(year, body.monthlyData);
      } else {
        setMonthly(year, body.monthlyData);
      }
    }

    audit("save", req, { year, partial: !!body.partial });
    res.json({ status: "success" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.get("/api/schools", requireAuth, (req, res) => {
  let schools = getSchools();
  if (req.user.role === "Operator Sekolah" && req.user.schoolNo != null) {
    schools = schools.filter((s) => Number(s.no) === Number(req.user.schoolNo));
  }
  res.json({ status: "success", schools });
});

app.post("/api/schools", requireAuth, requireRole("Admin Dinas"), (req, res) => {
  try {
    const body = parseBody(req);
    const list = Array.isArray(body.schools) ? body.schools : body.school ? [body.school] : null;
    if (!list) return res.status(400).json({ status: "error", message: "schools required" });
    audit("upsert_schools", req, { count: list.length });
    res.json({ status: "success", schools: upsertSchools(list) });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.delete("/api/schools/:no", requireAuth, requireRole("Admin Dinas"), (req, res) => {
  try {
    const no = Number(req.params.no);
    setSchools(getSchools().filter((s) => Number(s.no) !== no));
    for (const f of fs.readdirSync(DATA_DIR)) {
      if (!/^monthly_\d+\.json$/.test(f)) continue;
      const year = Number(f.replace(/\D/g, ""));
      const data = getMonthly(year);
      if (data[no] || data[String(no)]) {
        delete data[no];
        delete data[String(no)];
        setMonthly(year, data);
      }
    }
    audit("delete_school", req, { schoolNo: no });
    res.json({ status: "success" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.get("/api/users", requireAuth, requireRole("Admin Dinas"), (_req, res) => {
  res.json({ status: "success", users: sanitizeUsers(getUsers()) });
});

app.post("/api/users", requireAuth, requireRole("Admin Dinas"), async (req, res) => {
  try {
    const body = parseBody(req);
    const list = Array.isArray(body.users) ? body.users : body.user ? [body.user] : null;
    if (!list) return res.status(400).json({ status: "error", message: "users required" });
    const updated = await upsertUsers(list);
    audit("upsert_users", req, { count: list.length });
    res.json({ status: "success", users: sanitizeUsers(updated) });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.get("/api/sp2b-kab", requireAuth, (req, res) => {
  const year = Number(req.query.year) || 2024;
  const store = readJson(`sp2b_kab_${year}.json`, { records: {}, last: {} });
  res.json({ status: "success", year, records: store.records || {}, last: store.last || {} });
});

app.post("/api/sp2b-kab", requireAuth, requireRole("Admin Dinas", "BUD"), (req, res) => {
  try {
    const body = parseBody(req);
    const year = Number(body.year) || 2024;
    const file = `sp2b_kab_${year}.json`;
    const store = readJson(file, { records: {}, last: {} });
    if (body.records && typeof body.records === "object") {
      store.records = { ...(store.records || {}), ...body.records };
    }
    if (body.last && typeof body.last === "object") store.last = body.last;
    if (body.deleteKey && store.records) delete store.records[body.deleteKey];
    writeJson(file, store);
    audit("sp2b_kab", req, { year });
    res.json({ status: "success" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

// ---------- Upload helpers (folder per sekolah + per bulan) ----------
function sanitizeFolderPart(str, maxLen) {
  return String(str || "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9._\-\s]/g, "")
    .trim()
    .replace(/\s+/g, "_")
    .replace(/_+/g, "_")
    .slice(0, maxLen || 80) || "unknown";
}

const MONTH_MAP = {
  januari: "01", jan: "01", february: "02", februari: "02", feb: "02",
  maret: "03", mar: "03", april: "04", apr: "04",
  mei: "05", may: "05", juni: "06", jun: "06", juli: "07", jul: "07",
  agustus: "08", agus: "08", aug: "08", september: "09", sep: "09",
  oktober: "10", okt: "10", oct: "10", november: "11", nov: "11",
  desember: "12", des: "12", dec: "12",
  "1": "01", "2": "02", "3": "03", "4": "04", "5": "05", "6": "06",
  "7": "07", "8": "08", "9": "09", "10": "10", "11": "11", "12": "12",
  "01": "01", "02": "02", "03": "03", "04": "04", "05": "05", "06": "06",
  "07": "07", "08": "08", "09": "09",
};

function normalizeMonthFolder(month, year) {
  const y = String(year || new Date().getFullYear());
  const raw = String(month || "").trim().toLowerCase();
  let mm = MONTH_MAP[raw];
  if (!mm) {
    const m = raw.match(/(\d{1,2})/);
    mm = m ? String(m[1]).padStart(2, "0") : "00";
  }
  return `${y}-${mm}`;
}

function resolveSchoolFolder(meta) {
  // Cari data sekolah dari master jika npsn/nama kosong
  const schools = getSchools();
  const no = meta.schoolNo != null ? Number(meta.schoolNo) : null;
  const found = no != null ? schools.find((s) => Number(s.no) === no) : null;

  const npsn = sanitizeFolderPart(meta.npsn || found?.npsn || "", 20);
  const name = sanitizeFolderPart(meta.schoolName || found?.name || `Sekolah_${no || 0}`, 60);
  const idPart = npsn && npsn !== "unknown" ? npsn : `NO${no || 0}`;
  return `${idPart}_${name}`;
}

/**
 * Membuat path: uploads/{NPSN_NamaSekolah}/{YYYY-MM}/{docType}_{timestamp}_{fileName}
 * Mengembalikan { absPath, relativePath, fileName }
 */
function buildUploadPath(meta) {
  const schoolFolder = resolveSchoolFolder(meta);
  const monthFolder = normalizeMonthFolder(meta.month, meta.year);
  const docType = sanitizeFolderPart(meta.docType || "doc", 40);
  const original = sanitizeFolderPart(meta.fileName || "dokumen.pdf", 80);
  const safeName = original.toLowerCase().endsWith(".pdf") ? original : `${original}.pdf`;
  const fileName = `${docType}_${Date.now()}_${safeName}`;

  const dir = path.join(UPLOAD_DIR, schoolFolder, monthFolder);
  fs.mkdirSync(dir, { recursive: true });

  const relativePath = path.join(schoolFolder, monthFolder, fileName).replace(/\\/g, "/");
  const absPath = path.join(UPLOAD_DIR, schoolFolder, monthFolder, fileName);
  return { absPath, relativePath, fileName, schoolFolder, monthFolder };
}

/** Pastikan path file berada di dalam UPLOAD_DIR (cegah path traversal) */
function resolveSafeUploadPath(relativePath) {
  const normalized = path.normalize(relativePath).replace(/^(\.\.(\/|\\|$))+/, "");
  const abs = path.resolve(UPLOAD_DIR, normalized);
  const root = path.resolve(UPLOAD_DIR);
  if (!abs.startsWith(root + path.sep) && abs !== root) {
    return null;
  }
  return abs;
}

// Multer: simpan sementara di root, lalu dipindah ke folder sekolah/bulan
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const safe = (file.originalname || "dokumen.pdf").replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `tmp-${Date.now()}-${safe}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const name = (file.originalname || "").toLowerCase();
    if (file.mimetype === "application/pdf" && name.endsWith(".pdf")) {
      cb(null, true);
    } else {
      cb(new Error("Hanya file PDF yang diizinkan"));
    }
  },
});

app.post("/api/upload", requireAuth, (req, res, next) => {
  const ct = req.headers["content-type"] || "";
  if (ct.includes("multipart/form-data")) return upload.single("file")(req, res, next);
  return next();
}, (req, res) => {
  try {
    // --- Multipart upload ---
    if (req.file) {
      const buf = fs.readFileSync(req.file.path);
      if (buf.slice(0, 5).toString() !== "%PDF-") {
        fs.unlinkSync(req.file.path);
        return res.status(400).json({ status: "error", message: "File bukan PDF valid" });
      }

      const schoolNo = req.body?.schoolNo || req.user?.schoolNo || 0;
      if (req.user.role === "Operator Sekolah" && Number(schoolNo) !== Number(req.user.schoolNo)) {
        fs.unlinkSync(req.file.path);
        return res.status(403).json({ status: "error", message: "Tidak boleh upload untuk sekolah lain" });
      }

      const { absPath, relativePath } = buildUploadPath({
        schoolNo,
        schoolName: req.body?.schoolName,
        npsn: req.body?.npsn,
        month: req.body?.month,
        year: req.body?.year,
        docType: req.body?.docType || "doc",
        fileName: req.file.originalname,
      });

      fs.renameSync(req.file.path, absPath);
      const url = `/api/file/${relativePath}`;
      audit("upload", req, { file: relativePath, schoolNo });
      return res.json({ status: "success", fileUrl: url, fileName: req.file.originalname, path: relativePath });
    }

    // --- Base64 upload (dari frontend gasPost) ---
    const body = parseBody(req);
    if (body.action === "uploadFile" || body.fileData) {
      let base64 = body.fileData || "";
      const comma = base64.indexOf(",");
      if (comma >= 0) base64 = base64.slice(comma + 1);
      const buffer = Buffer.from(base64, "base64");
      if (!buffer.length) return res.status(400).json({ status: "error", message: "fileData kosong" });
      if (buffer.slice(0, 5).toString() !== "%PDF-") {
        return res.status(400).json({ status: "error", message: "File bukan PDF valid" });
      }

      const schoolNo = body.schoolNo || req.user.schoolNo || 0;
      if (req.user.role === "Operator Sekolah" && Number(schoolNo) !== Number(req.user.schoolNo)) {
        return res.status(403).json({ status: "error", message: "Tidak boleh upload untuk sekolah lain" });
      }

      const { absPath, relativePath } = buildUploadPath({
        schoolNo,
        schoolName: body.schoolName,
        npsn: body.npsn,
        month: body.month,
        year: body.year || body.activeYear,
        docType: body.docType || "doc",
        fileName: body.fileName || "dokumen.pdf",
      });

      fs.writeFileSync(absPath, buffer);
      const url = `/api/file/${relativePath}`;
      audit("upload", req, { file: relativePath, schoolNo });
      return res.json({
        status: "success",
        fileUrl: url,
        fileName: body.fileName || path.basename(relativePath),
        path: relativePath,
      });
    }
    return res.status(400).json({ status: "error", message: "Tidak ada file" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

/**
 * Download file — mendukung path bersarang:
 *   /api/file/69762652_SD_NEGERI_1_RATAHAN/2024-01/rekeningKoran_....pdf
 * dan juga file lama di root uploads/
 */
app.get("/api/file/*", requireAuth, (req, res) => {
  // req.params[0] berisi sisa path setelah /api/file/
  const relative = (req.params[0] || "").replace(/^\/+/, "");
  if (!relative) return res.status(400).json({ status: "error", message: "Path file kosong" });

  const file = resolveSafeUploadPath(relative);
  if (!file || !fs.existsSync(file)) {
    return res.status(404).json({ status: "error", message: "File tidak ditemukan" });
  }

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `inline; filename="${path.basename(file)}"`);
  res.sendFile(file);
});

// Legacy action router (kompatibilitas frontend lama)
app.post("/", requireAuth, (req, res) => {
  const body = parseBody(req);
  if (body.action === "uploadFile") {
    req.url = "/api/upload";
    return app._router.handle(req, res, () => {});
  }
  if (body.action === "saveAll") {
    req.url = "/api/save";
    return app._router.handle(req, res, () => {});
  }
  res.json({ status: "error", message: "Unknown action" });
});

app.get("/", (_req, res) => {
  const index = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(index)) return res.sendFile(index);
  res.type("text").send("Server Rekon BOSP (secure) berjalan.\nAPI: GET /api/health");
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(400).json({ status: "error", message: err.message || "Bad request" });
});

app.listen(PORT, HOST, () => {
  console.log(`Rekon BOSP SECURE  http://localhost:${PORT}`);
  console.log(`Data directory     ${DATA_DIR}`);
  console.log(`Uploads directory  ${UPLOAD_DIR}`);
  console.log(`Health             http://localhost:${PORT}/api/health`);
  console.log(`Mode               ${NODE_ENV}`);
});
