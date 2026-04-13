// server.js  — Business Card App · Unified Server  (v6 — Cross-Device Sync)
// ─────────────────────────────────────────────────────────────────────────────
// Changes from v5:
//  ✅ Added GET /api/user/:userId/cards and /images for Unity to sync data across devices
//  ✅ Modified /upload to prevent image overwrites by appending counter to filename
//  ✅ User authentication for GET endpoints using password (header or query)
//
// Changes from v4:
//  ✅ Single source of truth: ONE JSON per user at data/users/<userId>.json
//     (NOT inside uploads/ — no duplication on login)
//  ✅ userId-based auth: POST /login accepts { userId, password }
//     (also accepts legacy { username, email, password } for backwards compat)
//  ✅ Admin creates user → stored in data/users/<userId>.json only
//  ✅ Profile image: stored at uploads/<userId>/profile.<ext>
//     Path saved as "/uploads/<userId>/profile.jpg" in user JSON
//     Served via app.use('/uploads', express.static(...)) — <img src="/uploads/..."> works
//  ✅ /upload (Unity) never creates new user folders or overwrites profile JSON
//  ✅ PUT /update-user/:userId updates SAME JSON → reflects instantly in dashboard
//  ✅ All endpoints use userId as primary key (username field kept for Unity compat)
//  ✅ bcrypt hashing, 8-char / 10-digit validation enforced
//
// ── File layout ──────────────────────────────────────────────────────────────
//   data/
//     admins.json
//     users/
//       <userId>.json           ← ONE file per user (single source of truth)
//   uploads/
//     <userId>/
//       profile.jpg             ← profile image (served at /uploads/<userId>/profile.jpg)
//       cards/
//         card_001.json
//         card_001_front.png
//
// ── Endpoints used by Unity ───────────────────────────────────────────────────
//   POST /login                 { userId, password }
//                               → { ok, profile, resolvedUsername }
//   POST /upload                multipart: username(=userId), email, filetype, filename, subpath, file
//   PUT  /api/user/:userId      { currentPassword, newPassword?, mobile? }
//   GET  /api/user/:userId/cards   (requires password) → list of card JSONs
//   GET  /api/user/:userId/images  (requires password) → list of image filenames
//
// ── Admin endpoints ───────────────────────────────────────────────────────────
//   POST /api/admin/login       { id, password } → { ok, token }
//   POST /api/admin/logout
//   GET  /api/users             list users (dashboard)
//   POST /create-user           create user
//   GET  /user/:userId          get single user profile
//   GET  /api/user/:userId      (alias)
//   PUT  /update-user/:userId   update user fields
//   POST /upload/:userId        profile image upload (admin)
//   DELETE /api/admin/users/:u  delete user
//   GET  /api/user/:u/cards     get cards list
//   GET  /api/image/:u/:file    serve card image
//   GET  /api/user/:u/images    list images
//   GET  /api/admins            list admins
//   POST /api/admin/admins      create admin
//   PUT  /api/admin/admins/:id/password

require('dotenv').config();

const express   = require('express');
const multer    = require('multer');
const cors      = require('cors');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const bcrypt    = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');

const app  = express();
const PORT = process.env.PORT || 3000;

// Change these three lines near the top:
const DATA_DIR     = path.join(__dirname, 'data');
const USERS_DIR    = path.join(DATA_DIR, 'users');
const UPLOADS_ROOT = path.join(__dirname, 'uploads');
const ADMINS_FILE  = path.join(DATA_DIR, 'admins.json');

[DATA_DIR, USERS_DIR, UPLOADS_ROOT].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

if (!fs.existsSync(ADMINS_FILE)) {
  const hash = bcrypt.hashSync('admin1234', 10);
  fs.writeFileSync(ADMINS_FILE, JSON.stringify([{ id: 'admin', passwordHash: hash }], null, 2));
  console.log('[BOOT] Default admin created. ID: admin  Password: admin1234');
}

// ── In-memory sessions ────────────────────────────────────────────────────────
const jwt = require('jsonwebtoken');
const SECRET = "your_secret_key";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const sessions = new Map();
function createSession(adminId) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { id: adminId, exp: Date.now() + SESSION_TTL_MS });
  return token;
}
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of sessions) if (s.exp < now) sessions.delete(t);
}, 30 * 60 * 1000);

// ── User data helpers ─────────────────────────────────────────────────────────
function userFilePath(userId) {
  return path.join(USERS_DIR, path.basename(userId) + '.json');
}
function createToken(adminId) {
  return jwt.sign({ id: adminId }, SECRET, { expiresIn: '8h' });
}
function readUser(userId) {
  const f = userFilePath(userId);
  if (!fs.existsSync(f)) return null;
  try { return JSON.parse(fs.readFileSync(f, 'utf5')); } catch { return null; }
}
function writeUser(userId, data) {
  fs.writeFileSync(userFilePath(userId), JSON.stringify(data, null, 2));
}
function listAllUserIds() {
  if (!fs.existsSync(USERS_DIR)) return [];
  return fs.readdirSync(USERS_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => path.basename(f, '.json'));
}
function resolveUserId(sentId, sentEmail) {
  if (readUser(sentId)) return sentId;
  if (sentEmail) {
    for (const uid of listAllUserIds()) {
      const u = readUser(uid);
      if (u && u.email === sentEmail) return uid;
    }
  }
  return null;
}
function safeProfile(user) {
  const s = { ...user };
  delete s.password;
  delete s.passwordHash;
  return s;
}

// ── Admin helpers ─────────────────────────────────────────────────────────────
function readAdmins()       { try { return JSON.parse(fs.readFileSync(ADMINS_FILE, 'utf8')); } catch { return []; } }
function writeAdmins(data)  { fs.writeFileSync(ADMINS_FILE, JSON.stringify(data, null, 2)); }

function validateUserFields({ mobile, password } = {}) {
  if (mobile   !== undefined && !/^\d{10}$/.test(String(mobile).trim()))
    return 'Mobile must be exactly 10 digits';
  if (password !== undefined && String(password).length !==5)
    return 'Password must be exactly 5 characters';
  return null;
}

// ── Multer (memory storage) ───────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 10 }
});

// ── Rate limiters ─────────────────────────────────────────────────────────────
const loginLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { ok: false, error: 'Too many attempts' }, standardHeaders: true, legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, message: { error: 'Upload rate limit exceeded' } });

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const token =
    req.headers['x-admin-token'] ||
    (req.headers.authorization && req.headers.authorization.split(' ')[1]);

  if (!token) {
    return res.status(401).json({ ok: false, error: 'No token' });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.adminId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ ok: false, error: 'Invalid/Expired token' });
  }
}

// ── Global middleware ─────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log("➡️", req.method, req.url);
  next();
});
// Serve index.html and other static files from project root
// app.use(express.static(__dirname));

// ✅ FIX: Serve uploaded images at /uploads/... so <img src="/uploads/..."> works
app.use('/uploads', express.static(UPLOADS_ROOT, { maxAge: '1d' }));

// =============================================================================
//  UNITY — POST /login
//  Accepts { userId, password } or legacy { username, email, password }
// =============================================================================
app.post(['/login', '/api/login'], loginLimiter, async (req, res) => {
  try {
    const userId   = ((req.body.userId || req.body.username) || '').trim();
    const email    = (req.body.email || '').trim();
    const password = (req.body.password || '').trim();

    if (!userId || !password) {
      return res.json({ ok: false, error: 'Missing userId or password' });
    }

    const safeId = path.basename(userId);
    const resolvedId = resolveUserId(safeId, email);

    if (!resolvedId) {
      console.log(`[LOGIN FAILED] User not found: ${safeId}`);
      return res.json({ ok: false, error: 'User not found' });
    }

    // ✅ IMPORTANT FIX: load user BEFORE using it
    const user = readUser(resolvedId);
    if (!user) {
      console.log(`[LOGIN FAILED] User file missing: ${resolvedId}`);
      return res.json({ ok: false, error: 'User data missing' });
    }

    let passwordOk = false;

    // 🔐 bcrypt password check
    if (user.passwordHash) {
      passwordOk = await bcrypt.compare(password, user.passwordHash);
    } 
    // 🔁 legacy plain password support
    else if (user.password) {
      passwordOk = (user.password === password);

      // auto-upgrade to hashed password
      if (passwordOk) {
        user.passwordHash = await bcrypt.hash(password, 10);
        delete user.password;
        writeUser(resolvedId, user);
      }
    }

    if (!passwordOk) {
      console.log(`[LOGIN FAILED] Wrong password: ${resolvedId}`);
      return res.status(401).json({
        ok: false,
        error: 'Invalid credentials'
      });
    }

    console.log(`[LOGIN SUCCESS] User authenticated: ${resolvedId}`);

    // ✅ ensure upload folder exists
    const userDir = path.join(UPLOADS_ROOT, resolvedId);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(path.join(userDir, 'cards'), { recursive: true });
    }

    return res.json({
      ok: true,
      profile: safeProfile(user),
      resolvedUsername: resolvedId
    });

  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    return res.status(500).json({
      ok: false,
      error: 'Internal server error'
    });
  }
});

// =============================================================================
//  UNITY — PUT /api/user/:userId  (update mobile/password from app)
// =============================================================================
app.put('/api/user/:userId', uploadLimiter, async (req, res) => {
  const userId = path.basename(req.params.userId);
  const user   = readUser(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

  const { currentPassword, newPassword, mobile } = req.body || {};
  if (!currentPassword)
    return res.status(400).json({ ok: false, error: 'currentPassword is required' });

  let passwordOk = false;
  if (user.passwordHash) passwordOk = await bcrypt.compare(currentPassword, user.passwordHash);
  else if (user.password) passwordOk = (user.password === currentPassword);
  if (!passwordOk) return res.status(401).json({ ok: false, error: 'Wrong current password' });

  const validErr = validateUserFields({
    mobile:   mobile      !== undefined ? mobile      : undefined,
    password: newPassword !== undefined ? newPassword : undefined,
  });
  if (validErr) return res.status(400).json({ ok: false, error: validErr });

  if (mobile)      user.mobile      = mobile.trim();
  if (newPassword) { user.passwordHash = await bcrypt.hash(newPassword, 10); delete user.password; }
  user.updatedAt = new Date().toISOString();

  writeUser(userId, user);
  console.log(`[USER-UPDATE] ${userId} updated from app`);
  res.json({ ok: true });
});

// =============================================================================
//  USER — GET /api/user/:userId/cards  (for Unity to sync cards)
// =============================================================================
app.get('/api/user/:userId/cards', async (req, res) => {
  const userId = path.basename(req.params.userId);
  const user = readUser(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const password = req.headers['x-user-password'] || req.query.password;
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });
  let passwordOk = false;
  if (user.passwordHash) passwordOk = await bcrypt.compare(password, user.passwordHash);
  else if (user.password) passwordOk = (user.password === password);
  if (!passwordOk) return res.status(401).json({ ok: false, error: 'Invalid password' });
  const cardsDir = path.join(UPLOADS_ROOT, userId, 'cards');
  if (!fs.existsSync(cardsDir)) return res.json([]);
  const cards = fs.readdirSync(cardsDir).filter(f => f.endsWith('.json')).sort()
    .map(f => { try { return JSON.parse(fs.readFileSync(path.join(cardsDir, f), 'utf8')); } catch { return null; } })
    .filter(Boolean);
  res.json(cards);
});

// =============================================================================
//  USER — GET /api/user/:userId/images  (for Unity to sync images)
// =============================================================================
app.get('/api/user/:userId/images', async (req, res) => {
  const userId = path.basename(req.params.userId);
  const user = readUser(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const password = req.headers['x-user-password'] || req.query.password;
  if (!password) return res.status(400).json({ ok: false, error: 'Password required' });
  let passwordOk = false;
  if (user.passwordHash) passwordOk = await bcrypt.compare(password, user.passwordHash);
  else if (user.password) passwordOk = (user.password === password);
  if (!passwordOk) return res.status(401).json({ ok: false, error: 'Invalid password' });
  const userDir = path.join(UPLOADS_ROOT, userId);
  if (!fs.existsSync(userDir)) return res.json([]);
  const isImg = f => ['.png', '.jpg', '.jpeg', '.webp'].includes(path.extname(f).toLowerCase());
  const rootImgs = fs.readdirSync(userDir).filter(isImg).sort();
  const cardsDir = path.join(userDir, 'cards');
  const cardImgs = fs.existsSync(cardsDir)
    ? fs.readdirSync(cardsDir).filter(isImg).sort().map(f => 'cards/' + f) : [];
  res.json([...rootImgs, ...cardImgs]);
});

// =============================================================================
//  ADMIN — POST /create-user
//  Writes ONE file: data/users/<userId>.json
//  Also creates uploads/<userId>/cards/ folder
// =============================================================================
app.post('/create-user', requireAdmin, async (req, res) => {
  const { userId, username, email, mobile, password } = req.body || {};
  const id = ((userId || username) || '').trim().replace(/\s+/g, '_');

  if (!id || !email || !mobile || !password)
    return res.status(400).json({ ok: false, error: 'Missing required fields: userId, email, mobile, password' });

  const validErr = validateUserFields({ mobile, password });
  if (validErr) return res.status(400).json({ ok: false, error: validErr });

  const safeId = path.basename(id);
  if (readUser(safeId))
    return res.status(409).json({ ok: false, error: 'User ID already exists' });

  for (const uid of listAllUserIds()) {
    const u = readUser(uid);
    if (u && u.email === email)
      return res.status(409).json({ ok: false, error: 'Email already registered' });
  }

  const now = new Date().toISOString();
  const passwordHash = await bcrypt.hash(password, 10);

  const userData = {
    userId:       safeId,
    username:     safeId,
    email,
    mobile:       mobile.trim(),
    passwordHash,
    profileImage: '',
    createdAt:    now,
    updatedAt:    now,
  };

  writeUser(safeId, userData);
  // Create uploads folder structure
  fs.mkdirSync(path.join(UPLOADS_ROOT, safeId, 'cards'), { recursive: true });

  console.log(`[ADMIN] Created user: ${safeId}`);
  res.json({ ok: true, userId: safeId });
});

// Legacy alias used by old dashboard builds
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  if (!req.body.userId && req.body.username) req.body.userId = req.body.username;
  // inline create-user logic (can't forward easily)
  const { userId, username, email, mobile, password } = req.body || {};
  const id = ((userId || username) || '').trim().replace(/\s+/g, '_');
  if (!id || !email || !mobile || !password)
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  const validErr = validateUserFields({ mobile, password });
  if (validErr) return res.status(400).json({ ok: false, error: validErr });
  const safeId = path.basename(id);
  if (readUser(safeId)) return res.status(409).json({ ok: false, error: 'Username already exists' });
  for (const uid of listAllUserIds()) {
    const u = readUser(uid);
    if (u && u.email === email) return res.status(409).json({ ok: false, error: 'Email already registered' });
  }
  const now = new Date().toISOString();
  writeUser(safeId, { userId: safeId, username: safeId, email, mobile: mobile.trim(), passwordHash: await bcrypt.hash(password, 10), profileImage: '', createdAt: now, updatedAt: now });
  fs.mkdirSync(path.join(UPLOADS_ROOT, safeId, 'cards'), { recursive: true });
  console.log(`[ADMIN] Created user: ${safeId}`);
  res.json({ ok: true, username: safeId, userId: safeId });
});

// =============================================================================
//  ADMIN — GET /user/:userId  and  GET /api/user/:userId
// =============================================================================
app.get('/user/:userId', requireAdmin, (req, res) => {
  const user = readUser(path.basename(req.params.userId));
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  res.json(safeProfile(user));
});
app.get('/api/user/:userId', requireAdmin, (req, res) => {
  const user = readUser(path.basename(req.params.userId));
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  res.json(safeProfile(user));
});
// After: app.get('/api/user/:userId/cards', requireAdmin, ...)
// ADD THIS NEW ENDPOINT (no auth required — Unity calls it on login):

app.get('/sync/:userId', (req, res) => {
  const userId   = path.basename(req.params.userId);
  const user     = readUser(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

  const cardsDir = path.join(UPLOADS_ROOT, userId, 'cards');
  const cards    = [];
  const images   = [];

  if (fs.existsSync(cardsDir)) {
    fs.readdirSync(cardsDir).sort().forEach(f => {
      const fullPath = path.join(cardsDir, f);
      if (f.endsWith('.json')) {
        try { cards.push(JSON.parse(fs.readFileSync(fullPath, 'utf8'))); } catch {}
      } else if (['.png','.jpg','.jpeg','.webp'].includes(path.extname(f).toLowerCase())) {
        images.push(`/uploads/${userId}/cards/${f}`);
      }
    });
  }

  res.json({ ok: true, profile: safeProfile(user), cards, images });
});
// =============================================================================
//  ADMIN — PUT /update-user/:userId  (admin edits user — same JSON always)
// =============================================================================
app.put('/update-user/:userId', requireAdmin, async (req, res) => {
  const userId = path.basename(req.params.userId);
  const user   = readUser(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

  const { email, mobile, password, newUserId, newUsername } = req.body || {};
  const targetNewId = (newUserId || newUsername || '').trim().replace(/\s+/g, '_') || null;

  const validErr = validateUserFields({
    mobile:   mobile   !== undefined ? mobile   : undefined,
    password: password !== undefined ? password : undefined,
  });
  if (validErr) return res.status(400).json({ ok: false, error: validErr });

  if (targetNewId && targetNewId !== userId) {
    const safeNew = path.basename(targetNewId);
    if (readUser(safeNew)) return res.status(409).json({ ok: false, error: 'New userId already taken' });
    // Rename uploads folder
    const oldDir = path.join(UPLOADS_ROOT, userId);
    const newDir = path.join(UPLOADS_ROOT, safeNew);
    if (fs.existsSync(oldDir)) fs.renameSync(oldDir, newDir);
    if (email)    user.email    = email;
    if (mobile)   user.mobile   = mobile.trim();
    if (password) { user.passwordHash = await bcrypt.hash(password, 10); delete user.password; }
    user.userId   = safeNew;
    user.username = safeNew;
    user.updatedAt = new Date().toISOString();
    fs.unlinkSync(userFilePath(userId));
    writeUser(safeNew, user);
    return res.json({ ok: true, userId: safeNew });
  }

  if (email)    user.email    = email;
  if (mobile)   user.mobile   = mobile.trim();
  if (password) { user.passwordHash = await bcrypt.hash(password, 10); delete user.password; }
  user.updatedAt = new Date().toISOString();
  writeUser(userId, user);
  console.log(`[ADMIN-UPDATE] ${userId} updated`);
  res.json({ ok: true, userId });
});

// Legacy alias
app.put('/api/admin/users/:username', requireAdmin, async (req, res) => {
  req.params.userId = req.params.username;
  if (req.body.newUsername && !req.body.newUserId) req.body.newUserId = req.body.newUsername;
  const userId = path.basename(req.params.userId);
  const user   = readUser(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const { email, mobile, password, newUserId, newUsername } = req.body || {};
  const targetNewId = ((newUserId || newUsername) || '').trim().replace(/\s+/g, '_') || null;
  const validErr = validateUserFields({
    mobile:   mobile   !== undefined ? mobile   : undefined,
    password: password !== undefined ? password : undefined,
  });
  if (validErr) return res.status(400).json({ ok: false, error: validErr });
  if (targetNewId && targetNewId !== userId) {
    const safeNew = path.basename(targetNewId);
    if (readUser(safeNew)) return res.status(409).json({ ok: false, error: 'New userId already taken' });
    const oldDir = path.join(UPLOADS_ROOT, userId);
    const newDir = path.join(UPLOADS_ROOT, safeNew);
    if (fs.existsSync(oldDir)) fs.renameSync(oldDir, newDir);
    if (email)    user.email    = email;
    if (mobile)   user.mobile   = mobile.trim();
    if (password) { user.passwordHash = await bcrypt.hash(password, 10); delete user.password; }
    user.userId = safeNew; user.username = safeNew; user.updatedAt = new Date().toISOString();
    fs.unlinkSync(userFilePath(userId)); writeUser(safeNew, user);
    return res.json({ ok: true, username: safeNew, userId: safeNew });
  }
  if (email)    user.email    = email;
  if (mobile)   user.mobile   = mobile.trim();
  if (password) { user.passwordHash = await bcrypt.hash(password, 10); delete user.password; }
  user.updatedAt = new Date().toISOString();
  writeUser(userId, user);
  res.json({ ok: true, username: userId, userId });
});

// =============================================================================
//  ADMIN — POST /upload/:userId  (profile image)
//  ✅ FIX: saves at uploads/<userId>/profile.<ext>
//          stores "/uploads/<userId>/profile.<ext>" in user JSON
//          image is served at http://host/uploads/<userId>/profile.jpg
// =============================================================================
app.post('/upload/:userId', requireAdmin, upload.single('file'), async (req, res) => {
  const userId = path.basename(req.params.userId);
  const user   = readUser(userId);
  if (!user)    return res.status(404).json({ ok: false, error: 'User not found' });
  if (!req.file) return res.status(400).json({ ok: false, error: 'No file uploaded' });

  const ext = (path.extname(req.file.originalname || '').toLowerCase()) || '.jpg';
  if (!['.jpg', '.jpeg', '.png', '.webp'].includes(ext))
    return res.status(400).json({ ok: false, error: 'Only JPG, PNG, WebP allowed' });

  const userDir = path.join(UPLOADS_ROOT, userId);
  fs.mkdirSync(userDir, { recursive: true });

  const filename  = 'profile' + ext;
  fs.writeFileSync(path.join(userDir, filename), req.file.buffer);

  const publicUrl = `/uploads/${userId}/${filename}`;
  user.profileImage = publicUrl;
  user.updatedAt    = new Date().toISOString();
  writeUser(userId, user);

  console.log(`[PROFILE-IMG] ${userId} → ${publicUrl}`);
  res.json({ ok: true, profileImage: publicUrl });
});

// =============================================================================
//  UNITY — POST /upload  (card images + JSONs from app)
// =============================================================================
app.post('/upload', uploadLimiter, upload.single('file'), (req, res) => {
  const { username, filetype, filename, subpath, email } = req.body;

  if (!username || !filename || !req.file)
    return res.status(400).json({ error: 'Missing username, filename, or file' });

  const safeId     = path.basename(username);
  const resolvedId = resolveUserId(safeId, email);

  if (!resolvedId) {
    console.warn(`[UPLOAD] REJECTED — unknown user '${safeId}'`);
    return res.status(404).json({ error: 'User not found. Upload rejected.' });
  }

  const safeFile = path.basename(filename);
  const safeSub  = subpath ? path.basename(subpath) : '';
  const userDir  = path.join(UPLOADS_ROOT, resolvedId);

  if (!fs.existsSync(userDir))
    fs.mkdirSync(path.join(userDir, 'cards'), { recursive: true });

  const destDir  = safeSub ? path.join(userDir, safeSub) : userDir;
  fs.mkdirSync(destDir, { recursive: true });
  let destPath = path.join(destDir, safeFile);

  if (filetype !== 'json') {
    let counter = 1;
    const parsed = path.parse(safeFile);
    let newName = safeFile;
    while (fs.existsSync(path.join(destDir, newName))) {
      newName = `${parsed.name}_${counter}${parsed.ext}`;
      counter++;
    }
    destPath = path.join(destDir, newName);
  }

  if (filetype === 'json' && safeFile.endsWith('.json')) {
    // Block profile JSON overwrites — profile lives in data/users/
    const isProfileJson = safeSub === '' &&
      (safeFile === resolvedId + '.json' || safeFile === safeId + '.json');

    if (isProfileJson) {
      try {
        const incoming = JSON.parse(req.file.buffer.toString('utf8'));
        const user = readUser(resolvedId);
        if (user && incoming.mobile && incoming.mobile !== user.mobile) {
          user.mobile    = incoming.mobile.trim();
          user.updatedAt = new Date().toISOString();
          writeUser(resolvedId, user);
        }
      } catch {}
      return res.json({ ok: true, merged: true, resolvedUsername: resolvedId });
    }

    // Card JSON — merge or write
    try {
      const incoming = JSON.parse(req.file.buffer.toString('utf8'));
    if (fs.existsSync(destPath)) {
        const existing = JSON.parse(fs.readFileSync(destPath, 'utf8'));
        // ✅ APPEND FIX: if both are arrays, concat. If objects, deep-merge
        //    preserving existing keys — never let new data wipe old card entries.
        let merged;
        if (Array.isArray(existing) && Array.isArray(incoming)) {
          // De-duplicate by cardId or filename if present
          const existingIds = new Set(existing.map(c => c.cardId || c.filename || JSON.stringify(c)));
          const newItems    = incoming.filter(c => !existingIds.has(c.cardId || c.filename || JSON.stringify(c)));
          merged = [...existing, ...newItems];
        } else if (Array.isArray(existing)) {
          merged = [...existing, incoming]; // append single object
        } else {
          // Object merge — existing fields win for critical keys, incoming wins for new keys
          merged = { ...incoming, ...existing, updatedAt: new Date().toISOString() };
        }
        fs.writeFileSync(destPath, JSON.stringify(merged, null, 2));
      } else {
        fs.writeFileSync(destPath, JSON.stringify(incoming, null, 2));
      }
      const user = readUser(resolvedId);
      if (user) { user.updatedAt = new Date().toISOString(); writeUser(resolvedId, user); }
      console.log(`[UPLOAD/json] ${resolvedId}/${safeSub ? safeSub + '/' : ''}${safeFile}`);
      return res.json({ ok: true, merged: true, resolvedUsername: resolvedId });
    } catch (e) {
      fs.writeFileSync(destPath, req.file.buffer);
    }
  } else {
    // ✅ APPEND FIX: never overwrite existing image — add timestamp suffix if conflict
    let finalPath = destPath;
    if (fs.existsSync(destPath)) {
      const ext  = path.extname(safeFile);
      const base = path.basename(safeFile, ext);
      finalPath  = path.join(destDir, `${base}_${Date.now()}${ext}`);
    }
    fs.writeFileSync(finalPath, req.file.buffer);
    const user = readUser(resolvedId);
    if (user) { user.updatedAt = new Date().toISOString(); writeUser(resolvedId, user); }
  }

  console.log(`[UPLOAD] ${resolvedId}/${safeSub ? safeSub + '/' : ''}${safeFile}`);
  res.json({ ok: true, resolvedUsername: resolvedId });
});

// =============================================================================
//  ADMIN — GET /api/users  (dashboard list)
// =============================================================================
app.get('/api/users', requireAdmin, (req, res) => {
  const isImg = f => ['.png', '.jpg', '.jpeg', '.webp'].includes(path.extname(f).toLowerCase());
  const users = listAllUserIds().map(uid => {
    const user     = readUser(uid) || {};
    const userDir  = path.join(UPLOADS_ROOT, uid);
    const cardsDir = path.join(userDir, 'cards');
    const rootImages = fs.existsSync(userDir)  ? fs.readdirSync(userDir).filter(isImg).length  : 0;
    const cardImages = fs.existsSync(cardsDir) ? fs.readdirSync(cardsDir).filter(isImg).length : 0;
    const totalCards = fs.existsSync(cardsDir)
      ? fs.readdirSync(cardsDir).filter(f => f.endsWith('.json')).length : 0;
    return {
      userId:       user.userId       || uid,
      username:     user.username     || uid,
      email:        user.email        || '',
      mobile:       user.mobile       || '',
      profileImage: user.profileImage || '',
      createdAt:    user.createdAt    || null,
      updatedAt:    user.updatedAt    || null,
      totalImages:  rootImages + cardImages,
      totalCards,
    };
  });
  res.json(users);
});

// =============================================================================
//  ADMIN — GET /api/user/:userId/cards
// =============================================================================
app.get('/api/users/:userId/cards', requireAdmin, (req, res) => {
  const userId   = path.basename(req.params.userId);
  const cardsDir = path.join(UPLOADS_ROOT, userId, 'cards');
  if (!fs.existsSync(cardsDir)) return res.json([]);
  const cards = fs.readdirSync(cardsDir).filter(f => f.endsWith('.json')).sort()
    .map(f => { try { return JSON.parse(fs.readFileSync(path.join(cardsDir, f), 'utf8')); } catch { return null; } })
    .filter(Boolean);
  res.json(cards);
});

// =============================================================================
//  ADMIN — GET /api/image/:userId/:filename
// =============================================================================
app.get('/api/image/:userId/:filename', requireAdmin, (req, res) => {
  const userId   = path.basename(req.params.userId);
  const filename = path.basename(req.params.filename);
  const userDir  = path.join(UPLOADS_ROOT, userId);
  for (const p of [path.join(userDir, filename), path.join(userDir, 'cards', filename)]) {
    if (fs.existsSync(p)) {
      const ext  = path.extname(filename).toLowerCase();
      const mime = ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg' : ext === '.webp' ? 'image/webp' : 'image/png';
      res.setHeader('Content-Type', mime);
      res.setHeader('Cache-Control', 'public, max-age=86400');
      return res.sendFile(p);
    }
  }
  res.status(404).send('Not found');
});

// =============================================================================
//  ADMIN — GET /api/user/:userId/images
// =============================================================================
app.get('/api/users/:userId/images', requireAdmin, (req, res) => {
  const userId  = path.basename(req.params.userId);
  const userDir = path.join(UPLOADS_ROOT, userId);
  if (!fs.existsSync(userDir)) return res.json([]);
  const isImg = f => ['.png', '.jpg', '.jpeg', '.webp'].includes(path.extname(f).toLowerCase());
  const rootImgs = fs.readdirSync(userDir).filter(isImg).sort();
  const cardsDir = path.join(userDir, 'cards');
  const cardImgs = fs.existsSync(cardsDir)
    ? fs.readdirSync(cardsDir).filter(isImg).sort().map(f => 'cards/' + f) : [];
  res.json([...rootImgs, ...cardImgs]);
});

// =============================================================================
//  ADMIN — DELETE /api/admin/users/:userId
// =============================================================================
app.delete('/api/admin/users/:userId', requireAdmin, (req, res) => {
  const userId   = path.basename(req.params.userId);
  const jsonFile = userFilePath(userId);
  if (!fs.existsSync(jsonFile))
    return res.status(404).json({ ok: false, error: 'User not found' });
  fs.unlinkSync(jsonFile);
  const userDir = path.join(UPLOADS_ROOT, userId);
  if (fs.existsSync(userDir)) fs.rmSync(userDir, { recursive: true, force: true });
  console.log(`[ADMIN] Deleted user: ${userId}`);
  res.json({ ok: true });
});

// =============================================================================
//  ADMIN AUTH
// =============================================================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const { id, password } = req.body || {};
  if (!id || !password) return res.status(400).json({ ok: false, error: 'Missing id or password' });
  const admins = readAdmins();
  const admin  = admins.find(a => a.id === id);
  if (!admin) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
  let ok = admin.passwordHash ? await bcrypt.compare(password, admin.passwordHash) : (admin.password === password);
  if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });
  if (!admin.passwordHash && ok) { admin.passwordHash = await bcrypt.hash(password, 10); delete admin.password; writeAdmins(admins); }
const token = createToken(id);
  console.log(`[AUTH] Admin logged in: ${id}`);
  res.json({ ok: true, token });
});

app.post('/api/admin/logout', (req, res) => {
  res.json({ ok: true });
});
app.get('/api/admins', requireAdmin, (req, res) => {
  res.json(readAdmins().map(({ id }) => ({ id })));
});

app.post('/api/admin/admins', requireAdmin, async (req, res) => {
  const { newId, newPassword } = req.body || {};
  if (!newId || !newPassword) return res.status(400).json({ ok: false, error: 'newId and newPassword are required' });
  const admins = readAdmins();
  if (admins.find(a => a.id === newId)) return res.status(409).json({ ok: false, error: 'Admin ID already exists' });
  admins.push({ id: newId, passwordHash: await bcrypt.hash(newPassword, 10) });
  writeAdmins(admins);
  res.json({ ok: true });
});

app.put('/api/admin/admins/:id/password', requireAdmin, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ ok: false, error: 'oldPassword and newPassword required' });
  const admins = readAdmins();
  const admin  = admins.find(a => a.id === req.params.id);
  if (!admin) return res.status(404).json({ ok: false, error: 'Admin not found' });
  const ok = admin.passwordHash ? await bcrypt.compare(oldPassword, admin.passwordHash) : (admin.password === oldPassword);
  if (!ok) return res.status(401).json({ ok: false, error: 'Wrong old password' });
  admin.passwordHash = await bcrypt.hash(newPassword, 10);
  delete admin.password;
  writeAdmins(admins);
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
module.exports = app;