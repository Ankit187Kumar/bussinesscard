// server.js  — Business Card App · Unified Server  (v7 — Full MongoDB)
// ─────────────────────────────────────────────────────────────────────────────
// Changes from v6:
//  ✅ ALL user data stored in MongoDB (no more data/users/*.json)
//  ✅ ALL admin data stored in MongoDB (no more data/admins.json)
//  ✅ ALL card JSONs stored in MongoDB CardFile collection
//  ✅ All helpers (readUser, writeUser, readAdmins etc.) are now async
//  ✅ Default admin auto-created in MongoDB on first boot
//  ✅ Images stored in MongoDB GridFS (no local image files required)
//  ✅ Hardcoded SECRET replaced with process.env.JWT_SECRET
//
// ── Required environment variables ───────────────────────────────────────────
//   MONGODB_URI   — Atlas connection string
//   JWT_SECRET    — Long random string for signing tokens
//   PORT          — (optional, defaults to 3000)
//
// ── MongoDB Collections ───────────────────────────────────────────────────────
//   users         — one doc per user  (replaces data/users/<userId>.json)
//   admins        — one doc per admin (replaces data/admins.json)
//   cardfiles     — card JSON uploads  (replaces uploads/<userId>/cards/*.json)

require('dotenv').config();

const express   = require('express');
const multer    = require('multer');
const cors      = require('cors');
const path      = require('path');
const bcrypt    = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet    = require('helmet');
const jwt       = require('jsonwebtoken');
const mongoose  = require('mongoose');
const app  = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change_this_in_production';

let bucket;
const memoryUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 15 * 1024 * 1024, files: 1, fields: 10 }
});

// ── Mongoose Schemas & Models ─────────────────────────────────────────────────

const userSchema = new mongoose.Schema({
  userId:       { type: String, required: true, unique: true },
  username:     { type: String },
  email:        { type: String, unique: true, sparse: true },
  mobile:       { type: String },
  passwordHash: { type: String },
  profileImage: { type: String, default: '' },
  createdAt:    { type: String },
  updatedAt:    { type: String },
});
const UserModel = mongoose.model('User', userSchema);

const adminSchema = new mongoose.Schema({
  id:           { type: String, required: true, unique: true },
  passwordHash: { type: String },
});
const AdminModel = mongoose.model('Admin', adminSchema);

// Stores card JSON files — replaces uploads/<userId>/cards/*.json
const cardFileSchema = new mongoose.Schema({
  userId:    { type: String, required: true, index: true },
  filename:  { type: String, required: true },           // e.g. "card_001.json"
  subpath:   { type: String, default: 'cards' },         // always "cards" for now
  content:   { type: mongoose.Schema.Types.Mixed },      // parsed JSON content
  updatedAt: { type: String },
});
cardFileSchema.index({ userId: 1, filename: 1 }, { unique: true });
const CardFileModel = mongoose.model('CardFile', cardFileSchema);

// ── MongoDB Connection + Boot ─────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI)

  .then(async () => {
    console.log('✅ Connected to MongoDB');
    // Create default admin if none exist
    const count = await AdminModel.countDocuments();
    if (count === 0) {
      const hash = await bcrypt.hash('admin1234', 10);
      await AdminModel.create({ id: 'admin', passwordHash: hash });
      console.log('[BOOT] Default admin created → ID: admin  Password: admin1234');
    }
  })
  .catch(err => console.error('❌ MongoDB connection error:', err));

mongoose.connection.once('open', () => {
  bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'uploads' });
  console.log('✅ GridFS Ready');
});
// ── User data helpers (async) ─────────────────────────────────────────────────
async function readUser(userId) {
  const doc = await UserModel.findOne({ userId }).lean();
  return doc || null;
}

async function writeUser(userId, data) {
  const { _id, __v, ...clean } = data;
  await UserModel.findOneAndUpdate(
    { userId },
    { $set: clean },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
}

async function listAllUserIds() {
  const docs = await UserModel.find({}, { userId: 1 }).lean();
  return docs.map(d => d.userId);
}

async function resolveUserId(sentId, sentEmail) {
  if (await readUser(sentId)) return sentId;
  if (sentEmail) {
    const u = await UserModel.findOne({ email: sentEmail }, { userId: 1 }).lean();
    if (u) return u.userId;
  }
  return null;
}

function safeProfile(user) {
  if (!user) return null;
  const s = { ...user };
  delete s.password;
  delete s.passwordHash;
  delete s._id;
  delete s.__v;
  return s;
}

async function uploadFileToGridFS(buffer, filename, contentType, metadata = {}) {
  if (!bucket) throw new Error('GridFS bucket is not initialized');
  return new Promise((resolve, reject) => {
    const uploadStream = bucket.openUploadStream(filename, { metadata, contentType });
    uploadStream.end(buffer);
    uploadStream.on('finish', () => resolve({
      _id: uploadStream.id,
      filename: uploadStream.filename,
      contentType,
      metadata,
    }));
    uploadStream.on('error', reject);
  });
}

async function findGridFSFileByName(filename) {
  return await mongoose.connection.db.collection('uploads.files').findOne({ filename });
}

async function listGridFSFilesByUser(userId) {
  return await mongoose.connection.db.collection('uploads.files')
    .find({ 'metadata.userId': userId })
    .sort({ filename: 1 })
    .toArray();
}

function gridFsImageUrl(filename) {
  return `/image/${encodeURIComponent(filename)}`;
}

// ── Admin helpers (async) ─────────────────────────────────────────────────────
async function readAdmins() {
  return await AdminModel.find().lean();
}

async function findAdmin(id) {
  return await AdminModel.findOne({ id }).lean();
}

// ── Validation ────────────────────────────────────────────────────────────────
function validateUserFields({ mobile, password } = {}) {
  if (mobile !== undefined && !/^\d{10}$/.test(String(mobile).trim()))
    return 'Mobile must be exactly 10 digits';
  if (password !== undefined && String(password).length < 5)
    return 'Password must be at least 5 characters';
  return null;
}

function validateAdminPassword(password) {
  if (!password || String(password).length < 5)
    return 'Password must be at least 5 characters';
  return null;
}

// ── Multer (memory storage) ───────────────────────────────────────────────────
const upload = memoryUpload;
// ── Rate limiters ─────────────────────────────────────────────────────────────
const loginLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { ok: false, error: 'Too many attempts' }, standardHeaders: true, legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 60 * 1000, max: 120, message: { error: 'Upload rate limit exceeded' } });

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  const token =
    req.headers['x-admin-token'] ||
    (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  if (!token) return res.status(401).json({ ok: false, error: 'No token' });
  try {
    const decoded = jwt.verify(token, SECRET);
    req.adminId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ ok: false, error: 'Invalid/Expired token' });
  }
}

function createToken(adminId) {
  return jwt.sign({ id: adminId }, SECRET, { expiresIn: '8h' });
}

// ── Global middleware ─────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log('➡️', req.method, req.url);
  next();
});

// =============================================================================
//  UNITY — POST /login
//  Accepts { userId, password } or legacy { username, email, password }
// =============================================================================
app.post(['/login', '/api/login'], loginLimiter, async (req, res) => {
  try {
    const userId   = ((req.body.userId || req.body.username) || '').trim();
    const email    = (req.body.email || '').trim();
    const password = (req.body.password || '').trim();

    if (!userId || !password)
      return res.json({ ok: false, error: 'Missing userId or password' });

    const resolvedId = await resolveUserId(userId, email);
    if (!resolvedId) {
      console.log(`[LOGIN FAILED] User not found: ${userId}`);
      return res.json({ ok: false, error: 'User not found' });
    }

    const user = await readUser(resolvedId);
    if (!user) return res.json({ ok: false, error: 'User data missing' });

    let passwordOk = false;
    if (user.passwordHash) {
      passwordOk = await bcrypt.compare(password, user.passwordHash);
    } else if (user.password) {
      passwordOk = (user.password === password);
      if (passwordOk) {
        const hash = await bcrypt.hash(password, 10);
        await UserModel.findOneAndUpdate({ userId: resolvedId }, { $set: { passwordHash: hash }, $unset: { password: '' } });
      }
    }

    if (!passwordOk) {
      console.log(`[LOGIN FAILED] Wrong password: ${resolvedId}`);
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }

    console.log(`[LOGIN SUCCESS] ${resolvedId}`);
    return res.json({ ok: true, profile: safeProfile(user), resolvedUsername: resolvedId });
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  UNITY — PUT /api/user/:userId  (update mobile/password from app)
// =============================================================================
app.put('/api/user/:userId', uploadLimiter, async (req, res) => {
  try {
    const userId = req.params.userId;
    const user   = await readUser(userId);
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

    const update = { updatedAt: new Date().toISOString() };
    if (mobile)      update.mobile = mobile.trim();
    if (newPassword) update.passwordHash = await bcrypt.hash(newPassword, 10);

    await UserModel.findOneAndUpdate({ userId }, { $set: update, $unset: newPassword ? { password: '' } : {} });
    console.log(`[USER-UPDATE] ${userId} updated from app`);
    res.json({ ok: true });
  } catch (err) {
    console.error('[USER-UPDATE ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  USER — GET /api/user/:userId/cards  (Unity cross-device sync)
// =============================================================================
app.get('/api/user/:userId/cards', async (req, res) => {
  try {
    const userId = req.params.userId;
    const user   = await readUser(userId);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

    const password = req.headers['x-user-password'] || req.query.password;
    if (!password) return res.status(400).json({ ok: false, error: 'Password required' });

    let passwordOk = false;
    if (user.passwordHash) passwordOk = await bcrypt.compare(password, user.passwordHash);
    else if (user.password) passwordOk = (user.password === password);
    if (!passwordOk) return res.status(401).json({ ok: false, error: 'Invalid password' });

    const cardDocs = await CardFileModel.find({ userId }).sort({ filename: 1 }).lean();
    const cards = cardDocs.map(d => d.content).filter(Boolean);
    res.json(cards);
  } catch (err) {
    console.error('[CARDS ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  USER — GET /api/user/:userId/images  (Unity cross-device sync)
// =============================================================================
app.get('/api/user/:userId/images', async (req, res) => {
  try {
    const userId = req.params.userId;
    const user   = await readUser(userId);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

    const password = req.headers['x-user-password'] || req.query.password;
    if (!password) return res.status(400).json({ ok: false, error: 'Password required' });

    let passwordOk = false;
    if (user.passwordHash) passwordOk = await bcrypt.compare(password, user.passwordHash);
    else if (user.password) passwordOk = (user.password === password);
    if (!passwordOk) return res.status(401).json({ ok: false, error: 'Invalid password' });

    const files = await listGridFSFilesByUser(userId);
    const images = files.map(f => gridFsImageUrl(f.filename));
    res.json(images);
  } catch (err) {
    console.error('[IMAGES ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  SYNC — GET /sync/:userId  (full profile + cards + images)
// =============================================================================
app.get('/sync/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const user   = await readUser(userId);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

    const cardDocs = await CardFileModel.find({ userId }).sort({ filename: 1 }).lean();
    const cards    = cardDocs.map(d => d.content).filter(Boolean);

    const files = await listGridFSFilesByUser(userId);
    const images = files.map(f => gridFsImageUrl(f.filename));

    res.json({ ok: true, profile: safeProfile(user), cards, images });
  } catch (err) {
    console.error('[SYNC ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  ADMIN — POST /create-user
// =============================================================================
app.post('/create-user', requireAdmin, async (req, res) => {
  try {
    const { userId, username, email, mobile, password } = req.body || {};
    const id = ((userId || username) || '').trim().replace(/\s+/g, '_');

    if (!id || !email || !mobile || !password)
      return res.status(400).json({ ok: false, error: 'Missing required fields: userId, email, mobile, password' });

    const validErr = validateUserFields({ mobile, password });
    if (validErr) return res.status(400).json({ ok: false, error: validErr });

    if (await readUser(id))
      return res.status(409).json({ ok: false, error: 'User ID already exists' });

    const emailExists = await UserModel.findOne({ email }).lean();
    if (emailExists)
      return res.status(409).json({ ok: false, error: 'Email already registered' });

    const now = new Date().toISOString();
    const passwordHash = await bcrypt.hash(password, 10);

    await UserModel.create({
      userId: id, username: id, email, mobile: mobile.trim(),
      passwordHash, profileImage: '', createdAt: now, updatedAt: now,
    });

    console.log(`[ADMIN] Created user: ${id}`);
    res.json({ ok: true, userId: id });
  } catch (err) {
    console.error('[CREATE-USER ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Legacy alias
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  if (!req.body.userId && req.body.username) req.body.userId = req.body.username;
  const { userId, username, email, mobile, password } = req.body || {};
  const id = ((userId || username) || '').trim().replace(/\s+/g, '_');
  if (!id || !email || !mobile || !password)
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  const validErr = validateUserFields({ mobile, password });
  if (validErr) return res.status(400).json({ ok: false, error: validErr });
  if (await readUser(id)) return res.status(409).json({ ok: false, error: 'Username already exists' });
  const emailExists = await UserModel.findOne({ email }).lean();
  if (emailExists) return res.status(409).json({ ok: false, error: 'Email already registered' });
  const now = new Date().toISOString();
  await UserModel.create({ userId: id, username: id, email, mobile: mobile.trim(), passwordHash: await bcrypt.hash(password, 10), profileImage: '', createdAt: now, updatedAt: now });
  console.log(`[ADMIN] Created user: ${id}`);
  res.json({ ok: true, username: id, userId: id });
});

// =============================================================================
//  ADMIN — GET /user/:userId  and  GET /api/user/:userId
// =============================================================================
app.get('/user/:userId', requireAdmin, async (req, res) => {
  const user = await readUser(req.params.userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  res.json(safeProfile(user));
});

app.get('/api/user/:userId', requireAdmin, async (req, res) => {
  const user = await readUser(req.params.userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  res.json(safeProfile(user));
});

// =============================================================================
//  ADMIN — PUT /update-user/:userId
// =============================================================================
app.put('/update-user/:userId', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;
    const user   = await readUser(userId);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

    const { email, mobile, password, newUserId, newUsername } = req.body || {};
    const targetNewId = ((newUserId || newUsername) || '').trim().replace(/\s+/g, '_') || null;

    const validErr = validateUserFields({
      mobile:   mobile   !== undefined ? mobile   : undefined,
      password: password !== undefined ? password : undefined,
    });
    if (validErr) return res.status(400).json({ ok: false, error: validErr });

    if (targetNewId && targetNewId !== userId) {
      if (await readUser(targetNewId))
        return res.status(409).json({ ok: false, error: 'New userId already taken' });

      // Update all card files
      await CardFileModel.updateMany({ userId }, { $set: { userId: targetNewId } });

      const update = { userId: targetNewId, username: targetNewId, updatedAt: new Date().toISOString() };
      if (email)    update.email    = email;
      if (mobile)   update.mobile   = mobile.trim();
      if (password) { update.passwordHash = await bcrypt.hash(password, 10); }

      await UserModel.findOneAndUpdate({ userId }, { $set: update, $unset: password ? { password: '' } : {} });
      await UserModel.findOneAndUpdate({ userId: targetNewId }, { $set: { userId: targetNewId } });

      return res.json({ ok: true, userId: targetNewId });
    }

    const update = { updatedAt: new Date().toISOString() };
    if (email)    update.email    = email;
    if (mobile)   update.mobile   = mobile.trim();
    if (password) { update.passwordHash = await bcrypt.hash(password, 10); }

    await UserModel.findOneAndUpdate({ userId }, { $set: update, $unset: password ? { password: '' } : {} });
    console.log(`[ADMIN-UPDATE] ${userId} updated`);
    res.json({ ok: true, userId });
  } catch (err) {
    console.error('[UPDATE-USER ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// Legacy alias
app.put('/api/admin/users/:username', requireAdmin, async (req, res) => {
  if (req.body.newUsername && !req.body.newUserId) req.body.newUserId = req.body.newUsername;
  req.params.userId = req.params.username;
  // Reuse the main handler logic by forwarding
  const userId = req.params.username;
  const user   = await readUser(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
  const { email, mobile, password, newUserId, newUsername } = req.body || {};
  const targetNewId = ((newUserId || newUsername) || '').trim().replace(/\s+/g, '_') || null;
  const validErr = validateUserFields({
    mobile: mobile !== undefined ? mobile : undefined,
    password: password !== undefined ? password : undefined,
  });
  if (validErr) return res.status(400).json({ ok: false, error: validErr });
  if (targetNewId && targetNewId !== userId) {
    if (await readUser(targetNewId)) return res.status(409).json({ ok: false, error: 'New userId already taken' });
    await CardFileModel.updateMany({ userId }, { $set: { userId: targetNewId } });
    const update = { userId: targetNewId, username: targetNewId, updatedAt: new Date().toISOString() };
    if (email)    update.email    = email;
    if (mobile)   update.mobile   = mobile.trim();
    if (password) { update.passwordHash = await bcrypt.hash(password, 10); }
    await UserModel.findOneAndUpdate({ userId }, { $set: update, $unset: password ? { password: '' } : {} });
    return res.json({ ok: true, username: targetNewId, userId: targetNewId });
  }
  const update = { updatedAt: new Date().toISOString() };
  if (email)    update.email    = email;
  if (mobile)   update.mobile   = mobile.trim();
  if (password) { update.passwordHash = await bcrypt.hash(password, 10); }
  await UserModel.findOneAndUpdate({ userId }, { $set: update, $unset: password ? { password: '' } : {} });
  res.json({ ok: true, username: userId, userId });
});

// =============================================================================
//  ADMIN — POST /upload/:userId  (profile image)
// =============================================================================
app.post('/upload/:userId', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await readUser(userId);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });
    if (!req.file) return res.status(400).json({ ok: false, error: 'No file uploaded' });

    const ext = (path.extname(req.file.originalname || '').toLowerCase()) || '.jpg';
    if (!['.jpg', '.jpeg', '.png', '.webp'].includes(ext))
      return res.status(400).json({ ok: false, error: 'Only JPG, PNG, WebP allowed' });

    const filename = `profile-${userId}-${Date.now()}${ext}`;
    await uploadFileToGridFS(req.file.buffer, filename, req.file.mimetype || 'application/octet-stream', {
      userId,
      type: 'profile',
    });

    const publicUrl = gridFsImageUrl(filename);
    await UserModel.findOneAndUpdate(
      { userId },
      { $set: { profileImage: publicUrl, updatedAt: new Date().toISOString() } }
    );

    console.log(`[PROFILE-IMG] ${userId} → ${publicUrl}`);
    res.json({ ok: true, profileImage: publicUrl, filename });
  } catch (err) {
    console.error('[PROFILE-IMG ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});
// ✅ GET image from MongoDB (GridFS)
app.get('/image/:filename', async (req, res) => {
  try {
    const filename = req.params.filename;
    const file = await findGridFSFileByName(filename);
    if (!file) return res.status(404).send('No file found');

    res.setHeader('Content-Type', file.contentType || 'application/octet-stream');
    res.setHeader('Cache-Control', 'public, max-age=86400');

    const readStream = bucket.openDownloadStream(file._id);
    readStream.on('error', err => {
      console.error(err);
      if (!res.headersSent) res.status(500).send('Error fetching image');
    });
    readStream.pipe(res);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching image');
  }
});
// =============================================================================
//  UNITY — POST /upload  (card images + JSONs from app)
// =============================================================================
app.post('/upload', uploadLimiter, upload.single('file'), async (req, res) => {
  try {
    const { username, filetype, filename, subpath, email } = req.body;
    if (!username || !filename || !req.file)
      return res.status(400).json({ error: 'Missing username, filename, or file' });

    const resolvedId = await resolveUserId(username, email);
    if (!resolvedId) {
      console.warn(`[UPLOAD] REJECTED — unknown user '${username}'`);
      return res.status(404).json({ error: 'User not found. Upload rejected.' });
    }

    const safeFile = path.basename(filename);
    const safeSub = subpath ? path.basename(subpath) : '';

    // ── JSON card files → store in MongoDB ───────────────────────────────────
    if (filetype === 'json' && safeFile.endsWith('.json')) {
      const isProfileJson = safeSub === '' &&
        (safeFile === resolvedId + '.json' || safeFile === username + '.json');

      if (isProfileJson) {
        try {
          const incoming = JSON.parse(req.file.buffer.toString('utf8'));
          if (incoming.mobile) {
            await UserModel.findOneAndUpdate(
              { userId: resolvedId },
              { $set: { mobile: incoming.mobile.trim(), updatedAt: new Date().toISOString() } }
            );
          }
        } catch {}
        return res.json({ ok: true, merged: true, resolvedUsername: resolvedId });
      }

      // Card JSON
      try {
        const incoming = JSON.parse(req.file.buffer.toString('utf8'));
        const existing = await CardFileModel.findOne({ userId: resolvedId, filename: safeFile }).lean();

        let merged;
        if (existing) {
          const ex = existing.content;
          if (Array.isArray(ex) && Array.isArray(incoming)) {
            const existingIds = new Set(ex.map(c => c.cardId || c.filename || JSON.stringify(c)));
            const newItems = incoming.filter(c => !existingIds.has(c.cardId || c.filename || JSON.stringify(c)));
            merged = [...ex, ...newItems];
          } else if (Array.isArray(ex)) {
            merged = [...ex, incoming];
          } else {
            merged = { ...incoming, ...ex, updatedAt: new Date().toISOString() };
          }
        } else {
          merged = incoming;
        }

        await CardFileModel.findOneAndUpdate(
          { userId: resolvedId, filename: safeFile },
          { $set: { content: merged, subpath: safeSub || 'cards', updatedAt: new Date().toISOString() } },
          { upsert: true }
        );

        await UserModel.findOneAndUpdate(
          { userId: resolvedId },
          { $set: { updatedAt: new Date().toISOString() } }
        );

        console.log(`[UPLOAD/json] ${resolvedId}/${safeFile}`);
        return res.json({ ok: true, merged: true, resolvedUsername: resolvedId });
      } catch (e) {
        console.error('[UPLOAD/json parse error]', e);
        return res.status(400).json({ error: 'Invalid JSON file' });
      }
    }

    const ext = path.extname(req.file.originalname || safeFile).toLowerCase() || '.jpg';
    if (!['.jpg', '.jpeg', '.png', '.webp'].includes(ext))
      return res.status(400).json({ error: 'Only JPG, PNG, WebP allowed' });

    const storedFilename = `${resolvedId}-${safeSub || 'cards'}-${Date.now()}-${safeFile}`;
    await uploadFileToGridFS(
      req.file.buffer,
      storedFilename,
      req.file.mimetype || 'application/octet-stream',
      {
        userId: resolvedId,
        subpath: safeSub || 'cards',
        type: 'card-image',
        originalName: safeFile,
      }
    );

    await UserModel.findOneAndUpdate(
      { userId: resolvedId },
      { $set: { updatedAt: new Date().toISOString() } }
    );

    const imageUrl = gridFsImageUrl(storedFilename);
    console.log(`[UPLOAD/img] ${resolvedId}/${safeSub ? safeSub + '/' : ''}${storedFilename}`);
    return res.json({ ok: true, resolvedUsername: resolvedId, imageUrl, filename: storedFilename });
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
//  ADMIN — GET /api/users  (dashboard list)
// =============================================================================
app.get('/api/users', requireAdmin, async (req, res) => {
  try {
  
   res.set({
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      'Pragma': 'no-cache',
      'Expires': '0'
    });
    const users = await UserModel.find().lean();
    const filesColl = mongoose.connection.db.collection('uploads.files');

    const result = await Promise.all(users.map(async user => {
      const uid = user.userId;
      const totalImages = await filesColl.countDocuments({ 'metadata.userId': uid });
      const totalCards = await CardFileModel.countDocuments({ userId: uid });

      return {
        userId:       user.userId       || uid,
        username:     user.username     || uid,
        email:        user.email        || '',
        mobile:       user.mobile       || '',
        profileImage: user.profileImage || '',
        createdAt:    user.createdAt    || null,
        updatedAt:    user.updatedAt    || null,
        totalImages,
        totalCards,
      };
    }));

    res.json(result);
  } catch (err) {
    console.error('[LIST-USERS ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  ADMIN — GET /api/users/:userId/cards
// =============================================================================
app.get('/api/users/:userId/cards', requireAdmin, async (req, res) => {
  try {
    const userId   = req.params.userId;
    const cardDocs = await CardFileModel.find({ userId }).sort({ filename: 1 }).lean();
    res.json(cardDocs.map(d => d.content).filter(Boolean));
  } catch (err) {
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  ADMIN — GET /api/image/:userId/:filename
// =============================================================================
app.get('/api/image/:userId/:filename', requireAdmin, async (req, res) => {
  try {
    const userId = path.basename(req.params.userId);
    const filename = req.params.filename;
    const file = await findGridFSFileByName(filename);
    if (!file || file.metadata?.userId !== userId) return res.status(404).send('Not found');

    res.setHeader('Content-Type', file.contentType || 'application/octet-stream');
    res.setHeader('Cache-Control', 'public, max-age=86400');

    const download = bucket.openDownloadStream(file._id);
    download.on('error', err => {
      console.error(err);
      if (!res.headersSent) res.status(500).send('Error fetching image');
    });
    download.pipe(res);
  } catch (err) {
    console.error('[ADMIN-IMAGE DOWNLOAD ERROR]', err);
    res.status(500).send('Error fetching image');
  }
});

// =============================================================================
//  ADMIN — GET /api/users/:userId/images
// =============================================================================
app.get('/api/users/:userId/images', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;
    const files = await listGridFSFilesByUser(userId);
    const images = files.map(f => gridFsImageUrl(f.filename));
    res.json(images);
  } catch (err) {
    console.error('[ADMIN-USER-IMAGES ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  ADMIN — DELETE /api/admin/users/:userId
// =============================================================================
app.delete('/api/admin/users/:userId', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.userId;
    const user   = await readUser(userId);
    if (!user) return res.status(404).json({ ok: false, error: 'User not found' });

    await UserModel.deleteOne({ userId });
    await CardFileModel.deleteMany({ userId });

    console.log(`[ADMIN] Deleted user: ${userId}`);
    res.json({ ok: true });
  } catch (err) {
    console.error('[DELETE-USER ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// =============================================================================
//  ADMIN AUTH
// =============================================================================
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { id, password } = req.body || {};
    if (!id || !password) return res.status(400).json({ ok: false, error: 'Missing id or password' });

    const admin = await findAdmin(id);
    if (!admin) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

    let ok = admin.passwordHash
      ? await bcrypt.compare(password, admin.passwordHash)
      : (admin.password === password);

    if (!ok) return res.status(401).json({ ok: false, error: 'Invalid credentials' });

    // Migrate plain-text password
    if (!admin.passwordHash && ok) {
      await AdminModel.findOneAndUpdate(
        { id },
        { $set: { passwordHash: await bcrypt.hash(password, 10) }, $unset: { password: '' } }
      );
    }

    const token = createToken(id);
    console.log(`[AUTH] Admin logged in: ${id}`);
    res.json({ ok: true, token });
  } catch (err) {
    console.error('[ADMIN-LOGIN ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

app.post('/api/admin/logout', (req, res) => res.json({ ok: true }));

app.get('/api/admins', requireAdmin, async (req, res) => {
  const admins = await readAdmins();
  res.json(admins.map(({ id }) => ({ id })));
});

app.post('/api/admin/admins', requireAdmin, async (req, res) => {
  try {
    const { newId, newPassword } = req.body || {};
    if (!newId || !newPassword)
      return res.status(400).json({ ok: false, error: 'newId and newPassword are required' });
    const pwErr = validateAdminPassword(newPassword);
    if (pwErr) return res.status(400).json({ ok: false, error: pwErr });
    if (await findAdmin(newId))
      return res.status(409).json({ ok: false, error: 'Admin ID already exists' });
    await AdminModel.create({ id: newId, passwordHash: await bcrypt.hash(newPassword, 10) });
    res.json({ ok: true });
  } catch (err) {
    console.error('[CREATE-ADMIN ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

app.put('/api/admin/admins/:id/password', requireAdmin, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword)
      return res.status(400).json({ ok: false, error: 'oldPassword and newPassword required' });
    const pwErr = validateAdminPassword(newPassword);
    if (pwErr) return res.status(400).json({ ok: false, error: pwErr });

    const admin = await findAdmin(req.params.id);
    if (!admin) return res.status(404).json({ ok: false, error: 'Admin not found' });

    const ok = admin.passwordHash
      ? await bcrypt.compare(oldPassword, admin.passwordHash)
      : (admin.password === oldPassword);
    if (!ok) return res.status(401).json({ ok: false, error: 'Wrong old password' });

    await AdminModel.findOneAndUpdate(
      { id: req.params.id },
      { $set: { passwordHash: await bcrypt.hash(newPassword, 10) }, $unset: { password: '' } }
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('[CHANGE-ADMIN-PASS ERROR]', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// ── Static + fallback ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}
module.exports = app;
