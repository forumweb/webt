const express = require('express');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto');
const security = require('./security');
const app = express();
app.use(cors());
app.use(express.json());                                                         
// USERS
const USERS_FILE = './users.json';
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  const data = fs.readFileSync(USERS_FILE, 'utf8');
  const users = data ? JSON.parse(data) : [];
  // Auto-migrate any plaintext passwords to SHA-256 hashes
  return migrateUsersPasswords(users);
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// Detect if a string is a SHA-256 hex digest
function isSha256Hex(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/i.test(value);
}

// Migrate any user records that still store plaintext passwords
function migrateUsersPasswords(users) {
  let migrated = false;
  for (const user of users) {
    if (user && user.password && !isSha256Hex(user.password)) {
      user.password = hashPassword(String(user.password));
      migrated = true;
    }
  }
  if (migrated) saveUsers(users);
  return users;
}

// Generate paraphrase: 5 karakter acak (huruf besar, kecil, angka)
function generateParaphrase() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let p = '';
  for (let i = 0; i < 5; i++) p += chars[Math.floor(Math.random() * chars.length)];
  return p;
}

// REGISTER user multi-entitas
app.post('/users', async (req, res) => {
  const { username, email, password, userAgent, screen } = req.body;               if (!username || !email || !password || !userAgent || !screen)
    return res.status(400).json({ error: 'Semua field wajib diisi' });           
  // Validasi hanya Gmail
  if (!/@gmail\.com$/i.test(email.trim()))
    return res.status(400).json({ error: 'Hanya email Gmail yang diizinkan' });

  const users = loadUsers();
  if (users.find(u => u.email === email))
    return res.status(400).json({ error: 'Email sudah terpakai' });

  // Generate paraphrase
  const paraphrase = generateParaphrase();

  // Generate fingerprint
  const salt = crypto.randomBytes(8).toString('hex');
  const fingerprint = security.generateDeviceFingerprint({ userAgent, screen, salt });

  // Generate TOTP secret and QR code
  const totpSecretObj = security.generateTOTPSecret(email);
  const totpSecret = totpSecretObj.base32;
  const otpauth_url = totpSecretObj.otpauth_url;
  const qrCode = await security.generateQRCode(otpauth_url);

  // Generate RSA keypair for device
  const { publicKey } = security.generateKeypair();

  // Save user
  const hashed = hashPassword(password);
  const newUser = {
    id: Date.now(),
    username,
    email,
    password: hashed,
    paraphrase,
    bookmarks: [],
    balance: 0,
    totpSecret,
    trustedDevices: [
      { fingerprint, salt, userAgent, screen, registeredAt: Date.now() }
    ],
    publicKey,
  };
  users.push(newUser);                                                             saveUsers(users);

  res.json({
    id: newUser.id,
    username: newUser.username,
    email: newUser.email,
    totpQR: qrCode,
    totpSecret,
    fingerprint,
    salt,
    paraphrase
  });
});

// LOGIN multi-entitas
app.post('/login', (req, res) => {
  const { email, password, fingerprint, totp, challengeResponse } = req.body;
  if (!email || !password || !fingerprint || !totp) {
    return res.status(400).json({ error: 'Email, password, fingerprint, dan TOTP wajib diisi' });
  }
  const users = loadUsers();
  const hashed = hashPassword(password);
  let user = users.find(u => u.email === email && u.password === hashed);

  // If not found, attempt migration for legacy plaintext passwords for this user
  if (!user) {
    const candidate = users.find(u => u.email === email);
    if (candidate && candidate.password && !isSha256Hex(candidate.password)) {
      if (candidate.password === password) {
        candidate.password = hashed;
        saveUsers(users);
        user = candidate;
      }
    }
  }

  if (!user) return res.status(401).json({ error: 'Email/password salah' });
  // Device check
  const trusted = user.trustedDevices?.find(d => d.fingerprint === fingerprint);
  if (!trusted) return res.status(403).json({ error: 'Device not trusted' });    
  // Verify TOTP
  if (!security.verifyTOTP(user.totpSecret, totp))
    return res.status(403).json({ error: 'Kode TOTP salah' });

  if (challengeResponse !== 'accepted')
    return res.status(403).json({ error: 'Challenge response invalid' });

  const { password: pw, totpSecret, trustedDevices, ...userNoPw } = user;
  res.json(userNoPw);                                                            });

// Bind device via email + paraphrase
app.post('/bind-device', (req, res) => {
  const { email, paraphrase, userAgent, screen } = req.body;                       if (!email || !paraphrase || !userAgent || !screen)
    return res.status(400).json({ error: 'Email, paraphrase, userAgent, screen wajib diisi' });

  const users = loadUsers();
  const user = users.find(
    u => u.email === email && u.paraphrase === paraphrase
  );
  if (!user) return res.status(404).json({ error: 'User/paraphrase tidak cocok' });

  // Generate new fingerprint untuk perangkat ini
  const salt = crypto.randomBytes(8).toString('hex');
  const fingerprint = security.generateDeviceFingerprint({ userAgent, screen, salt });

  if (user.trustedDevices?.find(d => d.fingerprint === fingerprint))
    return res.status(400).json({ error: 'Device sudah terdaftar' });

  user.trustedDevices = user.trustedDevices || [];
  user.trustedDevices.push({
    fingerprint,
    salt,                                                                            userAgent,
    screen,
    registeredAt: Date.now()
  });
  saveUsers(users);
  res.json({ trustedDevices: user.trustedDevices, fingerprint });
});
                                                                                 // GET user by email (untuk frontend lookup userId, jika perlu)
app.get('/users', (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Email wajib diisi' });
  const users = loadUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  res.json({
    id: user.id,
    email: user.email,
    username: user.username,
  });
});

// BOOKMARK
app.post('/users/:userId/bookmark', (req, res) => {
  const { threadId } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.bookmarks = user.bookmarks || [];
  if (!user.bookmarks.includes(threadId)) user.bookmarks.push(threadId);
  saveUsers(users);
  res.json({ bookmarks: user.bookmarks });
});
app.post('/users/:userId/unbookmark', (req, res) => {
  const { threadId } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.bookmarks = user.bookmarks?.filter(id => id !== threadId) || [];
  saveUsers(users);
  res.json({ bookmarks: user.bookmarks });
});

// ===== SALDO / BALANCE ENDPOINTS =====

// Get saldo user
app.get('/users/:userId/balance', (req, res) => {
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ balance: user.balance || 0 });
});

// Top up saldo
app.post('/users/:userId/topup', (req, res) => {
  const { amount } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });             const nominal = parseInt(amount, 10);
  if (isNaN(nominal) || nominal <= 0) return res.status(400).json({ error: 'Nominal harus lebih dari 0' });
  user.balance = (user.balance || 0) + nominal;                                    saveUsers(users);
  res.json({ balance: user.balance });
});

// Withdraw saldo
app.post('/users/:userId/withdraw', (req, res) => {
  const { amount } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });             const nominal = parseInt(amount, 10);
  if (isNaN(nominal) || nominal <= 0) return res.status(400).json({ error: 'Nominal harus lebih dari 0' });
  if ((user.balance || 0) < nominal) return res.status(400).json({ error: 'Saldo tidak cukup' });                                                                   user.balance -= nominal;
  saveUsers(users);
  res.json({ balance: user.balance });
});

// Transfer saldo ke user lain
app.post('/users/:userId/transfer', (req, res) => {
  const { toUserId, amount } = req.body;
  const users = loadUsers();                                                       const user = users.find(u => u.id == req.params.userId);
  const toUser = users.find(u => u.id == toUserId);
  if (!user) return res.status(404).json({ error: 'User asal tidak ditemukan' });
  if (!toUser) return res.status(404).json({ error: 'User tujuan tidak ditemukan' });
  const nominal = parseInt(amount, 10);
  if (isNaN(nominal) || nominal <= 0) return res.status(400).json({ error: 'Nominal transfer harus lebih dari 0' });                                                if ((user.balance || 0) < nominal) return res.status(400).json({ error: 'Saldo tidak cukup' });
  user.balance -= nominal;
  toUser.balance = (toUser.balance || 0) + nominal;
  saveUsers(users);
  res.json({ balance: user.balance, toUserBalance: toUser.balance });
});

// THREADS - sinkronisasi properti
const THREADS_FILE = './threads.json';
function loadThreads() {
  if (!fs.existsSync(THREADS_FILE)) return [];
  const data = fs.readFileSync(THREADS_FILE, 'utf8');
  return data ? JSON.parse(data) : [];
}
function saveThreads(threads) {
  fs.writeFileSync(THREADS_FILE, JSON.stringify(threads, null, 2));
}

// Normalize thread shape for frontend compatibility
function normalizeThread(raw) {
  const safeAuthor = raw.author && typeof raw.author === 'object' ? raw.author : {};
  const safeCategory = raw.category && typeof raw.category === 'object' ? raw.category : {};
  const createdAt = raw.createdAt ? new Date(raw.createdAt).toISOString() : new Date().toISOString();
  const updatedAt = raw.updatedAt ? new Date(raw.updatedAt).toISOString() : createdAt;
  return {
    id: String(raw.id ?? Date.now()),
    title: String(raw.title ?? ''),
    content: String(raw.content ?? ''),
    author: {
      id: String(safeAuthor.id ?? 'unknown'),
      username: String(safeAuthor.username ?? 'Unknown'),
      avatar: String(safeAuthor.avatar ?? 'https://www.gravatar.com/avatar/00000000000000000000000000000000?d=identicon'),
      reputation: Number(safeAuthor.reputation ?? 0),
    },
    category: {
      id: String(safeCategory.id ?? 'c1'),
      name: String(safeCategory.name ?? 'General'),
      description: String(safeCategory.description ?? 'General discussion'),
      color: String(safeCategory.color ?? '#4a74ff'),
    },
    createdAt,
    updatedAt,
    votes: Number(raw.votes ?? 0),
    replyCount: Number(raw.replyCount ?? 0),
    isLocked: Boolean(raw.isLocked ?? false),
    isPinned: Boolean(raw.isPinned ?? false),
    tags: Array.isArray(raw.tags) ? raw.tags : [],
    // keep any other fields untouched if needed
  };
}

app.get('/threads', (req, res) => {
  const normalized = loadThreads().map(normalizeThread);
  res.json(normalized);
});
app.post('/threads', (req, res) => {
  const {
    title,
    content,
    author,
    category,
    tags,
    isPinned,
    isLocked,
    votes,
    createdAt,
    updatedAt
  } = req.body;

  if (!title || !content || !author || !category) {
    return res.status(400).json({ error: 'Semua field wajib diisi' });
  }

  const threads = loadThreads();
  const newThread = {                                                                id: String(Date.now()),
    title,
    content,
    author,
    category,                                                                        tags: tags || [],
    isPinned: isPinned || false,                                                     isLocked: isLocked || false,
    votes: votes || 0,
    replyCount: 0,
    createdAt: createdAt || new Date().toISOString(),
    updatedAt: updatedAt || new Date().toISOString()                               };
  threads.push(newThread);                                                         saveThreads(threads);
  res.json(newThread);
});

// REPLIES
const REPLIES_FILE = './replies.json';
function loadReplies() {                                                           if (!fs.existsSync(REPLIES_FILE)) return [];
  const data = fs.readFileSync(REPLIES_FILE, 'utf8');                              return data ? JSON.parse(data) : [];
}
function saveReplies(replies) {
  fs.writeFileSync(REPLIES_FILE, JSON.stringify(replies, null, 2));
}
app.get('/replies', (req, res) => {
  const { threadId } = req.query;                                                  const replies = loadReplies();
  const normalizeReply = (r) => ({
    ...r,
    id: String(r.id ?? Date.now()),
    createdAt: r.createdAt ? new Date(r.createdAt).toISOString() : new Date().toISOString(),
    votes: Number(r.votes ?? 0),
  });
  const out = threadId ? replies.filter(r => r.threadId == threadId).map(normalizeReply) : replies.map(normalizeReply);
  res.json(out);
});
app.post('/replies', (req, res) => {
  const { threadId, author, content } = req.body;
  if (!threadId || !author || !content) return res.status(400).json({ error: 'Semua field wajib' });
  const replies = loadReplies();
  const newReply = { id: String(Date.now()), threadId, author, content, createdAt: new Date().toISOString(), votes: 0 };
  replies.push(newReply);
  saveReplies(replies);
  res.json(newReply);
});

// NOTIFICATIONS
const NOTIF_FILE = './notifications.json';
function loadNotifs() {
  if (!fs.existsSync(NOTIF_FILE)) return [];
  const data = fs.readFileSync(NOTIF_FILE, 'utf8');
  return data ? JSON.parse(data) : [];
}
function saveNotifs(notifs) {
  fs.writeFileSync(NOTIF_FILE, JSON.stringify(notifs, null, 2));
}
app.get('/notifications', (req, res) => {
  const { userId } = req.query;
  const notifs = loadNotifs();
  if (userId) { return res.json(notifs.filter(n => n.userId == userId)); }
  res.json(notifs);
});
app.post('/notifications', (req, res) => {
  const { userId, message, type } = req.body;
  if (!userId || !message || !type) return res.status(400).json({ error: 'Semua field wajib' });
  const notifs = loadNotifs();
  const newNotif = { id: Date.now(), userId, message, type, isRead: false, time: Date.now() };
  notifs.push(newNotif);
  saveNotifs(notifs);
  res.json(newNotif);
});

// Test endpoint
app.get('/', (req, res) => { res.send('API Romusha File JSON Jalan!'); });

app.listen(3000, () => console.log('Server jalan di port 3000 (File JSON, Multi-Entitas Security)'));
