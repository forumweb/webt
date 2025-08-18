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
  return data ? JSON.parse(data) : [];
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// REGISTER user multi-entitas
app.post('/users', async (req, res) => {
  const { username, email, password, userAgent, screen } = req.body;
  if (!username || !email || !password || !userAgent || !screen)
    return res.status(400).json({ error: 'Semua field wajib diisi' });

  const users = loadUsers();
  if (users.find(u => u.email === email))
    return res.status(400).json({ error: 'Email sudah terpakai' });

  // Generate fingerprint
  const salt = crypto.randomBytes(8).toString('hex');
  const fingerprint = security.generateDeviceFingerprint({ userAgent, screen, salt });

  // Generate TOTP secret and QR code
  const totpSecretObj = security.generateTOTPSecret(email);
  const totpSecret = totpSecretObj.base32;
  const otpauth_url = totpSecretObj.otpauth_url;
  const qrCode = await security.generateQRCode(otpauth_url);

  // Generate RSA keypair for device
  const { publicKey, privateKey } = security.generateKeypair();

  // Save user
  const hashed = hashPassword(password);
  const newUser = {
    id: Date.now(),
    username,
    email,
    password: hashed,
    bookmarks: [],
    balance: 0,
    totpSecret,
    trustedDevices: [{ fingerprint, salt, userAgent, screen, registeredAt: Date.now() }],
    publicKey,
    // DO NOT save privateKey in server, only in device
  };
  users.push(newUser);
  saveUsers(users);

  // Return QR code (base64), fingerprint, publicKey (send privateKey only to device)
  res.json({
    id: newUser.id,
    username: newUser.username,
    email: newUser.email,
    totpQR: qrCode,
    totpSecret,
    fingerprint,
    publicKey,
    salt
  });
});

// LOGIN multi-entitas
app.post('/login', (req, res) => {
  const { email, password, fingerprint, totp, challengeResponse } = req.body;
  const users = loadUsers();
  const hashed = hashPassword(password);
  const user = users.find(u => u.email === email && u.password === hashed);
  if (!user) return res.status(401).json({ error: 'Email/password salah' });

  // Check fingerprint
  const trusted = user.trustedDevices?.find(d => d.fingerprint === fingerprint);
  if (!trusted) return res.status(403).json({ error: 'Device not trusted' });

  // Verify TOTP
  if (!security.verifyTOTP(user.totpSecret, totp))
    return res.status(403).json({ error: 'Kode TOTP salah' });

  // Challenge-response: simple (just echo), upgrade to real cryptography for full version
  if (challengeResponse !== 'accepted')
    return res.status(403).json({ error: 'Challenge response invalid' });

  // Passed all checks
  const { password: pw, totpSecret, trustedDevices, ...userNoPw } = user;
  res.json(userNoPw);
});

// Endpoint: bind device (add fingerprint)
app.post('/users/:userId/bind-device', (req, res) => {
  const { fingerprint, userAgent, screen, salt } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.trustedDevices?.find(d => d.fingerprint === fingerprint))
    return res.status(400).json({ error: 'Device sudah terdaftar' });

  user.trustedDevices = user.trustedDevices || [];
  user.trustedDevices.push({ fingerprint, salt, userAgent, screen, registeredAt: Date.now() });
  saveUsers(users);
  res.json({ trustedDevices: user.trustedDevices });
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
  if (!user) return res.status(404).json({ error: 'User not found' });
  const nominal = parseInt(amount, 10);
  if (isNaN(nominal) || nominal <= 0) return res.status(400).json({ error: 'Nominal harus lebih dari 0' });
  user.balance = (user.balance || 0) + nominal;
  saveUsers(users);
  res.json({ balance: user.balance });
});

// Withdraw saldo
app.post('/users/:userId/withdraw', (req, res) => {
  const { amount } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const nominal = parseInt(amount, 10);
  if (isNaN(nominal) || nominal <= 0) return res.status(400).json({ error: 'Nominal harus lebih dari 0' });
  if ((user.balance || 0) < nominal) return res.status(400).json({ error: 'Saldo tidak cukup' });
  user.balance -= nominal;
  saveUsers(users);
  res.json({ balance: user.balance });
});

// Transfer saldo ke user lain
app.post('/users/:userId/transfer', (req, res) => {
  const { toUserId, amount } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.id == req.params.userId);
  const toUser = users.find(u => u.id == toUserId);
  if (!user) return res.status(404).json({ error: 'User asal tidak ditemukan' });
  if (!toUser) return res.status(404).json({ error: 'User tujuan tidak ditemukan' });
  const nominal = parseInt(amount, 10);
  if (isNaN(nominal) || nominal <= 0) return res.status(400).json({ error: 'Nominal transfer harus lebih dari 0' });
  if ((user.balance || 0) < nominal) return res.status(400).json({ error: 'Saldo tidak cukup' });
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
app.get('/threads', (req, res) => { res.json(loadThreads()); });
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
  const newThread = {
    id: Date.now(),
    title,
    content,
    author,
    category,
    tags: tags || [],
    isPinned: isPinned || false,
    isLocked: isLocked || false,
    votes: votes || 0,
    createdAt: createdAt || new Date().toISOString(),
    updatedAt: updatedAt || new Date().toISOString()
  };
  threads.push(newThread);
  saveThreads(threads);
  res.json(newThread);
});

// REPLIES
const REPLIES_FILE = './replies.json';
function loadReplies() {
  if (!fs.existsSync(REPLIES_FILE)) return [];
  const data = fs.readFileSync(REPLIES_FILE, 'utf8');
  return data ? JSON.parse(data) : [];
}
function saveReplies(replies) {
  fs.writeFileSync(REPLIES_FILE, JSON.stringify(replies, null, 2));
}
app.get('/replies', (req, res) => {
  const { threadId } = req.query;
  const replies = loadReplies();
  if (threadId) { return res.json(replies.filter(r => r.threadId == threadId)); }
  res.json(replies);
});
app.post('/replies', (req, res) => {
  const { threadId, author, content } = req.body;
  if (!threadId || !author || !content) return res.status(400).json({ error: 'Semua field wajib' });
  const replies = loadReplies();
  const newReply = { id: Date.now(), threadId, author, content, createdAt: Date.now() };
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
