const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'printing-masterclass-secret-2024';

// ── DATABASE SETUP ──
const db = new Database(path.join(__dirname, 'users.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    progress TEXT DEFAULT '{}',
    quiz_score INTEGER DEFAULT NULL,
    certificate_name TEXT DEFAULT NULL,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

console.log('✅ Database ready: users.db');

// ── MIDDLEWARE ──
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── AUTH MIDDLEWARE ──
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// ══════════════════════════════════════
//  AUTH ROUTES
// ══════════════════════════════════════

// SIGN UP
app.post('/api/signup', (req, res) => {
  const { full_name, email, password } = req.body;
  if (!full_name || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const hashedPassword = bcrypt.hashSync(password, 10);
    const stmt = db.prepare('INSERT INTO users (full_name, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(full_name, email.toLowerCase(), hashedPassword);
    const token = jwt.sign({ id: result.lastInsertRowid, email, full_name }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Account created!', token, user: { id: result.lastInsertRowid, full_name, email } });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// LOG IN
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password are required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'No account found with this email' });

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Incorrect password' });

  const token = jwt.sign({ id: user.id, email: user.email, full_name: user.full_name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    message: 'Welcome back!',
    token,
    user: { id: user.id, full_name: user.full_name, email: user.email, quiz_score: user.quiz_score, certificate_name: user.certificate_name }
  });
});

// ══════════════════════════════════════
//  PROTECTED USER ROUTES
// ══════════════════════════════════════

// GET profile + progress
app.get('/api/me', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT id, full_name, email, progress, quiz_score, certificate_name, joined_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.progress = JSON.parse(user.progress || '{}');
  res.json(user);
});

// SAVE progress (which tabs/lessons completed)
app.post('/api/progress', authenticateToken, (req, res) => {
  const { progress } = req.body;
  db.prepare('UPDATE users SET progress = ? WHERE id = ?').run(JSON.stringify(progress), req.user.id);
  res.json({ message: 'Progress saved' });
});

// SAVE quiz score
app.post('/api/quiz-score', authenticateToken, (req, res) => {
  const { score } = req.body;
  db.prepare('UPDATE users SET quiz_score = ? WHERE id = ?').run(score, req.user.id);
  res.json({ message: 'Score saved' });
});

// SAVE certificate name
app.post('/api/certificate', authenticateToken, (req, res) => {
  const { name } = req.body;
  db.prepare('UPDATE users SET certificate_name = ? WHERE id = ?').run(name, req.user.id);
  res.json({ message: 'Certificate saved' });
});

// ADMIN: list all users (protect with admin secret header)
app.get('/api/admin/users', (req, res) => {
  const adminKey = req.headers['x-admin-key'];
  if (adminKey !== (process.env.ADMIN_KEY || 'dgroup-admin-2024'))
    return res.status(403).json({ error: 'Forbidden' });
  const users = db.prepare('SELECT id, full_name, email, quiz_score, certificate_name, joined_at FROM users ORDER BY joined_at DESC').all();
  res.json({ total: users.length, users });
});

// ── CATCH-ALL: serve frontend ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
