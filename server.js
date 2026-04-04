const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Папка data/ — на Railway подключи Volume на путь /app/data
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'sfpd.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    vk_page TEXT,
    role TEXT DEFAULT 'instructor',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    cadet TEXT NOT NULL,
    exam_type TEXT NOT NULL,
    instructor TEXT NOT NULL,
    exam_date TEXT,
    screenshot_link TEXT NOT NULL,
    note TEXT,
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'sfpd-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

app.post('/api/register', (req, res) => {
  const { nickname, password, vk_page } = req.body;
  if (!nickname || !password || !vk_page) return res.json({ success: false, error: 'Заполните все поля' });
  if (password.length < 6) return res.json({ success: false, error: 'Пароль минимум 6 символов' });
  const existing = db.prepare('SELECT id FROM users WHERE nickname = ?').get(nickname);
  if (existing) return res.json({ success: false, error: 'Никнейм уже занят' });
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (nickname, password, vk_page) VALUES (?, ?, ?)').run(nickname, hash, vk_page);
  req.session.userId = result.lastInsertRowid;
  req.session.nickname = nickname;
  res.json({ success: true, nickname });
});

app.post('/api/login', (req, res) => {
  const { nickname, password } = req.body;
  if (!nickname || !password) return res.json({ success: false, error: 'Заполните все поля' });
  const user = db.prepare('SELECT * FROM users WHERE nickname = ?').get(nickname);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.json({ success: false, error: 'Неверный никнейм или пароль' });
  req.session.userId = user.id;
  req.session.nickname = user.nickname;
  res.json({ success: true, nickname: user.nickname });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', (req, res) => {
  if (req.session.userId) res.json({ loggedIn: true, nickname: req.session.nickname });
  else res.json({ loggedIn: false });
});

// Только МОИ отчёты
app.get('/api/reports/my', requireAuth, (req, res) => {
  const reports = db.prepare('SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC').all(req.session.userId);
  res.json({ success: true, reports });
});

// ВСЕ отчёты (общий список)
app.get('/api/reports/all', requireAuth, (req, res) => {
  const reports = db.prepare(`
    SELECT r.*, u.nickname as author_nickname
    FROM reports r JOIN users u ON r.user_id = u.id
    ORDER BY r.created_at DESC
  `).all();
  res.json({ success: true, reports });
});

// Создать отчёт
app.post('/api/reports', requireAuth, (req, res) => {
  const { cadet, exam_type, instructor, exam_date, screenshot_link, note } = req.body;
  if (!cadet || !exam_type || !instructor || !screenshot_link) return res.json({ success: false, error: 'Заполните все обязательные поля' });
  const result = db.prepare(
    'INSERT INTO reports (user_id, cadet, exam_type, instructor, exam_date, screenshot_link, note) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(req.session.userId, cadet, exam_type, instructor, exam_date || null, screenshot_link, note || null);
  const report = db.prepare('SELECT * FROM reports WHERE id = ?').get(result.lastInsertRowid);
  res.json({ success: true, report });
});

// Изменить статус
app.patch('/api/reports/:id/status', requireAuth, (req, res) => {
  const { status } = req.body;
  if (!['pending', 'approved', 'rejected'].includes(status)) return res.json({ success: false, error: 'Неверный статус' });
  db.prepare('UPDATE reports SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ success: true });
});

// Удалить (только свой отчёт)
app.delete('/api/reports/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM reports WHERE id = ? AND user_id = ?').run(req.params.id, req.session.userId);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`SFPD Academy запущен на http://localhost:${PORT}`);
  console.log(`База данных: ${path.join(DATA_DIR, 'sfpd.db')}`);
});
