const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'sfpd.db'));

// ── СОЗДАНИЕ ТАБЛИЦ ───────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    nickname        TEXT    UNIQUE NOT NULL,
    password_hash   TEXT    NOT NULL,
    vk_page         TEXT,
    position        TEXT    DEFAULT 'Trainee of PA',
    role            TEXT    DEFAULT 'user',
    approved        INTEGER DEFAULT 0,
    can_use_prefix  INTEGER DEFAULT 0,
    ip_address      TEXT,
    reg_ip          TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login      DATETIME,
    notes           TEXT
  );
  CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    cadet           TEXT    NOT NULL,
    exam_type       TEXT    NOT NULL,
    instructor      TEXT    NOT NULL,
    exam_date       TEXT,
    screenshot_link TEXT    NOT NULL,
    note            TEXT,
    status          TEXT    DEFAULT 'pending',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS login_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    login_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    success    INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS prefixes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    prefix   TEXT    NOT NULL,
    given_by TEXT,
    given_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    active   INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Миграции для старых БД
[
  "ALTER TABLE users ADD COLUMN password_hash TEXT",
  "ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 0",
  "ALTER TABLE users ADD COLUMN can_use_prefix INTEGER DEFAULT 0",
  "ALTER TABLE users ADD COLUMN ip_address TEXT",
  "ALTER TABLE users ADD COLUMN reg_ip TEXT",
  "ALTER TABLE users ADD COLUMN last_login DATETIME",
  "ALTER TABLE users ADD COLUMN notes TEXT",
  "ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'",
  "ALTER TABLE users ADD COLUMN position TEXT DEFAULT 'Trainee of PA'",
].forEach(sql => { try { db.exec(sql); } catch(e) {} });

// Если есть старое поле password — переносим в password_hash
try {
  const cols = db.prepare("PRAGMA table_info(users)").all().map(r => r.name);
  if (cols.includes('password') && cols.includes('password_hash')) {
    db.exec("UPDATE users SET password_hash = password WHERE password_hash IS NULL");
  }
} catch(e) {}

// Первый пользователь автоматически становится admin с доступом
(function ensureAdmin() {
  const admin = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
  if (!admin) {
    const first = db.prepare("SELECT id FROM users ORDER BY id ASC LIMIT 1").get();
    if (first) db.prepare("UPDATE users SET role='admin', approved=1, can_use_prefix=1 WHERE id=?").run(first.id);
  }
})();

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
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

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const user = db.prepare('SELECT role FROM users WHERE id=?').get(req.session.userId);
  if (!user || user.role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  next();
}

// ── РЕГИСТРАЦИЯ ───────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { nickname, password, vk_page } = req.body;
  if (!nickname || !password || !vk_page) return res.json({ success: false, error: 'Заполните все поля' });
  if (password.length < 6) return res.json({ success: false, error: 'Пароль минимум 6 символов' });

  const existing = db.prepare('SELECT id FROM users WHERE nickname=?').get(nickname);
  if (existing) return res.json({ success: false, error: 'Никнейм уже занят' });

  const hash = bcrypt.hashSync(password, 10);
  const ip = getIP(req);

  // Первый зарегистрировавшийся = admin с полным доступом
  const isFirst = db.prepare('SELECT COUNT(*) as c FROM users').get().c === 0;
  const result = db.prepare(
    'INSERT INTO users (nickname, password_hash, vk_page, reg_ip, ip_address, approved, can_use_prefix, role) VALUES (?,?,?,?,?,?,?,?)'
  ).run(nickname, hash, vk_page, ip, ip, isFirst ? 1 : 0, isFirst ? 1 : 0, isFirst ? 'admin' : 'user');

  req.session.userId = result.lastInsertRowid;
  req.session.nickname = nickname;

  if (!isFirst) {
    // Новый пользователь — ждёт одобрения
    return res.json({ success: false, pending: true, error: 'Аккаунт создан. Ожидайте одобрения от администратора.' });
  }

  res.json({ success: true, nickname });
});

// ── ВХОД ──────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { nickname, password } = req.body;
  if (!nickname || !password) return res.json({ success: false, error: 'Заполните все поля' });

  const user = db.prepare('SELECT * FROM users WHERE nickname=?').get(nickname);
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';

  if (!user) {
    return res.json({ success: false, error: 'Неверный никнейм или пароль' });
  }

  const passField = user.password_hash || user.password;
  if (!bcrypt.compareSync(password, passField)) {
    // Логируем неудачный вход
    db.prepare('INSERT INTO login_logs (user_id, ip_address, user_agent, success) VALUES (?,?,?,0)').run(user.id, ip, ua);
    return res.json({ success: false, error: 'Неверный никнейм или пароль' });
  }

  if (!user.approved) {
    db.prepare('INSERT INTO login_logs (user_id, ip_address, user_agent, success) VALUES (?,?,?,0)').run(user.id, ip, ua);
    return res.json({ success: false, error: 'Ваш аккаунт ожидает одобрения администратора' });
  }

  // Успешный вход
  db.prepare('UPDATE users SET last_login=CURRENT_TIMESTAMP, ip_address=? WHERE id=?').run(ip, user.id);
  db.prepare('INSERT INTO login_logs (user_id, ip_address, user_agent, success) VALUES (?,?,?,1)').run(user.id, ip, ua);

  req.session.userId = user.id;
  req.session.nickname = user.nickname;

  res.json({
    success: true,
    nickname: user.nickname,
    position: user.position,
    role: user.role,
    vk_page: user.vk_page,
    can_use_prefix: user.can_use_prefix,
    created_at: user.created_at
  });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  const user = db.prepare('SELECT id, nickname, vk_page, position, role, can_use_prefix, created_at FROM users WHERE id=?').get(req.session.userId);
  if (!user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, ...user });
});

// ── ПРОФИЛЬ ───────────────────────────────────────────────────────────────────
app.patch('/api/profile/position', requireAuth, (req, res) => {
  const { position } = req.body;
  const allowed = ['Chief of PA','Dep.Chief of PA','Inspector of PA','Instructor of PA','Trainee of PA'];
  if (!allowed.includes(position)) return res.json({ success: false, error: 'Неверная должность' });
  // Проверяем: Chief и Dep.Chief только если есть can_use_prefix
  const user = db.prepare('SELECT can_use_prefix FROM users WHERE id=?').get(req.session.userId);
  if (['Chief of PA','Dep.Chief of PA'].includes(position) && !user.can_use_prefix) {
    return res.json({ success: false, error: 'Нет доступа к этой должности' });
  }
  db.prepare('UPDATE users SET position=? WHERE id=?').run(position, req.session.userId);
  res.json({ success: true });
});

app.patch('/api/profile/password', requireAuth, (req, res) => {
  const { old_password, new_password } = req.body;
  if (!old_password || !new_password) return res.json({ success: false, error: 'Заполните все поля' });
  if (new_password.length < 6) return res.json({ success: false, error: 'Минимум 6 символов' });
  const user = db.prepare('SELECT password_hash, password FROM users WHERE id=?').get(req.session.userId);
  const passField = user.password_hash || user.password;
  if (!bcrypt.compareSync(old_password, passField)) return res.json({ success: false, error: 'Неверный текущий пароль' });
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(new_password, 10), req.session.userId);
  res.json({ success: true });
});

// ── ADMIN: ПОЛЬЗОВАТЕЛИ ───────────────────────────────────────────────────────
// Список всех пользователей
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT id, nickname, vk_page, position, role, approved, can_use_prefix,
           ip_address, reg_ip, created_at, last_login, notes
    FROM users ORDER BY created_at DESC
  `).all();
  res.json({ success: true, users });
});

// Одобрить/заблокировать
app.patch('/api/admin/users/:id/approved', requireAdmin, (req, res) => {
  const { approved } = req.body;
  db.prepare('UPDATE users SET approved=? WHERE id=?').run(approved ? 1 : 0, req.params.id);
  res.json({ success: true });
});

// Дать/забрать доступ к префиксу
app.patch('/api/admin/users/:id/prefix', requireAdmin, (req, res) => {
  const { can_use_prefix } = req.body;
  db.prepare('UPDATE users SET can_use_prefix=? WHERE id=?').run(can_use_prefix ? 1 : 0, req.params.id);
  res.json({ success: true });
});

// Сменить роль
app.patch('/api/admin/users/:id/role', requireAdmin, (req, res) => {
  const { role } = req.body;
  if (!['user','admin'].includes(role)) return res.json({ success: false, error: 'Неверная роль' });
  db.prepare('UPDATE users SET role=? WHERE id=?').run(role, req.params.id);
  res.json({ success: true });
});

// Заметка об игроке
app.patch('/api/admin/users/:id/notes', requireAdmin, (req, res) => {
  const { notes } = req.body;
  db.prepare('UPDATE users SET notes=? WHERE id=?').run(notes || '', req.params.id);
  res.json({ success: true });
});

// Удалить пользователя
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  if (req.params.id == req.session.userId) return res.json({ success: false, error: 'Нельзя удалить себя' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// Логи входов пользователя
app.get('/api/admin/users/:id/logs', requireAdmin, (req, res) => {
  const logs = db.prepare('SELECT * FROM login_logs WHERE user_id=? ORDER BY login_at DESC LIMIT 20').all(req.params.id);
  res.json({ success: true, logs });
});

// ── ОТЧЁТЫ ────────────────────────────────────────────────────────────────────
app.get('/api/reports/my', requireAuth, (req, res) => {
  const reports = db.prepare('SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC').all(req.session.userId);
  res.json({ success: true, reports });
});

app.get('/api/reports/all', requireAuth, (req, res) => {
  const reports = db.prepare(`
    SELECT r.*, u.nickname as author_nickname
    FROM reports r JOIN users u ON r.user_id=u.id
    ORDER BY r.created_at DESC
  `).all();
  res.json({ success: true, reports });
});

app.post('/api/reports', requireAuth, (req, res) => {
  const { cadet, exam_type, instructor, exam_date, screenshot_link, note } = req.body;
  if (!cadet || !exam_type || !instructor || !screenshot_link) return res.json({ success: false, error: 'Заполните все обязательные поля' });
  const result = db.prepare(
    'INSERT INTO reports (user_id,cadet,exam_type,instructor,exam_date,screenshot_link,note) VALUES (?,?,?,?,?,?,?)'
  ).run(req.session.userId, cadet, exam_type, instructor, exam_date||null, screenshot_link, note||null);
  const report = db.prepare('SELECT * FROM reports WHERE id=?').get(result.lastInsertRowid);
  res.json({ success: true, report });
});

app.patch('/api/reports/:id/status', requireAuth, (req, res) => {
  const { status } = req.body;
  if (!['pending','approved','rejected'].includes(status)) return res.json({ success: false, error: 'Неверный статус' });
  db.prepare('UPDATE reports SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ success: true });
});

app.delete('/api/reports/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM reports WHERE id=? AND user_id=?').run(req.params.id, req.session.userId);
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`SFPD Academy: http://localhost:${PORT}`));
