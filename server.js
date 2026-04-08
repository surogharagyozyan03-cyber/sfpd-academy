const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ── ПОДКЛЮЧЕНИЕ К SUPABASE ────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ── СОЗДАНИЕ ТАБЛИЦ ───────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id              SERIAL PRIMARY KEY,
      nickname        TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      vk_page         TEXT,
      position        TEXT DEFAULT 'Trainee of PA',
      role            TEXT DEFAULT 'user',
      approved        BOOLEAN DEFAULT FALSE,
      can_use_prefix  BOOLEAN DEFAULT FALSE,
      ip_address      TEXT,
      reg_ip          TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      last_login      TIMESTAMPTZ,
      notes           TEXT
    );

    CREATE TABLE IF NOT EXISTS reports (
      id              SERIAL PRIMARY KEY,
      user_id         INTEGER NOT NULL REFERENCES users(id),
      cadet           TEXT NOT NULL,
      exam_type       TEXT NOT NULL,
      instructor      TEXT NOT NULL,
      exam_date       TEXT,
      screenshot_link TEXT NOT NULL,
      note            TEXT,
      status          TEXT DEFAULT 'pending',
      reviewed_by     TEXT,
      reviewed_at     TIMESTAMPTZ,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    );
    -- Миграция: добавляем поля если их нет
    ALTER TABLE reports ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
    ALTER TABLE reports ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

    -- Таблица состава академии
    CREATE TABLE IF NOT EXISTS roster (
      id              SERIAL PRIMARY KEY,
      section         TEXT NOT NULL DEFAULT 'staff',
      position        TEXT,
      rank            TEXT,
      appointed_date  TEXT,
      last_promotion  TEXT,
      next_promotion  TEXT,
      personal_file   TEXT,
      promotion_status TEXT DEFAULT 'Рано',
      warnings        TEXT DEFAULT '0/3',
      sort_order      INTEGER DEFAULT 0,
      updated_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_by      TEXT
    );

    CREATE TABLE IF NOT EXISTS login_logs (
      id          SERIAL PRIMARY KEY,
      user_id     INTEGER NOT NULL REFERENCES users(id),
      ip_address  TEXT,
      user_agent  TEXT,
      login_at    TIMESTAMPTZ DEFAULT NOW(),
      success     BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS prefixes (
      id        SERIAL PRIMARY KEY,
      user_id   INTEGER NOT NULL REFERENCES users(id),
      prefix    TEXT NOT NULL,
      given_by  TEXT,
      given_at  TIMESTAMPTZ DEFAULT NOW(),
      active    BOOLEAN DEFAULT TRUE
    );
    CREATE TABLE IF NOT EXISTS roster (
      id            SERIAL PRIMARY KEY,
      section       TEXT NOT NULL DEFAULT 'main',
      sort_order    INTEGER DEFAULT 0,
      full_name     TEXT DEFAULT '',
      rank          TEXT DEFAULT '',
      position      TEXT DEFAULT '',
      date_assigned TEXT DEFAULT '',
      date_last_up  TEXT DEFAULT '',
      personal_link TEXT DEFAULT '',
      admission     TEXT DEFAULT 'Рано',
      warnings      TEXT DEFAULT '0/3',
      updated_at    TIMESTAMPTZ DEFAULT NOW(),
      updated_by    TEXT DEFAULT ''
    );
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS sort_order INTEGER DEFAULT 0;
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS full_name TEXT DEFAULT '';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS rank TEXT DEFAULT '';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS position TEXT DEFAULT '';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS date_assigned TEXT DEFAULT '';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS date_last_up TEXT DEFAULT '';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS personal_link TEXT DEFAULT '';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS admission TEXT DEFAULT 'Рано';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS warnings TEXT DEFAULT '0/3';
    ALTER TABLE roster ADD COLUMN IF NOT EXISTS updated_by TEXT DEFAULT '';
  `);

  // Если задана переменная ADMIN_NICKNAME — делаем этого пользователя админом
  const adminNick = process.env.ADMIN_NICKNAME;
  if (adminNick) {
    await pool.query(
      "UPDATE users SET role='admin', approved=TRUE, can_use_prefix=TRUE WHERE nickname=$1",
      [adminNick]
    );
    console.log(`Admin set: ${adminNick}`);
  }

  console.log('БД готова');
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new pgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'sfpd-secret-2024',
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
async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const { rows } = await pool.query('SELECT role FROM users WHERE id=$1', [req.session.userId]);
  if (!rows[0] || rows[0].role !== 'admin') return res.status(403).json({ error: 'Нет прав' });
  next();
}

// Moderator или Admin
async function requireMod(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  const { rows } = await pool.query('SELECT role FROM users WHERE id=$1', [req.session.userId]);
  if (!rows[0] || !['admin','moderator'].includes(rows[0].role)) return res.status(403).json({ error: 'Нет прав' });
  next();
}

// ── РЕГИСТРАЦИЯ ───────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { nickname, password, vk_page } = req.body;
  if (!nickname || !password || !vk_page) return res.json({ success: false, error: 'Заполните все поля' });
  if (password.length < 6) return res.json({ success: false, error: 'Пароль минимум 6 символов' });

  const existing = await pool.query('SELECT id FROM users WHERE nickname=$1', [nickname]);
  if (existing.rows.length) return res.json({ success: false, error: 'Никнейм уже занят' });

  const hash = bcrypt.hashSync(password, 10);
  const ip = getIP(req);
  const count = await pool.query('SELECT COUNT(*) FROM users');
  const isFirst = count.rows[0].count === '0';

  const result = await pool.query(
    'INSERT INTO users (nickname, password_hash, vk_page, reg_ip, ip_address, approved, can_use_prefix, role, position) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
    [nickname, hash, vk_page, ip, ip, isFirst, isFirst, isFirst ? 'admin' : 'user', isFirst ? 'Chief of PA' : 'Игрок']
  );

  if (!isFirst) {
    return res.json({ success: false, pending: true, error: 'Аккаунт создан. Ожидайте одобрения администратора.' });
  }

  req.session.userId = result.rows[0].id;
  req.session.nickname = nickname;
  res.json({ success: true, nickname });
});

// ── ВХОД ──────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { nickname, password } = req.body;
  if (!nickname || !password) return res.json({ success: false, error: 'Заполните все поля' });

  const { rows } = await pool.query('SELECT * FROM users WHERE nickname=$1', [nickname]);
  const user = rows[0];
  const ip = getIP(req);
  const ua = req.headers['user-agent'] || '';

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    if (user) await pool.query('INSERT INTO login_logs (user_id,ip_address,user_agent,success) VALUES ($1,$2,$3,FALSE)', [user.id, ip, ua]);
    return res.json({ success: false, error: 'Неверный никнейм или пароль' });
  }

  if (!user.approved) {
    await pool.query('INSERT INTO login_logs (user_id,ip_address,user_agent,success) VALUES ($1,$2,$3,FALSE)', [user.id, ip, ua]);
    return res.json({ success: false, not_approved: true, error: 'Ваш аккаунт ожидает одобрения администратора' });
  }

  await pool.query('UPDATE users SET last_login=NOW(), ip_address=$1 WHERE id=$2', [ip, user.id]);
  await pool.query('INSERT INTO login_logs (user_id,ip_address,user_agent,success) VALUES ($1,$2,$3,TRUE)', [user.id, ip, ua]);

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

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  const { rows } = await pool.query('SELECT id,nickname,vk_page,position,role,can_use_prefix,created_at FROM users WHERE id=$1', [req.session.userId]);
  if (!rows[0]) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, ...rows[0] });
});

// ── ПРОФИЛЬ ───────────────────────────────────────────────────────────────────
app.patch('/api/profile/position', requireAuth, async (req, res) => {
  const { position } = req.body;
  const allowed = ['Chief of PA','Dep.Chief of PA','Inspector of PA','Instructor of PA','Trainee of PA'];
  if (!allowed.includes(position)) return res.json({ success: false, error: 'Неверная должность' });
  // Проверяем: только если есть can_use_prefix можно менять должность (не Trainee и не Игрок)
  const { rows } = await pool.query('SELECT can_use_prefix, role FROM users WHERE id=$1', [req.session.userId]);
  const user = rows[0];
  // Только admin/moderator может менять должность. Обычный игрок не может.
  if (!['admin','moderator'].includes(user.role) && !user.can_use_prefix) {
    return res.json({ success: false, error: 'Нет доступа к выбору должности. Обратитесь к администратору.' });
  }
  // Если обычный пользователь с префиксом — не может сменить сам
  if (user.role === 'user') {
    return res.json({ success: false, error: 'Должность назначается только администратором или модератором.' });
  }
  await pool.query('UPDATE users SET position=$1 WHERE id=$2', [position, req.session.userId]);
  res.json({ success: true });
});

app.patch('/api/profile/password', requireAuth, async (req, res) => {
  const { old_password, new_password } = req.body;
  if (!old_password || !new_password) return res.json({ success: false, error: 'Заполните все поля' });
  if (new_password.length < 6) return res.json({ success: false, error: 'Минимум 6 символов' });
  const { rows } = await pool.query('SELECT password_hash FROM users WHERE id=$1', [req.session.userId]);
  if (!bcrypt.compareSync(old_password, rows[0].password_hash)) return res.json({ success: false, error: 'Неверный текущий пароль' });
  await pool.query('UPDATE users SET password_hash=$1 WHERE id=$2', [bcrypt.hashSync(new_password, 10), req.session.userId]);
  res.json({ success: true });
});

// ── ADMIN: ПОЛЬЗОВАТЕЛИ ───────────────────────────────────────────────────────
app.get('/api/admin/users', requireMod, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT id, nickname, vk_page, position, role, approved, can_use_prefix,
           ip_address, reg_ip, created_at, last_login, notes
    FROM users ORDER BY created_at DESC
  `);
  res.json({ success: true, users: rows });
});

app.patch('/api/admin/users/:id/approved', requireMod, async (req, res) => {
  await pool.query('UPDATE users SET approved=$1 WHERE id=$2', [req.body.approved, req.params.id]);
  res.json({ success: true });
});

app.patch('/api/admin/users/:id/prefix', requireMod, async (req, res) => {
  await pool.query('UPDATE users SET can_use_prefix=$1 WHERE id=$2', [req.body.can_use_prefix, req.params.id]);
  res.json({ success: true });
});

app.patch('/api/admin/users/:id/role', requireAdmin, async (req, res) => {
  const { role } = req.body;
  if (!['user','admin','moderator'].includes(role)) return res.json({ success: false, error: 'Неверная роль' });
  await pool.query('UPDATE users SET role=$1 WHERE id=$2', [role, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  if (req.params.id == req.session.userId) return res.json({ success: false, error: 'Нельзя удалить себя' });
  const id = req.params.id;
  // Удаляем все связанные данные перед удалением пользователя
  await pool.query('DELETE FROM login_logs WHERE user_id=$1', [id]);
  await pool.query('DELETE FROM prefixes WHERE user_id=$1', [id]);
  await pool.query('DELETE FROM reports WHERE user_id=$1', [id]);
  await pool.query('DELETE FROM users WHERE id=$1', [id]);
  res.json({ success: true });
});

// Выдать конкретный префикс пользователю
app.patch('/api/admin/users/:id/give-prefix', requireMod, async (req, res) => {
  const { prefix_label } = req.body;
  const allowed = ['Chief of PA','Dep.Chief of PA','Inspector of PA','Instructor of PA','Trainee of PA'];
  if (!allowed.includes(prefix_label)) return res.json({ success: false, error: 'Неверный префикс' });
  await pool.query('UPDATE users SET can_use_prefix=TRUE, position=$1 WHERE id=$2', [prefix_label, req.params.id]);
  res.json({ success: true });
});

// ── СОСТАВ АКАДЕМИИ ──────────────────────────────────────────────────────────
// Получить весь состав
app.get('/api/roster', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM roster ORDER BY sort_order ASC, id ASC');
  res.json({ success: true, roster: rows });
});

// Добавить строку
app.post('/api/roster', requireAuth, async (req, res) => {
  const { section, position, sort_order } = req.body;
  const { rows } = await pool.query(
    'INSERT INTO roster (section, position, sort_order, updated_by) VALUES ($1,$2,$3,$4) RETURNING *',
    [section||'staff', position||'', sort_order||0, req.session.nickname]
  );
  res.json({ success: true, row: rows[0] });
});

// Обновить поле строки
app.patch('/api/roster/:id', requireAuth, async (req, res) => {
  const allowed = ['position','rank','appointed_date','last_promotion','next_promotion','personal_file','promotion_status','warnings','sort_order','section'];
  const updates = [];
  const vals = [];
  let i = 1;
  for (const [k, v] of Object.entries(req.body)) {
    if (allowed.includes(k)) {
      updates.push(`${k}=$${i++}`);
      vals.push(v);
    }
  }
  if (!updates.length) return res.json({ success: false, error: 'Нет данных' });
  updates.push(`updated_at=NOW()`, `updated_by=$${i++}`);
  vals.push(req.session.nickname, req.params.id);
  await pool.query(`UPDATE roster SET ${updates.join(',')} WHERE id=$${i}`, vals);
  res.json({ success: true });
});

// Удалить строку
app.delete('/api/roster/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM roster WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// ── ОТЧЁТЫ ────────────────────────────────────────────────────────────────────
app.get('/api/reports/my', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM reports WHERE user_id=$1 ORDER BY created_at DESC', [req.session.userId]);
  res.json({ success: true, reports: rows });
});

app.get('/api/reports/all', requireAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT r.*, u.nickname as author_nickname
    FROM reports r JOIN users u ON r.user_id=u.id
    ORDER BY r.created_at DESC
  `);
  res.json({ success: true, reports: rows });
});

app.post('/api/reports', requireAuth, async (req, res) => {
  const { cadet, exam_type, instructor, exam_date, screenshot_link, note } = req.body;
  if (!cadet || !exam_type || !instructor || !screenshot_link) return res.json({ success: false, error: 'Заполните все обязательные поля' });
  // Проверяем что пользователь не "Игрок"
  const { rows: ur } = await pool.query('SELECT position, role FROM users WHERE id=$1', [req.session.userId]);
  if (ur[0] && ur[0].position === 'Игрок' && ur[0].role === 'user') {
    return res.json({ success: false, error: 'Нет прав для создания отчётов' });
  }
  const { rows } = await pool.query(
    'INSERT INTO reports (user_id,cadet,exam_type,instructor,exam_date,screenshot_link,note) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [req.session.userId, cadet, exam_type, instructor, exam_date||null, screenshot_link, note||null]
  );
  res.json({ success: true, report: rows[0] });
});

app.patch('/api/reports/:id/status', requireAuth, async (req, res) => {
  const { status } = req.body;
  if (!['pending','approved','rejected'].includes(status)) return res.json({ success: false, error: 'Неверный статус' });
  // Сохраняем кто проверил
  await pool.query('UPDATE reports SET status=$1, reviewed_by=$2, reviewed_at=NOW() WHERE id=$3',
    [status, req.session.nickname, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/reports/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM reports WHERE id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
  res.json({ success: true });
});

// ── ЗАПУСК ────────────────────────────────────────────────────────────────────
// Запускаем сервер сразу — даже если БД ещё не готова
// ── ROSTER API ───────────────────────────────────────────────────────────────
app.get('/api/roster', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM roster ORDER BY section, sort_order, id');
  res.json({ success: true, rows });
});

app.post('/api/roster', requireAuth, async (req, res) => {
  const { section } = req.body;
  const count = await pool.query('SELECT COUNT(*) FROM roster WHERE section=$1', [section]);
  const { rows } = await pool.query(
    'INSERT INTO roster (section, sort_order, updated_by) VALUES ($1,$2,$3) RETURNING *',
    [section || 'main', parseInt(count.rows[0].count), req.session.nickname]
  );
  res.json({ success: true, row: rows[0] });
});

app.post('/api/roster/full', requireAuth, async (req, res) => {
  const { section, full_name, rank, position, date_assigned, date_last_up, personal_link, admission, warnings } = req.body;
  if (!full_name || !rank || !position || !section) return res.json({ success: false, error: 'Заполните обязательные поля' });
  const count = await pool.query('SELECT COUNT(*) FROM roster WHERE section=$1', [section]);
  const { rows } = await pool.query(
    `INSERT INTO roster (section, sort_order, full_name, rank, position, date_assigned, date_last_up, personal_link, admission, warnings, updated_by)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
    [section, parseInt(count.rows[0].count), full_name, rank, position,
     date_assigned||'', date_last_up||'', personal_link||'', admission||'Рано', warnings||'0/3', req.session.nickname]
  );
  res.json({ success: true, row: rows[0] });
});

app.patch('/api/roster/:id', requireAuth, async (req, res) => {
  const { field, value } = req.body;
  const allowed = ['full_name','rank','position','date_assigned','date_last_up','date_next_up','personal_link','admission','warnings','sort_order'];
  if (!allowed.includes(field)) return res.json({ success: false, error: 'Неверное поле' });
  await pool.query(
    `UPDATE roster SET ${field}=$1, updated_at=NOW(), updated_by=$2 WHERE id=$3`,
    [value, req.session.nickname, req.params.id]
  );
  res.json({ success: true });
});

app.delete('/api/roster/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM roster WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`SFPD Academy: http://localhost:${PORT}`));

// Подключаемся к БД с повторными попытками
async function connectWithRetry(attempts = 10) {
  for (let i = 1; i <= attempts; i++) {
    try {
      await initDB();
      console.log('БД подключена успешно!');
      return;
    } catch (err) {
      console.error(`Попытка ${i}/${attempts} не удалась:`, err.message);
      if (i < attempts) await new Promise(r => setTimeout(r, 3000));
    }
  }
  console.error('Не удалось подключиться к БД после всех попыток');
}
connectWithRetry();
