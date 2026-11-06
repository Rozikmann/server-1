const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const admin = require('./admin');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));

const PROD = process.env.NODE_ENV === 'production';
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

if (PROD && admin.password === 'change-me-please') {
  console.warn('ВНИМАНИЕ: задайте ADMIN_PASSWORD в переменных окружения.');
}

/* ---------- файл обычных аккаунтов ---------- */
function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return []; }
}
function saveUsers(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(list, null, 2));
}

/* ---------- пароли ---------- */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(pw, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(pw, salt, 64);
  const real = Buffer.from(hash, 'hex');
  return real.length === test.length && crypto.timingSafeEqual(real, test);
}
function sameText(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}
const DUMMY = hashPassword('dummy');

/* ---------- сессии (в памяти) ---------- */
const sessions = new Map();
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function startSession(res, login, role) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { login, role, exp: Date.now() + SESSION_MS });
  res.cookie('sid', token, {
    httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: SESSION_MS, path: '/',
  });
}
function getSession(req) {
  const token = parseCookies(req).sid;
  const s = token && sessions.get(token);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(token); return null; }
  return s;
}
function dropSessionsOf(login) {
  for (const [t, s] of sessions) if (s.login === login) sessions.delete(t);
}

/* ---------- ограничение попыток входа ---------- */
const fails = new Map();
const MAX_FAILS = 5;
const BLOCK_MS = 10 * 60 * 1000;
function failKey(req, login) { return req.ip + '|' + login; }
function isBlocked(key) {
  const f = fails.get(key);
  if (!f) return 0;
  if (f.until && f.until > Date.now()) return Math.ceil((f.until - Date.now()) / 60000);
  if (f.until) fails.delete(key);
  return 0;
}
function addFail(key) {
  const f = fails.get(key) || { n: 0 };
  f.n += 1;
  if (f.n >= MAX_FAILS) { f.until = Date.now() + BLOCK_MS; f.n = 0; }
  fails.set(key, f);
}

/* ---------- вход / выход ---------- */
app.post('/api/login', (req, res) => {
  const login = String(req.body.login || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!login || !password) return res.status(400).json({ error: 'Введите логин и пароль' });

  const key = failKey(req, login);
  const wait = isBlocked(key);
  if (wait) return res.status(429).json({ error: `Слишком много попыток. Попробуйте через ${wait} мин.` });

  if (login === admin.login) {
    if (sameText(password, admin.password)) {
      fails.delete(key);
      startSession(res, login, 'admin');
      return res.json({ ok: true });
    }
    addFail(key);
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }

  const user = loadUsers().find((u) => u.login === login);
  const ok = verifyPassword(password, user ? user.hash : DUMMY);
  if (!user || !ok) {
    addFail(key);
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  if (user.blocked) return res.status(403).json({ error: 'Аккаунт заблокирован. Обратитесь к администратору' });

  fails.delete(key);
  startSession(res, login, 'user');
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  const token = parseCookies(req).sid;
  if (token) sessions.delete(token);
  res.clearCookie('sid', { path: '/' });
  res.json({ ok: true });
});

function needAuth(req, res, next) {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: 'Нужно войти' });
  req.session = s;
  next();
}
function needAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Только для администратора' });
  next();
}

app.get('/api/me', needAuth, (req, res) => {
  res.json({ login: req.session.login, role: req.session.role });
});

/* ---------- управление аккаунтами (только администратор) ---------- */
const LOGIN_RE = /^[a-z0-9_.+@-]{3,32}$/;

app.get('/api/users', needAuth, needAdmin, (req, res) => {
  res.json(loadUsers().map((u) => ({ login: u.login, blocked: !!u.blocked })));
});

app.post('/api/users', needAuth, needAdmin, (req, res) => {
  const login = String(req.body.login || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!LOGIN_RE.test(login)) return res.status(400).json({ error: 'Логин: 3–32 символа, латиница, цифры, + @ _ . -' });
  if (password.length < 6) return res.status(400).json({ error: 'Пароль: минимум 6 символов' });
  const list = loadUsers();
  if (login === admin.login || list.some((u) => u.login === login)) {
    return res.status(409).json({ error: 'Такой логин уже есть' });
  }
  list.push({ login, hash: hashPassword(password), blocked: false });
  saveUsers(list);
  res.json({ ok: true });
});

app.patch('/api/users/:login', needAuth, needAdmin, (req, res) => {
  const list = loadUsers();
  const user = list.find((u) => u.login === req.params.login);
  if (!user) return res.status(404).json({ error: 'Аккаунт не найден' });
  if (req.body.password !== undefined) {
    const pw = String(req.body.password);
    if (pw.length < 6) return res.status(400).json({ error: 'Пароль: минимум 6 символов' });
    user.hash = hashPassword(pw);
    dropSessionsOf(user.login);
  }
  if (req.body.blocked !== undefined) {
    user.blocked = !!req.body.blocked;
    if (user.blocked) dropSessionsOf(user.login);
  }
  saveUsers(list);
  res.json({ ok: true });
});

app.delete('/api/users/:login', needAuth, needAdmin, (req, res) => {
  const list = loadUsers();
  const next = list.filter((u) => u.login !== req.params.login);
  if (next.length === list.length) return res.status(404).json({ error: 'Аккаунт не найден' });
  saveUsers(next);
  dropSessionsOf(req.params.login);
  res.json({ ok: true });
});

/* ---------- записи (общий календарь) ---------- */
const APPTS_FILE = path.join(DATA_DIR, 'appointments.json');
function loadAppts() {
  try { return JSON.parse(fs.readFileSync(APPTS_FILE, 'utf8')); }
  catch { return []; }
}
function saveAppts(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(APPTS_FILE, JSON.stringify(list, null, 2));
}
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
function toMin(t) { const [h, m] = t.split(':'); return +h * 60 + +m; }

// мастера: администратор и все незаблокированные сотрудники
app.get('/api/masters', needAuth, (req, res) => {
  const list = loadUsers().filter((u) => !u.blocked).map((u) => u.login);
  res.json([admin.login, ...list]);
});

function readAppt(body, masters) {
  const a = {
    client: String(body.client || '').trim().slice(0, 80),
    phone: String(body.phone || '').trim().slice(0, 30),
    service: String(body.service || '').trim().slice(0, 80),
    master: String(body.master || '').trim().toLowerCase(),
    date: String(body.date || ''),
    time: String(body.time || ''),
    duration: parseInt(body.duration, 10),
    note: String(body.note || '').trim().slice(0, 300),
  };
  if (!a.client) return { error: 'Введите имя клиента' };
  if (!a.service) return { error: 'Введите услугу' };
  if (!masters.includes(a.master)) return { error: 'Выберите мастера' };
  if (!DATE_RE.test(a.date) || isNaN(Date.parse(a.date))) return { error: 'Неверная дата' };
  if (!TIME_RE.test(a.time)) return { error: 'Неверное время' };
  if (!(a.duration >= 5 && a.duration <= 600)) return { error: 'Длительность: от 5 до 600 минут' };
  if (toMin(a.time) + a.duration > 24 * 60) return { error: 'Запись не должна уходить за полночь' };
  return { a };
}
function hasOverlap(list, a, skipId) {
  const s = toMin(a.time), e = s + a.duration;
  return list.some((x) => x.id !== skipId && x.master === a.master && x.date === a.date &&
    toMin(x.time) < e && s < toMin(x.time) + x.duration);
}
function allMasters() { return [admin.login, ...loadUsers().filter((u) => !u.blocked).map((u) => u.login)]; }

app.get('/api/appointments', needAuth, (req, res) => {
  const from = String(req.query.from || ''), to = String(req.query.to || '');
  if (!DATE_RE.test(from) || !DATE_RE.test(to)) return res.status(400).json({ error: 'Нужны from и to (ГГГГ-ММ-ДД)' });
  res.json(loadAppts().filter((x) => x.date >= from && x.date <= to));
});

app.post('/api/appointments', needAuth, (req, res) => {
  const r = readAppt(req.body, allMasters());
  if (r.error) return res.status(400).json({ error: r.error });
  const list = loadAppts();
  if (hasOverlap(list, r.a, null)) return res.status(409).json({ error: 'У этого мастера уже есть запись на это время' });
  const item = { id: crypto.randomBytes(6).toString('hex'), ...r.a, createdBy: req.session.login };
  list.push(item);
  saveAppts(list);
  res.json(item);
});

app.put('/api/appointments/:id', needAuth, (req, res) => {
  const list = loadAppts();
  const i = list.findIndex((x) => x.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Запись не найдена' });
  const r = readAppt(req.body, allMasters());
  if (r.error) return res.status(400).json({ error: r.error });
  if (hasOverlap(list, r.a, req.params.id)) return res.status(409).json({ error: 'У этого мастера уже есть запись на это время' });
  list[i] = { ...list[i], ...r.a };
  saveAppts(list);
  res.json(list[i]);
});

app.delete('/api/appointments/:id', needAuth, (req, res) => {
  const list = loadAppts();
  const next = list.filter((x) => x.id !== req.params.id);
  if (next.length === list.length) return res.status(404).json({ error: 'Запись не найдена' });
  saveAppts(next);
  res.json({ ok: true });
});

/* ---------- страницы ---------- */
app.get('/', (req, res) => {
  const file = getSession(req) ? 'app.html' : 'login.html';
  res.sendFile(path.join(__dirname, 'views', file));
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('Сервер запущен на порту ' + port));