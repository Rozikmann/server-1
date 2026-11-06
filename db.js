// db.js — слой работы с данными.
// Сейчас JSON-файлы в ./data. Позже заменяем на Postgres без изменения роутов.

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readJSON(file, fallback) {
  ensureDir();
  const p = path.join(DATA_DIR, file);
  try {
    if (!fs.existsSync(p)) return fallback;
    const raw = fs.readFileSync(p, 'utf8').trim();
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch (e) {
    console.error(`[db] read ${file} failed:`, e.message);
    return fallback;
  }
}

function writeJSON(file, data) {
  ensureDir();
  const p = path.join(DATA_DIR, file);
  const tmp = p + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, p);
}

// ---------- users ----------
function getUsers() {
  return readJSON('users.json', []);
}
function saveUsers(users) {
  writeJSON('users.json', users);
}
function normalizeLogin(login) {
  return String(login || '').trim().toLowerCase();
}
function findUserByLogin(login) {
  const norm = normalizeLogin(login);
  return getUsers().find(u => normalizeLogin(u.login) === norm) || null;
}
function addUser(user) {
  const users = getUsers();
  users.push(user);
  saveUsers(users);
  return user;
}
function updateUser(login, patch) {
  const users = getUsers();
  const norm = normalizeLogin(login);
  const idx = users.findIndex(u => normalizeLogin(u.login) === norm);
  if (idx === -1) return null;
  users[idx] = { ...users[idx], ...patch };
  saveUsers(users);
  return users[idx];
}
function deleteUser(login) {
  const users = getUsers();
  const norm = normalizeLogin(login);
  const next = users.filter(u => normalizeLogin(u.login) !== norm);
  saveUsers(next);
  return next.length !== users.length;
}

// ---------- clients ----------
function getClients() {
  return readJSON('clients.json', []);
}
function saveClients(clients) {
  writeJSON('clients.json', clients);
}
function addClient(client) {
  const clients = getClients();
  const item = { id: Date.now().toString(36), createdAt: new Date().toISOString(), ...client };
  clients.push(item);
  saveClients(clients);
  return item;
}
function findClientByPhone(phone) {
  const norm = String(phone || '').replace(/\D/g, '');
  return getClients().find(c => String(c.phone || '').replace(/\D/g, '') === norm) || null;
}

// ---------- appointments ----------
function getAppointments() {
  return readJSON('appointments.json', []);
}
function saveAppointments(list) {
  writeJSON('appointments.json', list);
}
function addAppointment(appt) {
  const list = getAppointments();
  const item = { id: Date.now().toString(36), createdAt: new Date().toISOString(), ...appt };
  list.push(item);
  saveAppointments(list);
  return item;
}
function updateAppointment(id, patch) {
  const list = getAppointments();
  const idx = list.findIndex(a => a.id === id);
  if (idx === -1) return null;
  list[idx] = { ...list[idx], ...patch, updatedAt: new Date().toISOString() };
  saveAppointments(list);
  return list[idx];
}
function deleteAppointment(id) {
  const list = getAppointments();
  const next = list.filter(a => a.id !== id);
  saveAppointments(next);
  return next.length !== list.length;
}
function getAppointmentsBetween(fromISO, toISO) {
  const from = new Date(fromISO).getTime();
  const to = new Date(toISO).getTime();
  return getAppointments().filter(a => {
    const t = new Date(a.start).getTime();
    return t >= from && t <= to;
  });
}

module.exports = {
  normalizeLogin,
  getUsers, saveUsers, findUserByLogin, addUser, updateUser, deleteUser,
  getClients, saveClients, addClient, findClientByPhone,
  getAppointments, saveAppointments, addAppointment,
  updateAppointment, deleteAppointment, getAppointmentsBetween
};