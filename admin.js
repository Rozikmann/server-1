// Мастер-аккаунт (администратор). Один, задаётся здесь, в коде.
// Репозиторий публичный, поэтому пароль лучше задать на Render
// в переменных окружения ADMIN_LOGIN и ADMIN_PASSWORD.
// Значения ниже работают только для проверки на своём компьютере.
module.exports = {
  login: (process.env.ADMIN_LOGIN || 'admin').toLowerCase(),
  // Имя, которое видно в расписании (логин при этом остаётся для входа)
  name: process.env.ADMIN_NAME || 'Администратор',
  password: process.env.ADMIN_PASSWORD || 'admin',
};