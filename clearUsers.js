const Database = require('better-sqlite3');

const db = new Database('./data/sfpd.db');

// Удаляем ВСЕХ пользователей
db.prepare("DELETE FROM users").run();

console.log("✅ Все пользователи удалены");
