const Database = require('better-sqlite3');

// создаст файл прямо в /app
const db = new Database('sfpd.db');

// очистка пользователей
db.prepare("DELETE FROM users").run();

console.log("✅ Все пользователи удалены");
process.exit();
