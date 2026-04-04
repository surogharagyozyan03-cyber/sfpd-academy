const Database = require('better-sqlite3');

const db = new Database('./data/sfpd.db');

db.prepare(`
  UPDATE users 
  SET role='admin', approved=1, can_use_prefix=1 
  WHERE nickname='Mayk Fyurze'
`).run();

const u = db.prepare(`
  SELECT nickname, role, approved 
  FROM users 
  WHERE nickname='Mayk Fyurze'
`).get();

console.log(u);
