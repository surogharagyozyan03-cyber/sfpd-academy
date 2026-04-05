# SFPD Police Academy

## Деплой на Render.com + Supabase

### Шаг 1 — Supabase (база данных)
1. Зайди на https://supabase.com → Sign Up
2. New Project → придумай название и пароль
3. После создания: Settings → Database → Connection string → выбери "URI"
4. Скопируй строку вида: postgresql://postgres:ПАРОЛЬ@db.xxx.supabase.co:5432/postgres

### Шаг 2 — Render.com (хостинг)
1. Зайди на https://render.com → Sign Up через GitHub
2. New → Web Service → выбери репозиторий sfpd-academy
3. Build Command: npm install
4. Start Command: node server.js
5. В разделе Environment Variables добавь:
   - DATABASE_URL = (строка из Supabase)
   - SESSION_SECRET = любое_случайное_слово
   - ADMIN_NICKNAME = твой_ник (чтобы стать админом)
6. Нажми Deploy

### Как управлять пользователями через Supabase
1. Зайди на supabase.com → твой проект
2. Слева нажми "Table Editor"
3. Выбери таблицу "users"
4. Прямо в таблице меняй:
   - approved = true (дать доступ)
   - can_use_prefix = true (дать префикс)
   - role = admin (сделать админом)
