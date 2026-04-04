# SFPD Police Academy — Система отчётов

## Что включено
- Авторизация / Регистрация с базой данных
- Пароли зашифрованы (bcrypt)
- Сессии хранятся в SQLite
- Создание, просмотр, удаление отчётов
- Смена статуса отчёта (Ожидание / Принято / Отклонено)

## Стек
- **Node.js + Express** — сервер
- **SQLite (better-sqlite3)** — база данных
- **bcryptjs** — шифрование паролей
- **express-session** — сессии

---

## Деплой на Railway (бесплатно)

### Шаг 1 — Загрузи код на GitHub
1. Зайди на https://github.com и создай новый репозиторий (например `sfpd-academy`)
2. Загрузи все файлы проекта в репозиторий

### Шаг 2 — Задеплой на Railway
1. Зайди на https://railway.app
2. Нажми **"New Project"**
3. Выбери **"Deploy from GitHub repo"**
4. Выбери свой репозиторий `sfpd-academy`
5. Railway автоматически найдёт `package.json` и задеплоит

### Шаг 3 — Получи домен
1. В Railway нажми на свой проект
2. Перейди в **Settings → Networking**
3. Нажми **"Generate Domain"**
4. Готово! Сайт будет доступен по ссылке вида `sfpd-academy.up.railway.app`

---

## Локальный запуск (для теста)

```bash
# Установить зависимости
npm install

# Запустить сервер
npm start

# Открыть в браузере
http://localhost:3000
```

---

## Структура файлов

```
sfpd-academy/
├── server.js          ← Сервер + все API маршруты
├── package.json       ← Зависимости
├── railway.toml       ← Конфиг для Railway
├── .gitignore
└── public/
    └── index.html     ← Весь фронтенд (одна страница)
```

## API маршруты

| Метод | URL | Описание |
|-------|-----|----------|
| POST | /api/register | Регистрация |
| POST | /api/login | Вход |
| POST | /api/logout | Выход |
| GET | /api/me | Проверка сессии |
| GET | /api/reports | Все отчёты |
| POST | /api/reports | Создать отчёт |
| PATCH | /api/reports/:id/status | Изменить статус |
| DELETE | /api/reports/:id | Удалить отчёт |
