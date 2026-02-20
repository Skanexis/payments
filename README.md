# Crypto Payment Bot + Admin

Проект: сервис выставления крипто-платежей с админкой, логами и автоподтверждением входящих переводов на ваш TrustWallet адрес.

## Полный гайд по IONOS VPS

Пошаговый прод деплой на IONOS (DNS, Git, Nginx с несколькими поддоменами без конфликтов, SSL, systemd, TrustWallet/API ключи):

- `DEPLOY_IONOS.md`

## Гайд по использованию (админ + пользователь)

Пошаговая эксплуатация админки, Telegram-бота и пользовательского сценария оплаты:

- `USAGE_GUIDE.md`

## Что реализовано

- Web-админка:
  - логин администратора;
  - создание платежа (инвойса);
  - просмотр статусов (`pending` -> `confirming` -> `paid`);
  - ручная отмена/ручное подтверждение;
  - просмотр логов;
  - просмотр реестра входящих переводов (`/admin/transfers`), включая нераспознанные.
- Public payment page: `/pay/<payment_id>`.
- API:
  - публичный статус платежа;
  - защищенный admin API (по `X-API-Key`) для интеграций.
- Авто-мониторинг сети:
  - TRON USDT (TRC20) через Trongrid;
  - BSC USDT (BEP20) через BscScan.
- Telegram:
  - отдельный бот для создания инвойсов и проверки статуса;
  - уведомления о подтверждении платежей.

## Важная логика авто-сверки

Платежи создаются с **уникальной суммой**: `base_amount + offset`.

Почему так: вы получаете переводы на один и тот же адрес TrustWallet. Чтобы сопоставить транзакцию конкретному счету без custodial-провайдера, используется точная сумма инвойса.

Для клиента это означает: нужно отправить **ровно** указанную сумму.

Дополнительно:

- перевод попадает в `confirming`, если подтверждений сети пока недостаточно;
- в `paid` переводится только после достижения `*_REQUIRED_CONFIRMATIONS`;
- все входящие tx сохраняются в `observed_transfers` с причиной, если они не сматчились (не та сумма, вне окна и т.д.);
- повторное создание платежа с тем же `external_id` и теми же параметрами возвращает существующий счет (idempotency).

## Защита от ошибок

- Строгая проверка суммы:
  - до 6 знаков после запятой;
  - диапазон `PAYMENT_MIN_BASE_AMOUNT .. PAYMENT_MAX_BASE_AMOUNT`.
- Строгая проверка TTL:
  - диапазон `PAYMENT_TTL_MIN_MINUTES .. PAYMENT_TTL_MAX_MINUTES`.
- Защита от дублей `tx_hash`:
  - один tx hash не может быть привязан к двум платежам.
- На публичной странице:
  - копирование адреса и суммы одной кнопкой;
  - явное указание, что сеть и сумма должны быть точными.

## Стек

- Python 3.11+
- FastAPI + Jinja2
- SQLAlchemy
- SQLite (быстрый старт) или PostgreSQL (рекомендуется для VPS)
- Uvicorn
- python-telegram-bot

## Структура

- `src/app/main.py` - FastAPI приложение
- `src/app/api/admin.py` - web-админка
- `src/app/api/public.py` - публичные страницы/статусы
- `src/app/api/internal.py` - защищенный API для интеграций
- `src/app/services/monitor.py` - фоновой монитор транзакций
- `src/app/models.py` - модели платежей и `observed_transfers`
- `src/app/telegram_bot.py` - Telegram бот
- `scripts/create_admin.py` - создать/обновить админа
- `.env.example` - пример переменных окружения

## Локальный запуск

1. Установите Python 3.11+.
2. Создайте виртуальное окружение:

```bash
python -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

3. Установите зависимости:

```bash
pip install -r requirements.txt
```

4. Создайте `.env`:

```bash
cp .env.example .env
```

5. Обязательно заполните:

- `SESSION_SECRET`
- `ADMIN_API_KEY`
- `ADMIN_USERNAME` / `ADMIN_PASSWORD`
- `TRON_WALLET_ADDRESS` и/или `BSC_WALLET_ADDRESS`
- `BASE_URL`
- `TRON_REQUIRED_CONFIRMATIONS` и/или `BSC_REQUIRED_CONFIRMATIONS`

6. Запустите web:

```bash
set PYTHONPATH=src
uvicorn app.main:app --host 127.0.0.1 --port 8081
```

Linux/macOS:

```bash
PYTHONPATH=src uvicorn app.main:app --host 127.0.0.1 --port 8081
```

7. Откройте:

- `http://127.0.0.1:8081/admin/login`

## Telegram бот (опционально)

Если нужен бот:

1. Заполните:
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ADMIN_IDS` (через запятую)

2. Запустите:

```bash
PYTHONPATH=src python -m app.telegram_bot
```

Команды:

- `/invoice <network> <amount> <title>`
- `/status <payment_id>`

Сети: `tron_usdt`, `bsc_usdt`.

## API

### Публичный

- `GET /api/payments/{payment_id}`
- `GET /api/payments/{payment_id}/status`

`/status` теперь возвращает `confirmations` и `required_confirmations`.

### Админский (защищен ключом)

Заголовок: `X-API-Key: <ADMIN_API_KEY>`

- `POST /api/admin/payments`
- `GET /api/admin/payments/{payment_id}`
- `GET /api/admin/payments?limit=50`

Пример создания платежа:

```json
{
  "external_id": "order-1001",
  "title": "Подписка на 1 месяц",
  "description": "Оплата доступа",
  "network": "tron_usdt",
  "base_amount": 25,
  "ttl_minutes": 30,
  "metadata": {
    "client_id": "u-001"
  }
}
```

## Деплой на VPS (без ломания текущего HTTPS)

Ниже инструкция, где ваш текущий сайт уже обслуживается Nginx + HTTPS.

### 1. Подготовка сервера

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx
```

Если используете PostgreSQL:

```bash
sudo apt install -y postgresql
```

Создайте пользователя/базу:

```bash
sudo -u postgres psql -c "CREATE USER crypto_user WITH PASSWORD 'crypto_password';"
sudo -u postgres psql -c "CREATE DATABASE crypto_pay OWNER crypto_user;"
```

### 2. Размещение проекта

```bash
cd /opt
sudo mkdir -p /opt/crypto-pay
sudo chown -R $USER:$USER /opt/crypto-pay
cd /opt/crypto-pay
# загрузите сюда ваш проект
```

### 3. Python окружение

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Конфиг `.env`

```bash
cp .env.example .env
```

Рекомендуемые ключевые значения:

- `ENVIRONMENT=prod`
- `HOST=127.0.0.1`
- `PORT=8081`
- `BASE_URL=https://payments.example.com` (или ваш под-путь)
- `DATABASE_URL=postgresql+psycopg://crypto_user:crypto_password@127.0.0.1:5432/crypto_pay`
- `TRON_WALLET_ADDRESS=...`
- `BSC_WALLET_ADDRESS=...`
- `TRON_REQUIRED_CONFIRMATIONS=1`
- `BSC_REQUIRED_CONFIRMATIONS=3`

### 5. systemd для web

Создайте `/etc/systemd/system/crypto-pay-web.service`:

```ini
[Unit]
Description=Crypto Pay Web
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/crypto-pay
Environment=PYTHONPATH=/opt/crypto-pay/src
EnvironmentFile=/opt/crypto-pay/.env
ExecStart=/opt/crypto-pay/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8081
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Применить:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now crypto-pay-web
sudo systemctl status crypto-pay-web
```

### 6. systemd для Telegram-бота (опционально)

`/etc/systemd/system/crypto-pay-bot.service`:

```ini
[Unit]
Description=Crypto Pay Telegram Bot
After=network.target crypto-pay-web.service

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/crypto-pay
Environment=PYTHONPATH=/opt/crypto-pay/src
EnvironmentFile=/opt/crypto-pay/.env
ExecStart=/opt/crypto-pay/.venv/bin/python -m app.telegram_bot
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now crypto-pay-bot
sudo systemctl status crypto-pay-bot
```

### 7. Nginx интеграция без изменения текущего HTTPS

#### Вариант A (рекомендуется): отдельный поддомен

Добавьте server block для `payments.example.com`, TLS можно выпустить через certbot отдельно.

Внутри:

```nginx
location / {
    proxy_pass http://127.0.0.1:8081;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Этот вариант не трогает ваш текущий проект по основному домену.

#### Вариант B: в существующий домен как путь `/crypto-pay/`

В существующем `server {}` аккуратно добавьте:

```nginx
location /crypto-pay/ {
    proxy_pass http://127.0.0.1:8081/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Потом:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Важно: это добавление `location`, не изменение вашего текущего `listen 443 ssl` и не замена сертификатов.

### 8. Проверка после деплоя

1. `systemctl status crypto-pay-web`
2. Открыть `/admin/login`
3. Создать тестовый платеж
4. Открыть `/pay/<id>`
5. Отправить тестовую сумму на нужную сеть/адрес
6. Убедиться что статус перешел в `paid`
7. Проверить `/admin/transfers` и `/admin/logs` для диагностики

## Эксплуатация

- Логи приложения: `logs/app.log`
- Логи systemd:
  - `journalctl -u crypto-pay-web -f`
  - `journalctl -u crypto-pay-bot -f`

## Безопасность и прод-заметки

- Не храните seed-фразу TrustWallet в этом проекте.
- Обязательно смените дефолтные секреты (`SESSION_SECRET`, `ADMIN_API_KEY`, админ-пароль).
- Ограничьте доступ к `/api/admin/*` только по ключу и, по возможности, IP-фильтрами в Nginx.
- Используйте PostgreSQL на VPS, SQLite оставьте для dev.
- Делайте backup БД по расписанию.

## Ограничения текущего решения

- Сопоставление платежей строится на уникальной сумме. При неточном переводе нужен ручной разбор.
- Если пользователь отправил не ту сеть или неточную сумму, перевод будет в `observed_transfers` как нераспознанный и потребует ручного решения.
- Если нужен enterprise-уровень (webhooks, AML, гарантированные callbacks, мультисеть из коробки), лучше подключить специализированный процессинг.
