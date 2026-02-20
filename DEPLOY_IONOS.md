# Deploy на IONOS VPS: Пошаговая инструкция (без поломки существующего поддомена)

Этот документ объясняет, как развернуть текущий проект на **том же VPS IONOS**, где уже работает другой сервис на другом поддомене, и не сломать текущий Nginx/HTTPS.

Инструкция включает:
- DNS в IONOS;
- Git на сервере (простой HTTPS clone/pull);
- подготовку Python окружения;
- настройку `.env` (TrustWallet, Tron/BSC API);
- `systemd` сервисы;
- отдельный `nginx` server block для нового поддомена;
- TLS/SSL через Certbot;
- проверку и безопасный rollback.

---

## 0. Что должно получиться в итоге

Допустим:
- уже работает сервис `old.example.com` (не трогаем);
- хотим поднять этот сервис на `pay.example.com`.

После деплоя:
- `old.example.com` продолжает работать как раньше;
- `pay.example.com` проксируется на `127.0.0.1:8081` (наш FastAPI);
- SSL сертификат для `pay.example.com` отдельный;
- приложение запускается через `systemd`;
- обновления через `git pull`.

---

## 1. Подготовьте данные заранее

Перед входом на VPS соберите:

1. Доступ к IONOS DNS (панель домена).
2. SSH доступ к VPS (`root`/`sudo` пользователь).
3. Git репозиторий проекта (GitHub/GitLab/Bitbucket) и, если репозиторий приватный, Personal Access Token (PAT).
4. TrustWallet адреса:
   - `TRON` адрес для USDT TRC20 (обычно начинается с `T...`);
   - `BSC` адрес для USDT BEP20 (обычно `0x...`).
5. API ключи:
   - Trongrid API key (для TRON);
   - BscScan API key (для BSC, опционально но желательно).

---

## 2. DNS в IONOS: добавьте новый поддомен

В IONOS:

1. Откройте DNS зону вашего домена.
2. Создайте `A` запись:
   - Host/Name: `pay` (или ваш новый поддомен),
   - Value: публичный IPv4 вашего VPS,
   - TTL: по умолчанию (например 3600).
3. Если используете IPv6, добавьте `AAAA` запись.

Проверка на локальной машине:

```bash
nslookup pay.example.com
```

Должен возвращаться IP вашего VPS.

Важно: существующую запись старого поддомена **не изменяйте**.

---

## 3. Подключение к VPS и базовая подготовка

Подключитесь:

```bash
ssh your_user@YOUR_VPS_IP
```

Обновите систему и поставьте пакеты:

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y git nginx python3 python3-venv python3-pip curl ufw
```

Если планируете PostgreSQL:

```bash
sudo apt install -y postgresql postgresql-contrib
```

---

## 4. Git на VPS: нормальное подключение через HTTPS

### 4.1 Настройте Git один раз

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
git config --global init.defaultBranch main
git config --global credential.helper 'cache --timeout=604800'
```

Это сохранит авторизацию на 7 дней и не будет постоянно спрашивать токен.

### 4.2 Если репозиторий приватный: сделайте PAT

GitHub:
1. `Settings -> Developer settings -> Personal access tokens -> Tokens (classic)`.
2. `Generate new token (classic)`.
3. Scope: `repo`.
4. Скопируйте токен.

Важно: при работе через HTTPS Git спросит:
- `Username`: ваш логин GitHub;
- `Password`: ваш PAT (не пароль от аккаунта).

### 4.3 Быстрый тест доступа к репозиторию

```bash
git ls-remote https://github.com/YOUR_ORG/YOUR_REPO.git
```

Если репозиторий публичный, команда сразу вернет список refs.  
Если приватный, введите `Username` + `PAT`.

---

## 5. Структура папок на сервере

Рекомендуемая структура:

```text
/opt/crypto-pay/      # код
/opt/crypto-pay/.venv # виртуальное окружение
/opt/crypto-pay/.env  # прод переменные
```

Создайте и назначьте права:

```bash
sudo mkdir -p /opt/crypto-pay
sudo chown -R $USER:$USER /opt/crypto-pay
```

---

## 6. Клонируйте репозиторий через Git

```bash
cd /opt/crypto-pay
git clone https://github.com/YOUR_ORG/YOUR_REPO.git .
git checkout main
git pull origin main
```

Если репозиторий приватный, во время `git clone` введите:
- `Username`: ваш логин GitHub;
- `Password`: ваш PAT.

Проверка:

```bash
git branch
git remote -v
```

---

## 7. Python окружение и зависимости

```bash
cd /opt/crypto-pay
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Если используете PostgreSQL, проверьте что `psycopg` установился без ошибок.

---

## 8. Настройте `.env` (самая важная часть)

Создайте прод конфиг:

```bash
cp .env.example .env
nano .env
```

Минимально обязательные поля:

```env
ENVIRONMENT=prod
HOST=127.0.0.1
PORT=8081
BASE_URL=https://pay.example.com

DATABASE_URL=sqlite:///./data/crypto_pay.db
# или postgres:
# DATABASE_URL=postgresql+psycopg://crypto_user:strong_password@127.0.0.1:5432/crypto_pay

SESSION_SECRET=SUPER_LONG_RANDOM_SECRET
ADMIN_API_KEY=SUPER_LONG_RANDOM_API_KEY
ADMIN_USERNAME=admin
ADMIN_PASSWORD=SUPER_STRONG_PASSWORD

TRON_WALLET_ADDRESS=YOUR_TRUSTWALLET_TRC20_ADDRESS
BSC_WALLET_ADDRESS=YOUR_TRUSTWALLET_BEP20_ADDRESS

TRON_API_KEY=YOUR_TRONGRID_API_KEY
BSCSCAN_API_KEY=YOUR_BSCSCAN_API_KEY

TRON_REQUIRED_CONFIRMATIONS=1
BSC_REQUIRED_CONFIRMATIONS=3
```

### 8.1 Как правильно взять адреса из TrustWallet

1. Откройте TrustWallet.
2. Для TRC20 USDT:
   - зайдите в `USDT (TRON)` или TRON сеть,
   - нажмите `Receive`,
   - скопируйте адрес вида `T...`,
   - вставьте в `TRON_WALLET_ADDRESS`.
3. Для BEP20 USDT:
   - зайдите в `USDT (BSC)` или BNB Smart Chain,
   - `Receive`,
   - адрес вида `0x...`,
   - вставьте в `BSC_WALLET_ADDRESS`.

Критично: адрес и сеть должны совпадать.

### 8.2 Tron API key (Trongrid)

Ниже полный путь от нуля до проверки.

1. Откройте сайт Trongrid и создайте аккаунт (email + пароль).
2. Подтвердите email (если попросит).
3. В личном кабинете откройте раздел с API Keys.
4. Нажмите создание нового ключа (`Create API Key`/`New Key`).
5. Укажите имя ключа, например: `crypto-pay-prod`.
6. Если есть выбор среды/проекта, создайте отдельный ключ для продакшена.
7. Скопируйте ключ сразу после создания.
8. На VPS откройте `.env`:

```bash
cd /opt/crypto-pay
nano .env
```

9. Добавьте/проверьте значения:

```env
TRON_API_BASE=https://api.trongrid.io
TRON_API_KEY=PASTE_YOUR_TRONGRID_KEY
TRON_USDT_CONTRACT=TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
TRON_REQUIRED_CONFIRMATIONS=1
```

10. Проверьте ключ вручную через `curl` (на VPS):

```bash
curl -sS -H "TRON-PRO-API-KEY: PASTE_YOUR_TRONGRID_KEY" \
  "https://api.trongrid.io/v1/accounts/YOUR_TRON_ADDRESS/transactions/trc20?limit=1" | head
```

11. Если ключ рабочий, получите JSON (ошибки вида `UNAUTHORIZED` быть не должно).
12. После сохранения `.env` перезапустите сервис:

```bash
sudo systemctl restart crypto-pay-web
sudo systemctl status crypto-pay-web
```

13. Проверьте логи:

```bash
journalctl -u crypto-pay-web -n 100 --no-pager
```

Ищите строки без ошибок fetch для сети `tron_usdt`.

### 8.3 BscScan API key

Для BSC ключ формально опционален, но в проде крайне рекомендуется (меньше риск лимитов и сбоев).

1. Откройте BscScan и создайте аккаунт.
2. Подтвердите email.
3. Зайдите в профиль -> API Keys.
4. Создайте новый ключ, например `crypto-pay-prod`.
5. Скопируйте ключ.
6. На VPS откройте `.env`:

```bash
cd /opt/crypto-pay
nano .env
```

7. Добавьте/проверьте:

```env
BSCSCAN_API_BASE=https://api.bscscan.com/api
BSCSCAN_API_KEY=PASTE_YOUR_BSCSCAN_KEY
BSC_USDT_CONTRACT=0x55d398326f99059ff775485246999027b3197955
BSC_REQUIRED_CONFIRMATIONS=3
```

8. Проверьте ключ вручную:

```bash
curl -sS "https://api.bscscan.com/api?module=account&action=tokentx&contractaddress=0x55d398326f99059ff775485246999027b3197955&address=YOUR_BSC_ADDRESS&page=1&offset=1&sort=desc&apikey=PASTE_YOUR_BSCSCAN_KEY" | head
```

9. Рабочий ответ: JSON с полями `status`, `message`, `result`.
10. Если приходит ошибка по лимиту/доступу, проверьте тариф и правильность ключа.
11. Перезапустите сервис:

```bash
sudo systemctl restart crypto-pay-web
sudo systemctl status crypto-pay-web
```

12. Проверьте логи:

```bash
journalctl -u crypto-pay-web -n 100 --no-pager
```

Ищите строки без ошибок fetch для сети `bsc_usdt`.

### 8.4 Быстрая валидация API ключей после запуска

1. Откройте админку: `https://pay.example.com/admin/login`.
2. Создайте тестовый платеж в `tron_usdt`.
3. Создайте тестовый платеж в `bsc_usdt`.
4. Подождите 1-2 цикла мониторинга (по умолчанию 20 секунд).
5. Проверьте:
   - `https://pay.example.com/admin/logs`
   - `https://pay.example.com/admin/transfers`
6. Если ключи работают, не будет повторяющихся ошибок `Transfer fetch failed`.
7. Если ошибки есть:
   - перепроверьте ключи в `.env`;
   - проверьте корректность адресов кошельков;
   - проверьте интернет с VPS (`curl https://api.trongrid.io` и `curl https://api.bscscan.com/api`).

---

## 9. Пробный запуск без Nginx (локально на VPS)

Проверим, что приложение стартует:

```bash
cd /opt/crypto-pay
source .venv/bin/activate
PYTHONPATH=src uvicorn app.main:app --host 127.0.0.1 --port 8081
```

В другом SSH окне:

```bash
curl -I http://127.0.0.1:8081/health
```

Ожидается `200 OK`.

Остановите `uvicorn` (`Ctrl+C`), если проверка успешна.

---

## 10. systemd: автозапуск приложения

Создайте сервис:

```bash
sudo nano /etc/systemd/system/crypto-pay-web.service
```

Содержимое:

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

Назначьте права на проект:

```bash
sudo chown -R www-data:www-data /opt/crypto-pay
```

Запустите:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now crypto-pay-web
sudo systemctl status crypto-pay-web
```

Логи:

```bash
journalctl -u crypto-pay-web -f
```

---

## 11. Nginx: добавляем новый поддомен БЕЗ изменения старого

### 11.1 Посмотрите текущие конфиги

```bash
ls -la /etc/nginx/sites-available
ls -la /etc/nginx/sites-enabled
```

Сделайте backup перед изменениями:

```bash
sudo cp -a /etc/nginx /etc/nginx.backup.$(date +%F-%H%M)
```

### 11.2 Создайте отдельный файл для нового поддомена

```bash
sudo nano /etc/nginx/sites-available/pay.example.com.conf
```

Вставьте:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name pay.example.com;

    access_log /var/log/nginx/pay.example.com.access.log;
    error_log  /var/log/nginx/pay.example.com.error.log;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

Включите сайт:

```bash
sudo ln -s /etc/nginx/sites-available/pay.example.com.conf /etc/nginx/sites-enabled/pay.example.com.conf
```

Проверьте:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Важно:
- вы **не трогаете** конфиг старого поддомена;
- у нового поддомена отдельный файл и `server_name`;
- так сервисы не конфликтуют.

---

## 12. SSL для нового поддомена

Установите Certbot:

```bash
sudo apt install -y certbot python3-certbot-nginx
```

Выпустите сертификат только для нового поддомена:

```bash
sudo certbot --nginx -d pay.example.com
```

Проверьте автообновление:

```bash
sudo certbot renew --dry-run
```

---

## 13. Проверка, что старый сервис не пострадал

Проверьте оба поддомена:

```bash
curl -I https://old.example.com
curl -I https://pay.example.com
```

Проверьте `nginx` ошибки:

```bash
sudo tail -n 100 /var/log/nginx/error.log
sudo tail -n 100 /var/log/nginx/pay.example.com.error.log
```

Если старый сервис отвечает как раньше, всё корректно.

---

## 14. Telegram-бот (опционально)

Если нужен бот:

1. В `.env` задайте:
   - `TELEGRAM_BOT_TOKEN=...`
   - `TELEGRAM_ADMIN_IDS=...`
   - `TELEGRAM_NOTIFY_ENABLED=true`

2. Сервис:

```bash
sudo nano /etc/systemd/system/crypto-pay-bot.service
```

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

Запуск:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now crypto-pay-bot
sudo systemctl status crypto-pay-bot
```

---

## 15. Первый боевой тест платежа

1. Зайдите `https://pay.example.com/admin/login`.
2. Создайте платеж `tron_usdt` на маленькую сумму.
3. Переведите в TrustWallet **ровно** указанную сумму в нужной сети.
4. Проверяйте:
   - `/admin/payments/<id>`
   - `/admin/transfers`
   - `/admin/logs`
5. Ожидаем:
   - сначала `pending`/`confirming`,
   - затем `paid`.

---

## 16. Ежедневная работа с Git на проде

### 16.1 Обновление сервиса

```bash
cd /opt/crypto-pay
git fetch origin
git status
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart crypto-pay-web
sudo systemctl status crypto-pay-web
```

Если меняли бота:

```bash
sudo systemctl restart crypto-pay-bot
```

### 16.2 Безопасный workflow

Рекомендуется:
- в репозитории вести `main` (prod) + `develop`;
- на VPS деплоить только `main`;
- перед pull на VPS проверять CI/тесты.

### 16.3 Если обновление сломало сервис

1. Посмотреть логи:

```bash
journalctl -u crypto-pay-web -n 200 --no-pager
```

2. Откатить код:

```bash
cd /opt/crypto-pay
git log --oneline -n 10
git checkout <previous_commit_hash>
sudo systemctl restart crypto-pay-web
```

3. После фикса вернуть `main`.

---

## 17. Рекомендации по безопасности

1. Закрыть лишние порты через UFW:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

2. Не хранить seed-фразу TrustWallet на сервере.
3. Сгенерировать сильные `SESSION_SECRET`, `ADMIN_API_KEY`.
4. Ограничить `/api/admin/*` по IP в Nginx (если есть фиксированный офисный IP).
5. Регулярно делать бэкап БД.

---

## 18. Частые ошибки и как исправлять

### Ошибка: Certbot не выдает сертификат
- DNS не резолвится на ваш VPS;
- порт 80 закрыт firewall;
- конфликтующий `server_name`.

### Ошибка: `502 Bad Gateway`
- `crypto-pay-web` не запущен;
- приложение слушает другой порт;
- ошибка в `.env`/зависимостях.

### Ошибка: платеж не матчит
- пользователь отправил не ту сеть;
- неточная сумма;
- tx вне окна времени;
- недостаточно confirmations.
Проверьте `/admin/transfers` и `/admin/logs`.

### Ошибка: старый поддомен перестал работать
- вы изменили его конфиг вместо добавления нового;
- дублируется `default_server`.
Верните backup `/etc/nginx.backup.*` и перезагрузите Nginx.

---

## 19. Мини-чеклист перед прод запуском

1. DNS `pay.example.com` указывает на VPS.
2. `systemctl status crypto-pay-web` = active.
3. `nginx -t` = ok.
4. `https://pay.example.com/health` отвечает.
5. SSL валиден.
6. Админка доступна.
7. Тестовый платеж прошел.
8. Старый поддомен работает как раньше.
