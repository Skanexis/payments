# Enterprise API Guide

Документ для разработчиков, которые интегрируют сервис с CRM, checkout, Telegram-ботом или backend-приложением.

## 1. Основные принципы

1. Все суммы в `base_amount` задаются в **USD**.
2. Для USDT-инвойсов система рассчитывает уникальную сумму в сети USDT.
3. Для BTC-инвойсов система:
   - берет USD сумму;
   - конвертирует в BTC по текущему курсу;
   - фиксирует курс в момент создания инвойса.
4. Idempotency поддерживается через `external_id`.
5. Все защищенные endpoint требуют `X-API-Key`.

## 2. Безопасность API

### Заголовки

Для всех `GET/POST/PATCH /api/admin/*`:

```http
X-API-Key: <ADMIN_API_KEY>
Content-Type: application/json
```

### Rate limit

На `admin API` действует лимит запросов с одного IP:
- `ADMIN_API_RATE_LIMIT_PER_MINUTE` (по умолчанию `120`).

При превышении:
- HTTP `429 Too Many Requests`
- `detail: "Rate limit exceeded: max ... requests/minute"`

### Рекомендации для интеграции

1. Используйте server-to-server вызовы (не из браузера клиента).
2. Храните `ADMIN_API_KEY` только в секретах backend.
3. Ограничьте доступ к `/api/admin/*` через Nginx allowlist IP.
4. Добавьте retry c exponential backoff для `429/5xx`.

## 3. Публичные endpoint

### Health

`GET /health`

Ответ:

```json
{ "ok": true }
```

### Полный статус платежа

`GET /api/payments/{payment_id}`

### Компактный статус платежа

`GET /api/payments/{payment_id}/status`

Ответ содержит:
- `status`
- `tx_hash`
- `confirmations`
- `required_confirmations`
- `updated_at`

## 4. Admin API: платежи

### Создать платеж

`POST /api/admin/payments`

Тело:

```json
{
  "external_id": "order-1001",
  "title": "Subscription 30 days",
  "description": "Created from CRM",
  "network": "tron_usdt",
  "base_amount": 9.9,
  "ttl_minutes": 60,
  "metadata": {
    "source": "crm",
    "customer_id": "u-18"
  }
}
```

### Получить платеж

`GET /api/admin/payments/{payment_id}`

### Список платежей

`GET /api/admin/payments?limit=50`

Лимит:
- min `1`
- max `500`

## 5. Admin API: сети

### Справочник сетей

`GET /api/admin/networks`

Используйте для UI/бота:
- какие сети доступны;
- какие кошельки настроены;
- required confirmations;
- currency mapping.

## 6. Admin API: quick templates

Quick template = сохраненный шаблон быстрых инвойсов в USD.

Структура:
- `title`
- `description`
- `usd_amount`
- `ttl_minutes`
- `usdt_network` (`tron_usdt` | `bsc_usdt` | `eth_usdt`)
- `is_active`

### Список шаблонов

`GET /api/admin/templates?limit=200`

Лимит:
- min `1`
- max `1000`

### Создать шаблон

`POST /api/admin/templates`

```json
{
  "title": "Subscription 30 days",
  "description": "Default plan",
  "usd_amount": 9.9,
  "ttl_minutes": 60,
  "usdt_network": "tron_usdt",
  "is_active": true
}
```

### Обновить шаблон

`PATCH /api/admin/templates/{template_id}`

Можно передавать только изменяемые поля:

```json
{
  "usd_amount": 11.9,
  "ttl_minutes": 90,
  "is_active": true
}
```

### Быстро создать инвойс из шаблона

`POST /api/admin/templates/{template_id}/quick-create`

```json
{
  "currency": "USDT",
  "network": "tron_usdt"
}
```

Поддерживаемые валюты:
- `USDT`: сеть берется из `template.usdt_network`
- `BTC`: сеть всегда `btc`

`network` в запросе опционален и нужен для явной валидации на стороне интегратора:
- для `USDT` допустимо только значение сети из шаблона;
- для `BTC` допустимо только `btc`.

Ответ: стандартный `PaymentResponse`.

## 7. Формат ошибок

Все ошибки возвращают JSON вида:

```json
{
  "detail": "Human readable error"
}
```

Типовые коды:
- `400` — валидация/логика
- `401` — неверный `X-API-Key`
- `404` — сущность не найдена
- `429` — rate limit
- `500` — серверная ошибка/конфигурация

## 8. Интеграция с Telegram-ботом (рекомендуемый план)

Текущий бот можно перевести на API-first сценарий:

1. При запуске бота:
   - загрузить шаблоны `GET /api/admin/templates`
   - загрузить сети `GET /api/admin/networks`
2. В команде `/invoice`:
   - либо использовать обычный `POST /api/admin/payments`
   - либо quick flow: `POST /api/admin/templates/{id}/quick-create` с `currency`
3. В команде `/status`:
   - `GET /api/payments/{payment_id}/status`
4. Для операторов:
   - показывать `pay_url` из `PaymentResponse`
   - выводить `required_confirmations` и текущие `confirmations`.

## 9. Производительность и эксплуатация

1. Для прод используйте PostgreSQL.
2. Держите `MONITOR_INTERVAL_SECONDS` не слишком маленьким (обычно 15-30 сек).
3. Dashboard кэшируется через `DASHBOARD_STATS_CACHE_SECONDS`.
4. Для high-load сценариев:
   - вынесите монитор в отдельный worker;
   - добавьте очередь событий для внешних callback.

## 10. Минимальный чек-лист для интегратора

1. Проверка health: `GET /health`.
2. Проверка ключа: `GET /api/admin/networks`.
3. Создание тестового шаблона.
4. Quick create из шаблона в `USDT` и `BTC`.
5. Проверка статуса по `payment_id`.
6. Логирование всех `4xx/5xx` в вашей интеграции.
