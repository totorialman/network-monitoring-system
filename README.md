# Система мониторинга сетевого трафика

**Версия:** 2.1.0

## Назначение

Автоматизированная система приёма, хранения и анализа событий сетевого трафика. Агенты (OpenWRT/RPi) отправляют ZIP-архивы с логами, бэкенд на Go сохраняет их в ClickHouse, ML-сервис на Python выполняет анализ аномалий, а веб-панель на React отображает дашборд, инциденты и список агентов с обновлением в реальном времени через WebSocket.

## Состав

| Компонент | Технология | Роль |
|---|---|---|
| Frontend | React 19, Vite, TypeScript, Recharts, Nginx | Веб-панель администратора |
| Backend | Go 1.21, Gorilla Mux, pgx, goose | REST API, авторизация, приём логов, WebSocket |
| PostgreSQL | 15 Alpine | Пользователи, агенты, инциденты, алерты, аудит |
| ClickHouse | 23.3 Alpine | Сырые сетевые логи + материализованные представления |
| ML2-сервис | Python 3.11, FastAPI, scikit-learn | Детекция аномалий (Isolation Forest) |
| Оркестрация | Docker Compose | Единый запуск всех сервисов |

## Быстрый старт (локально)

```bash
# 1. Клонировать репозиторий
git clone https://github.com/totorialman/network-monitoring-system.git
cd network-monitoring-system

# 2. Настроить переменные окружения
cp .env.example .env
# Отредактировать .env — обязательно сменить:
#   DB_PASSWORD, CLICKHOUSE_PASSWORD, JWT_SECRET, INIT_ADMIN_PASSWORD

# 3. Запустить
docker compose up --build -d

# 4. Открыть
# http://localhost:3000
# Логин: admin (из INIT_ADMIN_LOGIN)
# Пароль: из INIT_ADMIN_PASSWORD в .env
```

## Порты

| Сервис | Внутренний | Хост | Назначение |
|---|---|---|---|
| Frontend (Nginx) | 3000 | 3000 | SPA + прокси `/api` и `/api/ws` |
| Backend (Go) | 8080 | 8080 | REST API + WebSocket |
| PostgreSQL | 5432 | 5432 | Транзакционное хранилище |
| ClickHouse HTTP | 8123 | 8123 | HTTP-интерфейс |
| ClickHouse Native | 9000 | 9000 | Native-интерфейс |
| ML2-сервис | 5000 | 5001 | FastAPI |

## WebSocket

Фронтенд подключается к `/api/ws` через JWT-токен. При создании нового инцидента бэкенд рассылает событие `new_incident` всем подключённым клиентам. Фронтенд автоматически обновляет дашборд без перезагрузки.

## Развёртывание на сервере с публичным доменом

### 1. Подготовка сервера

```bash
# Ubuntu 22.04 / Debian 12
apt update && apt install -y docker.io docker-compose-v2 nginx certbot python3-certbot-nginx
systemctl enable --now docker
```

### 2. Клонирование и настройка

```bash
cd /opt
git clone https://github.com/totorialman/network-monitoring-system.git
cd network-monitoring-system

# Создать .env
cat > .env << 'EOF'
DB_PASSWORD=<сгенерируйте_надёжный_пароль>
CLICKHOUSE_PASSWORD=<сгенерируйте_надёжный_пароль>
JWT_SECRET=<сгенерируйте_секрет_минимум_32_символа>
INIT_ADMIN_LOGIN=admin
INIT_ADMIN_PASSWORD=<сгенерируйте_надёжный_пароль>
BASE_INCIDENT_URL=https://monitor.example.com/incidents
TELEGRAM_BOT_TOKEN=
TELEGRAM_ADMIN_CHAT_ID=
TELEGRAM_MIN_SEVERITY=3
TELEGRAM_MIN_ML_SCORE=0.6
EOF
```

### 3. Запуск контейнеров

```bash
docker compose up --build -d
```

### 4. Настройка Nginx как reverse proxy с HTTPS

```bash
# Создать конфиг сайта
cat > /etc/nginx/sites-available/network-monitor << 'EOF'
server {
    listen 80;
    server_name monitor.example.com;  # замените на ваш домен

    # Все запросы проксируются на frontend-контейнер
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF

ln -s /etc/nginx/sites-available/network-monitor /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

### 5. Получение SSL-сертификата

```bash
certbot --nginx -d monitor.example.com
# Сертификат будет автоматически обновляться
```

### 6. Проверка

```bash
# Healthcheck
curl https://monitor.example.com/healthz

# Статистика (требуется JWT)
curl -X POST https://monitor.example.com/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"admin","password":"<ваш_пароль>"}'
```

## Переменные окружения

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `DB_PASSWORD` | Пароль PostgreSQL | **обязательно** |
| `CLICKHOUSE_PASSWORD` | Пароль ClickHouse | **обязательно** |
| `JWT_SECRET` | Секрет для JWT-токенов | **обязательно** |
| `INIT_ADMIN_LOGIN` | Логин начального администратора | `admin` |
| `INIT_ADMIN_PASSWORD` | Пароль начального администратора | **обязательно** |
| `TELEGRAM_BOT_TOKEN` | Токен Telegram-бота | (необязательно) |
| `TELEGRAM_ADMIN_CHAT_ID` | ID чата для уведомлений | (необязательно) |
| `TELEGRAM_MIN_SEVERITY` | Минимальная критичность для уведомлений | `3` |
| `TELEGRAM_MIN_ML_SCORE` | Минимальный ML-скор для уведомлений | `0.6` |
| `BASE_INCIDENT_URL` | Базовый URL инцидентов для ссылок в Telegram | `https://monitor.local/incidents` |
| `ML_WINDOW_SECONDS` | Размер временного окна для ML-агрегации | `300` |

## REST API

| Метод | URI | Назначение | Аутентификация |
|---|---|---|---|
| POST | `/api/auth/login` | Вход администратора | — |
| POST | `/api/agent/logs` | Загрузка ZIP с логами | Agent Token |
| POST | `/api/admin/agents/tokens` | Создание токена агента | Admin JWT |
| GET | `/api/agents` | Список агентов | Admin JWT |
| GET | `/api/agents/{id}/logs` | Сырые логи агента из ClickHouse | Admin JWT |
| GET | `/api/incidents` | Список инцидентов | Admin JWT |
| GET | `/api/incidents/{id}` | Детали инцидента | Admin JWT |
| PUT | `/api/incidents/{id}/status` | Смена статуса инцидента | Admin JWT |
| GET | `/api/stats` | Агрегированная статистика | Admin JWT |
| GET | `/api/ws` | WebSocket-подключение | Admin JWT |
| GET | `/healthz` | Проверка здоровья | — |

## Формат логов (traffic.json)

```json
{
  "timestamp": 1713623722.45,
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.5",
  "src_port": 54321,
  "dst_port": 80,
  "proto": 6,
  "ttl": 64,
  "tcp_flags": "SYN",
  "length": 64
}
```

Поддерживаются также:
- `tcp_flags` — строка (`"SYN"`) или число (`2`)
- `src_mac`, `dst_mac`, `vlan`, `eth_type`, `icmp_type`, `icmp_code` — опциональны, могут быть `null`
- Массивы JSON-объектов в одном файле

## Остановка и очистка

```bash
# Остановка
docker compose down

# Остановка с удалением данных
docker compose down -v
```

## Готовность к продакшену

- [x] Все сервисы в Docker Compose с healthcheck'ами
- [x] Nginx как reverse proxy (внутренний + внешний с HTTPS)
- [x] WebSocket для реального времени
- [x] Автоматические миграции PostgreSQL при старте
- [x] ClickHouse со сжатием и TTL (90 дней)
- [x] Circuit Breaker для ML-сервиса
- [x] Fallback на эвристики при недоступности ML
- [x] Интерфейс полностью на русском языке
- [x] Все логи создают инциденты (независимо от ML-оценки)