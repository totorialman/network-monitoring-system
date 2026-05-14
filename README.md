# Network Monitoring System

Система мониторинга сетевых аномалий в реальном времени. Принимает сетевые логи от агентов, анализирует их через ML-модель (Isolation Forest), создаёт инциденты и транслирует обновления через WebSocket.

## Архитектура

```
┌──────────┐    JSONL (HTTP POST)    ┌──────────────┐
│  Agents   │ ──────────────────────> │   Backend    │
│ (агенты)  │                         │  (Go, :8080) │
└──────────┘                         └──────┬───────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
              ┌─────▼─────┐         ┌──────▼──────┐       ┌──────▼──────┐
              │ PostgreSQL │         │  ClickHouse │       │ ML Service  │
              │ (инциденты,│         │ (сырые логи)│       │ (Python,    │
              │  агенты,   │         │             │       │  :5000)     │
              │  пользова- │         └──────────────┘       └─────────────┘
              │  тели)     │
              └────────────┘
                                           │
                                    ┌──────▼──────┐
                                    │   Frontend  │
                                    │ (Nginx+React│
                                    │   :3000)    │
                                    │  ┌───────┐  │
                                    │  │ WebSocket│ │
                                    │  └───────┘  │
                                    └─────────────┘
```

- **Backend** (Go) — REST API + WebSocket Hub
- **Frontend** (React/Vite) — дашборд с графиками, списком инцидентов и управлением агентами
- **PostgreSQL** — пользователи, агенты, инциденты, алерты
- **ClickHouse** — сырые сетевые логи (TTL 90 дней, автоматическое удаление)
- **ML Service** (Python/FastAPI) — Isolation Forest + эвристики

## Системные требования

- Docker Engine 24+ и Docker Compose v2
- Сервер с **2+ ядрами CPU** и **4+ ГБ RAM**
- Публичный домен (для HTTPS через Certbot + Let's Encrypt)
- Открытые порты: **80** и **443** (для Certbot), **3000** (фронтенд, только локально)

## Быстрый старт

### 1. Клонирование

```bash
git clone https://github.com/totorialman/network-monitoring-system.git
cd network-monitoring-system
git checkout feature/jsonl-websocket-russian-fixes
```

### 2. Настройка окружения

Создайте файл `.env` в корне проекта:

```env
# Пароли для БД (обязательно замените на свои!)
DB_PASSWORD=StrongPostgresPassword123!
CLICKHOUSE_PASSWORD=StrongClickHousePassword123!

# JWT секрет (минимум 32 символа, сгенерируйте через: openssl rand -hex 32)
JWT_SECRET=your-secret-at-least-32-characters-long-hex-string

# Пароль администратора по умолчанию (смените после первого входа)
INIT_ADMIN_PASSWORD=ChangeMe123!

# Telegram-уведомления (опционально)
TELEGRAM_BOT_TOKEN=
TELEGRAM_ADMIN_CHAT_ID=
TELEGRAM_MIN_SEVERITY=3
TELEGRAM_MIN_ML_SCORE=0.6

# URL для ссылок в Telegram-уведомлениях
BASE_INCIDENT_URL=https://monitor.example.com/incidents

# ML-сервис
ML_SERVICE_URL=http://ml2-http-service:5000
ML_TIMEOUT=30s
ML_WINDOW_SECONDS=300
```

### 3. Запуск

```bash
docker compose up -d
```

Проверьте статус всех контейнеров:

```bash
docker compose ps
```

Должны быть запущены 5 контейнеров: `nm-frontend`, `nm-backend`, `nm-postgres`, `nm-clickhouse`, `nm-ml2-http`.

### 4. Доступ к панели управления

Откройте браузер на `http://<IP-сервера>:3000` и войдите:

- **Логин:** `admin`
- **Пароль:** тот, что указан в `INIT_ADMIN_PASSWORD`

> ⚠️ **Сразу после входа смените пароль администратора** через создание второго админа в БД или замену хеша пароля.

## Настройка HTTPS с Certbot + Let's Encrypt

### Шаг 1: Установите Nginx на хост-машине

```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

### Шаг 2: Создайте конфигурацию Nginx

`/etc/nginx/sites-available/monitor`:

```nginx
server {
    listen 80;
    server_name monitor.example.com;  # замените на ваш домен

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/monitor /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Шаг 3: Получите SSL-сертификат

```bash
sudo certbot --nginx -d monitor.example.com
```

Выберите вариант `2` (redirect HTTP → HTTPS) при запросе.

Сертификат будет автоматически обновляться через systemd-таймер.

## Отправка логов от агентов

### 1. Создайте токен агента через панель управления

Администратор → раздел «Агенты» → «Создать токен»

### 2. Отправка JSONL-файла

```bash
curl -X POST https://monitor.example.com/api/agent/logs \
  -H "Authorization: Bearer <agent-token>" \
  -F "file=@logs.jsonl"
```

### 3. Формат JSONL (одна строка = один лог)

```jsonl
{"timestamp": 1747221400.123, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 443, "proto": 6, "ttl": 64, "length": 1500, "tcp_flags": "SYN", "src_mac": "aa:bb:cc:dd:ee:ff", "dst_mac": "11:22:33:44:55:66", "eth_type": "IPv4"}
{"timestamp": 1747221400.456, "src_ip": "192.168.1.101", "dst_ip": "10.0.0.6", "src_port": 12345, "dst_port": 80, "proto": 6, "ttl": 128, "length": 512, "tcp_flags": "ACK", "src_mac": "aa:bb:cc:dd:ee:01", "dst_mac": "11:22:33:44:55:01", "eth_type": "IPv4"}
```

| Поле | Тип | Обязательно | Описание |
|------|------|---------|----------|
| `timestamp` | float64 | да | Unix timestamp с миллисекундами |
| `src_ip` | string | да | IP-адрес источника |
| `dst_ip` | string | да | IP-адрес назначения |
| `src_port` | uint16 | нет | Порт источника |
| `dst_port` | uint16 | нет | Порт назначения |
| `proto` | uint8 | нет | IP-протокол (6=TCP, 17=UDP, 1=ICMP) |
| `ttl` | uint8 | нет | Time-to-live |
| `length` | uint16 | нет | Длина пакета |
| `tcp_flags` | string | нет | TCP-флаги |
| `src_mac` | string | нет | MAC источника |
| `dst_mac` | string | нет | MAC назначения |
| `icmp_type` | uint8 | нет | ICMP type |
| `icmp_code` | uint8 | нет | ICMP code |
| `vlan` | uint16 | нет | VLAN ID |
| `eth_type` | string | нет | EtherType |

Ограничения:
- Размер файла: до 50 МБ
- Длина одной строки: до 1 МБ
- Минимум одна валидная запись в файле

## Переменные окружения (полный список)

| Переменная | По умолчанию | Описание |
|------------|-------------|----------|
| `APP_ENV` | `development` | Окружение: `development` или `production` |
| `APP_PORT` | `8080` | Порт бэкенда |
| `APP_VERSION` | `1.0.0` | Версия приложения |
| `DB_POSTGRES_HOST` | `localhost` | Хост PostgreSQL |
| `DB_POSTGRES_PORT` | `5432` | Порт PostgreSQL |
| `DB_POSTGRES_USER` | `nm_user` | Пользователь PostgreSQL |
| `DB_POSTGRES_PASSWORD` | — | Пароль PostgreSQL (из `DB_PASSWORD`) |
| `DB_POSTGRES_DB` | `network_monitor` | База данных PostgreSQL |
| `DB_CLICKHOUSE_HOST` | `localhost` | Хост ClickHouse |
| `DB_CLICKHOUSE_PORT` | `9000` | Нативный порт ClickHouse |
| `DB_CLICKHOUSE_USER` | `default` | Пользователь ClickHouse |
| `DB_CLICKHOUSE_PASSWORD` | — | Пароль ClickHouse (из `CLICKHOUSE_PASSWORD`) |
| `DB_CLICKHOUSE_DB` | `default` | База данных ClickHouse |
| `ML_SERVICE_URL` | `http://localhost:5000` | URL ML-сервиса |
| `ML_TIMEOUT` | `30s` | Таймаут запроса к ML |
| `ML_WINDOW_SECONDS` | `300` | Размер окна агрегации (сек) |
| `JWT_SECRET` | `change-me-...` | Секрет для JWT (минимум 32 символа) |
| `JWT_EXPIRATION` | `24h` | Время жизни JWT |
| `TELEGRAM_BOT_TOKEN` | — | Токен Telegram-бота |
| `TELEGRAM_ADMIN_CHAT_ID` | — | ID чата для уведомлений |
| `TELEGRAM_MIN_SEVERITY` | `3` | Минимальная критичность для уведомления |
| `TELEGRAM_MIN_ML_SCORE` | `0.6` | Минимальный ML-скор для уведомления |
| `BASE_INCIDENT_URL` | `https://monitor.local/incidents` | Базовый URL инцидентов |
| `INIT_ADMIN_LOGIN` | `admin` | Логин начального администратора |
| `INIT_ADMIN_PASSWORD` | `ChangeMe123!` | Пароль начального администратора |

## Обслуживание

### Резервное копирование

```bash
# PostgreSQL
docker exec nm-postgres pg_dump -U nm_user network_monitor > backup_$(date +%Y%m%d).sql

# ClickHouse (опционально — сырые логи обычно не бэкапят)
docker exec nm-clickhouse clickhouse-client --password "$CLICKHOUSE_PASSWORD" --query "BACKUP DATABASE default TO Disk('backups', 'backup_$(date +%Y%m%d)')"
```

### Просмотр логов

```bash
docker compose logs -f backend    # логи бэкенда
docker compose logs -f frontend   # логи nginx
docker compose logs -f ml2-http-service  # логи ML-сервиса
```

### Обновление

```bash
git pull origin feature/jsonl-websocket-russian-fixes
docker compose up -d --build
```

### Очистка старых данных ClickHouse

TTL на 90 дней настроен автоматически. Для ручной очистки:

```bash
docker exec nm-clickhouse clickhouse-client --password "$CLICKHOUSE_PASSWORD" --query "ALTER TABLE network_logs DELETE WHERE timestamp < now() - INTERVAL 30 DAY"
```

## Устранение неполадок

1. **Фронтенд не грузится (502/504)**: проверьте `docker compose ps` — все ли контейнеры healthy.
2. **Ошибка подключения к БД**: проверьте пароли в `.env`, дождитесь healthcheck (до 60 сек).
3. **ML-сервис недоступен**: логируются в `stdout`, проверьте `docker compose logs ml2-http-service`.
4. **WebSocket не подключается**: проверьте nginx upstream на порту 3000 — должен быть `proxy_http_version 1.1` и `Upgrade`/`Connection` заголовки.

## Разработка

Требования: Go 1.21+, Node.js 22+, pnpm.

```bash
# Бэкенд
go run ./cmd/server

# Фронтенд
cd frontend && pnpm install && pnpm run dev
```

Бэкенд ожидает PostgreSQL и ClickHouse на `localhost:5432` и `localhost:9000` соответственно.