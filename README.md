# Network Traffic Monitoring System

**Версия проекта:** 2.0.0 (ml2)

## Назначение проекта

Проект реализует систему мониторинга сетевого трафика по ТЗ. В состав входят **React frontend для администратора**, **Go backend**, **PostgreSQL**, **ClickHouse** и отдельный **Python ML2-сервис**. 

Система принимает ZIP-архивы с сетевыми событиями от агентов, валидирует и сохраняет сырые логи в ClickHouse, передаёт их в ML2-сервис (который сам агрегирует признаки и запускает Isolation Forest), создаёт инциденты в PostgreSQL и отображает результаты в web-панели с авторизацией, графиками, карточками инцидентов и управлением агентами.

> **Ключевая идея архитектуры:** PostgreSQL — транзакционные сущности (пользователи, агенты, инциденты, алерты, аудит). ClickHouse — высокообъёмные события сетевого трафика. ML2-сервис — отдельный Python/FastAPI контейнер, который принимает **сырые логи**, сам агрегирует их в 18 признаков (как в ml2/TimeWindowAggregator) и запускает Isolation Forest. Классификация угроз (port_scan, ddos, anomaly) выполняется также в ML2-сервисе. Frontend обслуживается через Nginx и проксирует `/api` в backend внутри общей Docker-сети (same-origin, без CORS).

## Состав репозитория

| Путь | Назначение |
|---|---|
| `frontend` | React/Vite frontend: авторизация, dashboard, инциденты, агенты. |
| `cmd/server` | Точка входа Go backend и Dockerfile. |
| `internal/config` | Загрузка конфигурации из ENV. |
| `internal/domain` | Доменные структуры: пользователи, агенты, логи, запросы. |
| `internal/handler` | HTTP-обработчики REST API. |
| `internal/middleware` | JWT-аутентификация, авторизация агента, логирование, recovery. |
| `internal/repository/postgres` | PostgreSQL-репозитории и embedded SQL миграции. |
| `internal/repository/clickhouse` | ClickHouse-репозиторий для хранения сетевых логов. |
| `internal/service` | Auth, log ingestion, ML-client, Telegram notifications. |
| `ml2-http-service` | Python FastAPI ML2-сервис (Isolation Forest, 18 признаков, классификация угроз). |
| `ml2` | Автономный ML-агент для обучения модели на pcap-файлах или захвата с интерфейса. |
| `clickhouse/config.xml` | Конфигурация ClickHouse. |
| `docker-compose.yml` | Общий Compose-файл для всех сервисов. |

## Технологический стек

| Компонент | Технология | Роль |
|---|---|---|
| Frontend | React 19, Vite, TypeScript, Recharts | Web-панель администратора. |
| Frontend runtime | Nginx 1.27 Alpine | Отдача SPA + proxy `/api` к backend. |
| Backend | Go 1.21, Gorilla Mux, pgx, goose | REST API, авторизация, валидация, ingestion. |
| OLTP-хранилище | PostgreSQL 15 | Пользователи, агенты, инциденты, алерты, аудит. |
| Event-хранилище | ClickHouse 23.3 | Хранение и аналитика сетевых логов. |
| ML2-сервис | Python 3.11, FastAPI, scikit-learn | Детекция аномалий (Isolation Forest) + классификация угроз. |
| Автономный ML2 | Python 3.7+, scapy, scikit-learn | Обучение модели на pcap-файлах или захват с интерфейса. |
| Оркестрация | Docker Compose | Запуск всех сервисов одной командой. |

## Быстрый запуск через Docker Compose

```bash
# 1. Создать .env из шаблона
cp .env.example .env

# 2. Отредактировать .env — обязательно сменить:
#    DB_PASSWORD, CLICKHOUSE_PASSWORD, JWT_SECRET, INIT_ADMIN_PASSWORD

# 3. Запустить все сервисы
docker compose up --build -d

# 4. Открыть в браузере
open http://localhost:3000
```

| Поле | Значение по умолчанию |
|---|---|
| Логин | admin (из `INIT_ADMIN_LOGIN`) |
| Пароль | из `INIT_ADMIN_PASSWORD` в `.env` |
| Frontend | `http://localhost:3000` |
| Backend API | `http://localhost:8080` (через Nginx same-origin `/api`) |

Проверить состояние:

```bash
curl http://localhost:8080/healthz
```

## Порты сервисов

| Сервис | Контейнер | Порт хоста | Назначение |
|---|---|---|---:|
| Frontend | `nm-frontend` | `3000` | Web-панель администратора. |
| Backend | `nm-backend` | `8080` | REST API и healthcheck. |
| PostgreSQL | `nm-postgres` | `5432` | Транзакционное хранилище. |
| ClickHouse HTTP | `nm-clickhouse` | `8123` | HTTP-интерфейс ClickHouse. |
| ClickHouse native | `nm-clickhouse` | `9000` | Native-интерфейс ClickHouse. |
| ML2-сервис | `nm-ml2-http` | `5001` | FastAPI ML2 endpoint. |

## REST API

### Авторизация администратора

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"admin","password":"ChangeMe123!"}'
```

### Создание токена агента

```bash
ADMIN_TOKEN='<jwt_from_login>'
curl -X POST http://localhost:8080/api/admin/agents/tokens \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"agent_name":"office-gateway-1"}'
```

### Загрузка логов агентом

```bash
AGENT_TOKEN='<agent_token>'
curl -X POST http://localhost:8080/api/agent/logs \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -F 'archive=@traffic.zip'
```

Минимальный элемент `traffic.json`:

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

### Инциденты

```bash
curl "http://localhost:8080/api/incidents?page=1&limit=20&status=new" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"

# Смена статуса
curl -X PUT "http://localhost:8080/api/incidents/${INCIDENT_ID}/status" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"status":"investigating","comment":"Взято в работу"}'
```

### Статистика

```bash
curl http://localhost:8080/api/stats \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## Архитектура передачи данных

```
Агент (OpenWRT/RPi)
  └─► ZIP/traffic.json
         └─► POST /api/agent/logs (Go backend)
                ├─► ClickHouse (сохранение сырых логов)
                └─► POST /analyze → ml2-http-service
                       │ 1. Агрегация → 18 признаков (TimeWindowAggregator)
                       │ 2. Isolation Forest (модель /models/anomaly_model.pkl)
                       │ 3. Классификация: port_scan | ddos | anomaly
                       └─► { is_anomaly, anomaly_score, confidence, threat_type, recommendations }
                └─► Создание incident в PostgreSQL
                └─► Отправка Telegram (опционально)
```

## ML2-сервис

ML2-сервис (ml2-http-service) загружает предобученную модель Isolation Forest из `/models/anomaly_model.pkl`. При первом запуске, если модели нет, сервис работает, но ML-анализ недоступен (используются эвристики).

| Endpoint | Метод | Назначение |
|---|---|---|
| `/health` | GET | Проверка готовности и загрузки модели. |
| `/analyze` | POST | Принимает `{ agent_id, window_seconds, logs: [...] }`. Возвращает `{ is_anomaly, anomaly_score, confidence, threat_type, recommendations }`. |

### Обучение модели

Вы можете обучить модель на реальном трафике через `ml2/`:

```bash
# Обучение из pcap-файла
cd ml2
pip install -r requirements.txt
python main.py --mode train --pcap /path/to/dump.pcap --model /models/anomaly_model.pkl
```

Затем скопировать `.pkl` в volume `/models` — ml2-http-service подхватит её автоматически.

## Миграции и схема данных

Миграции PostgreSQL встроены в бинарный файл backend через `embed.FS` и применяются при старте. ClickHouse-схема создаётся через `CREATE TABLE IF NOT EXISTS`.

| Хранилище | Таблицы |
|---|---|
| PostgreSQL | `users`, `agents`, `incidents`, `alerts`, `audit_log` |
| ClickHouse | `network_logs` (с материализованным представлением `network_logs_hourly`) |

## Остановка и очистка

```bash
# Остановка
docker compose down

# Остановка + удаление данных
docker compose down -v