# Network Traffic Monitoring System

**Автор:** Manus AI  
**Версия проекта:** 1.1.0

## Назначение проекта

Проект реализует систему мониторинга сетевого трафика по предоставленному ТЗ. В состав входят **React frontend для администратора**, **Go backend**, **PostgreSQL**, **ClickHouse** и отдельный **Python ML-service**. Система принимает ZIP-архивы с сетевыми событиями от агентов, валидирует и сохраняет сырые логи в ClickHouse, агрегирует признаки, отправляет их в ML-service для обнаружения аномалий, создает инциденты в PostgreSQL и отображает результаты в web-панели с авторизацией, графиками, карточками инцидентов и управлением агентами.

> **Ключевая идея архитектуры:** PostgreSQL используется для транзакционных сущностей, пользователей, агентов, инцидентов и аудита, ClickHouse используется для высокообъемных событий сетевого трафика, а ML-service вынесен в отдельный Python/FastAPI сервис. Frontend обслуживается через Nginx и проксирует `/api` в backend внутри общей Docker-сети, поэтому в браузере используется единый origin без отдельной CORS-настройки.

## Состав репозитория

| Путь | Назначение |
|---|---|
| `frontend` | React/Vite frontend: авторизация администратора, dashboard-графики, инциденты, детали инцидента, агенты и генерация agent token. |
| `frontend/Dockerfile` | Multi-stage Dockerfile: сборка React-приложения и отдача статики через Nginx. |
| `frontend/nginx.conf` | Nginx-конфигурация: SPA fallback и reverse proxy `/api/` в Go backend. |
| `cmd/server` | Точка входа Go backend и Dockerfile backend-сервиса. |
| `internal/config` | Загрузка конфигурации из переменных окружения. |
| `internal/domain` | Доменные структуры: пользователи, агенты, логи, ML-запросы. |
| `internal/handler` | HTTP-обработчики REST API. |
| `internal/middleware` | JWT-аутентификация, авторизация агента, logging и panic recovery. |
| `internal/repository/postgres` | PostgreSQL-репозитории и embedded SQL migrations. |
| `internal/repository/clickhouse` | ClickHouse-репозиторий для хранения сетевых логов. |
| `internal/service` | Auth, log ingestion, ML-client и Telegram notifications. |
| `ml-service` | Python FastAPI ML-service с Isolation Forest и эвристической классификацией. |
| `clickhouse/config.xml` | Конфигурация ClickHouse для запуска в контейнере. |
| `docker-compose.yml` | Общий Compose-файл для frontend, backend, PostgreSQL, ClickHouse и ML-service. |
| `.env.example` | Шаблон переменных окружения для локального запуска. |
| `TZ.md` | Нормализованная копия исходного ТЗ. |

## Технологический стек

| Компонент | Технология | Роль в системе |
|---|---|---|
| Frontend | React 19, Vite, TypeScript, Recharts, Tailwind CSS | Web-панель администратора, авторизация, графики, таблицы и управление инцидентами. |
| Frontend runtime | Nginx 1.27 Alpine | Отдача SPA и same-origin proxy `/api` к backend. |
| Backend | Go 1.21, Gorilla Mux, pgx, goose | REST API, авторизация, валидация, ingestion pipeline, создание инцидентов. |
| OLTP-хранилище | PostgreSQL 15 | Пользователи, агенты, токены, инциденты, алерты, аудит. |
| Event-хранилище | ClickHouse 23.3 | Хранение и аналитическая обработка сетевых событий. |
| ML-service | Python 3.11, FastAPI, scikit-learn | Детекция аномалий на агрегированных признаках. |
| Оркестрация | Docker Compose | Локальный запуск всех сервисов одной командой. Docker Compose описывает мультиконтейнерное приложение декларативным YAML-файлом.[1] |

## Быстрый запуск через Docker Compose

Перед запуском убедитесь, что на машине установлен Docker с поддержкой Compose Plugin. Современный вариант команды запуска использует `docker compose`, как описано в официальной документации Docker.[1]

```bash
cp .env.example .env
```

Откройте `.env` и обязательно замените значения секретов. Минимально нужно поменять `DB_PASSWORD`, `CLICKHOUSE_PASSWORD`, `JWT_SECRET` и `INIT_ADMIN_PASSWORD`.

```bash
docker compose up --build -d
```

После старта откройте frontend в браузере:

```text
http://localhost:3000
```

Авторизация выполняется в web-интерфейсе через логин и пароль администратора из `.env`:

| Поле | Значение по умолчанию |
|---|---|
| Логин | значение `INIT_ADMIN_LOGIN`, по умолчанию `admin` |
| Пароль | значение `INIT_ADMIN_PASSWORD` из `.env` |
| Frontend URL | `http://localhost:3000` |
| Backend API URL | `http://localhost:8080`, но из frontend используется same-origin `/api` через Nginx proxy |

Проверить состояние backend можно отдельно:

```bash
curl http://localhost:8080/healthz
```

Ожидаемый ответ имеет вид JSON-объекта со статусом `ok` и состояниями зависимых сервисов.

## Что есть во frontend

Frontend добавлен как полноценная административная панель, а не как заглушка. После входа пользователь попадает в SOC/NOC dashboard, где данные загружаются из backend API; если API пока пустой, интерфейс сохраняет демонстрационную визуальную структуру, чтобы были видны все предусмотренные ТЗ экраны.

| Экран / функция | Реализация |
|---|---|
| Авторизация | Форма входа администратора через `POST /api/auth/login`; JWT сохраняется в `localStorage` и отправляется в `Authorization: Bearer`. |
| Dashboard | Метрики `total_incidents`, `new_incidents`, `active_agents`, `total_logs_processed`, `avg_ml_score`; графики временного ряда, распределение угроз и топ источников. |
| Инциденты | Таблица инцидентов с фильтрами по статусу и severity; загрузка через `GET /api/incidents`. |
| Детали инцидента | Inspector-панель с threat type, severity, ML score, details, raw sample и timeline; загрузка через `GET /api/incidents/{id}`. |
| Смена статуса | Управление статусом через `PUT /api/incidents/{id}/status`; поддерживаются `new`, `investigating`, `resolved`, `false_positive`. |
| Агенты | Список агентов через `GET /api/admin/agents` и генерация agent token через `POST /api/admin/agents/tokens`. |
| Выход | Удаление JWT из `localStorage` и возврат на экран входа. |

## Конфигурация окружения

| Переменная | Обязательность | Назначение |
|---|---:|---|
| `DB_PASSWORD` | Да | Пароль PostgreSQL-пользователя `nm_user`. |
| `CLICKHOUSE_PASSWORD` | Да | Пароль пользователя `default` в ClickHouse. |
| `JWT_SECRET` | Да | Секрет подписи JWT-токенов. Рекомендуется строка не короче 32 символов. |
| `INIT_ADMIN_LOGIN` | Да | Логин администратора, создаваемого при первом запуске. |
| `INIT_ADMIN_PASSWORD` | Да | Пароль администратора, создаваемого при первом запуске. |
| `TELEGRAM_BOT_TOKEN` | Нет | Токен Telegram-бота. Если пустой, уведомления не отправляются. |
| `TELEGRAM_ADMIN_CHAT_ID` | Нет | Chat ID администратора или группы для уведомлений. |
| `TELEGRAM_MIN_SEVERITY` | Нет | Минимальная критичность инцидента для Telegram-уведомления. |
| `TELEGRAM_MIN_ML_SCORE` | Нет | Минимальный ML-score для Telegram-уведомления. |
| `ML_WINDOW_SECONDS` | Нет | Размер окна агрегации логов для ML-анализа, по умолчанию 300 секунд. |
| `BASE_INCIDENT_URL` | Нет | Базовый URL для ссылок на инциденты в уведомлениях. |

## Порты сервисов

| Сервис | Контейнер | Порт хоста | Назначение |
|---|---|---:|---|
| Frontend | `nm-frontend` | `3000` | Web-панель администратора. |
| Backend | `nm-backend` | `8080` | REST API и healthcheck. |
| PostgreSQL | `nm-postgres` | `5432` | Транзакционное хранилище. |
| ClickHouse HTTP | `nm-clickhouse` | `8123` | HTTP-интерфейс ClickHouse. |
| ClickHouse native | `nm-clickhouse` | `9000` | Native-интерфейс ClickHouse. |
| ML-service | `nm-ml` | `5000` | FastAPI ML endpoint. |

## REST API

### Авторизация администратора

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"login":"admin","password":"ChangeMe123!"}'
```

Ответ содержит JWT-токен, который далее нужно передавать в заголовке `Authorization: Bearer <token>`.

### Создание токена агента

```bash
ADMIN_TOKEN='<jwt_from_login>'

curl -X POST http://localhost:8080/api/admin/agents/tokens \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"agent_name":"office-gateway-1"}'
```

Токен агента показывается только один раз. В базе хранится только SHA-256 hash токена, что снижает риск компрометации при утечке данных.

### Загрузка логов агентом

Backend принимает multipart-запрос с ZIP-архивом. Внутри архива должен находиться ровно один файл `traffic.json`, содержащий JSON-массив сетевых событий.

```bash
AGENT_TOKEN='<agent_token_from_previous_step>'

curl -X POST http://localhost:8080/api/agent/logs \
  -H "Authorization: Bearer ${AGENT_TOKEN}" \
  -F 'archive=@traffic.zip'
```

Минимальный пример элемента массива `traffic.json`:

```json
{
  "timestamp": "2026-05-11T12:00:00Z",
  "src_ip": "10.0.0.10",
  "dst_ip": "10.0.0.20",
  "src_port": 52341,
  "dst_port": 443,
  "protocol": "TCP",
  "packet_length": 512,
  "ttl": 64,
  "tcp_flags": ["SYN", "ACK"]
}
```

### Получение списка инцидентов

```bash
curl "http://localhost:8080/api/incidents?page=1&limit=20&status=new" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

Поддерживаются фильтры `status`, `severity_min`, `severity_max`, `threat_type`, `agent_id`, `from`, `to`, `sort_by` и `order`.

### Изменение статуса инцидента

```bash
INCIDENT_ID='<incident_uuid>'

curl -X PUT "http://localhost:8080/api/incidents/${INCIDENT_ID}/status" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"status":"investigating","comment":"Взято в работу"}'
```

Разрешенные статусы: `new`, `investigating`, `resolved`, `false_positive`.

### Статистика

```bash
curl http://localhost:8080/api/stats \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

## ML-service

ML-service реализован на FastAPI, который является современным Python-фреймворком для создания API и автоматически формирует OpenAPI-совместимую документацию.[2] При первом запуске сервис обучает базовую модель Isolation Forest на синтетическом нормальном профиле трафика и сохраняет ее в volume `/models`. Последующие запуски используют сохраненный файл модели.

| Endpoint | Метод | Назначение |
|---|---|---|
| `/health` | `GET` | Проверка готовности ML-service и загрузки модели. |
| `/analyze` | `POST` | Анализ агрегированных признаков сетевого окна и возврат `is_anomaly`, `anomaly_score`, `confidence`, `threat_type` и рекомендаций. |

## Миграции и схема данных

Миграции PostgreSQL встроены в бинарный файл backend через `embed.FS` и автоматически применяются при старте сервиса. Это упрощает запуск в контейнере: отдельный migration job не требуется. ClickHouse-схема создается backend при старте через `CREATE TABLE IF NOT EXISTS`.

| Хранилище | Таблицы |
|---|---|
| PostgreSQL | `users`, `agents`, `incidents`, `incident_status_history`, `alerts`. |
| ClickHouse | `network_logs`. |

## Проверка проекта без Docker

В sandbox были выполнены следующие проверки:

```bash
# Backend
PATH=/usr/local/go/bin:$PATH go build ./cmd/server

# Frontend
cd frontend
pnpm install --frozen-lockfile
pnpm run check
pnpm run build
```

Сборка Go backend, TypeScript-проверка frontend и production-сборка Vite завершились успешно. Полный запуск через Docker Compose в текущем sandbox не выполнялся, поскольку в среде отсутствует установленный Docker Engine; при этом в репозитории присутствуют все необходимые Dockerfile, Nginx-конфигурация и общий `docker-compose.yml`.

## Локальная разработка frontend без Docker

Для быстрой разработки интерфейса можно запустить frontend отдельно:

```bash
cd frontend
pnpm install
VITE_API_BASE_URL=http://localhost:8080 pnpm run dev
```

При Docker-запуске `VITE_API_BASE_URL` оставлен пустым, потому что Nginx внутри frontend-контейнера проксирует `/api` в `http://backend:8080/api`.

## Остановка и очистка

Остановить сервисы можно командой:

```bash
docker compose down
```

Если требуется удалить также данные PostgreSQL, ClickHouse и сохраненную ML-модель, используйте:

```bash
docker compose down -v
```

Команда `down -v` удаляет именованные volumes, поэтому ее не следует выполнять в среде, где нужно сохранить данные.

## Что реализовано по ТЗ

| Требование | Статус |
|---|---|
| Frontend с авторизацией администратора | Реализовано. |
| Dashboard-графики и статистика | Реализовано через Recharts и `/api/stats`. |
| Просмотр списка инцидентов | Реализовано через `/api/incidents`. |
| Просмотр деталей инцидента | Реализовано через `/api/incidents/{id}`. |
| Смена статуса инцидента | Реализовано через `/api/incidents/{id}/status`. |
| Просмотр агентов и генерация token | Реализовано через `/api/admin/agents` и `/api/admin/agents/tokens`. |
| Go backend с REST API | Реализовано. |
| JWT-аутентификация администратора | Реализовано. |
| Agent Bearer Token auth с hash-хранением токена | Реализовано. |
| Прием ZIP-архива с `traffic.json` | Реализовано. |
| Валидация сетевых логов | Реализовано. |
| Хранение raw logs в ClickHouse | Реализовано. |
| PostgreSQL для users/agents/incidents/alerts | Реализовано. |
| ML-service на Python/FastAPI | Реализовано. |
| Автоматическое создание инцидентов по ML-анализу | Реализовано. |
| Telegram notifications | Реализовано как опциональная интеграция через Bot API. |
| Dockerfile для frontend | Реализовано. |
| Dockerfile для backend | Реализовано. |
| Dockerfile для ML-service | Реализовано. |
| Общий `docker-compose.yml` | Реализовано. |
| README с запуском | Реализовано. |

## References

[1]: https://docs.docker.com/compose/ "Docker Compose documentation"  
[2]: https://fastapi.tiangolo.com/ "FastAPI documentation"
