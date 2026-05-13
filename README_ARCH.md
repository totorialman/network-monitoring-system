# Архитектура системы мониторинга сети

## Компоненты

| Компонент | Порт | Назначение |
|-----------|------|------------|
| **Go Backend** (`cmd/server/`) | 8080 | Приём ZIP, валидация, запись в ClickHouse, вызов ML, создание инцидентов |
| **ml2-http-service** (FastAPI) | 5000 | Агрегация 18 признаков → Isolation Forest → классификация угроз |
| **PostgreSQL** | 5432 | Пользователи, агенты, инциденты, алерты, аудит |
| **ClickHouse** | 9000 | Сырые сетевые логи + материализованное представление `network_logs_hourly` |
| **Frontend** (React + TypeScript + Nginx) | 3000 | Дашборд, инциденты, агенты, Inspector с сырыми логами |
| **Telegram Bot** | — | Оповещения об аномалиях (best-effort) |

## Конвейер данных

```
Агент ── POST /api/agent/logs (ZIP с .json файлами, токен в Authorization) ──► Go Backend
                                      │
                                      ▼
                              1. Проверка токена (SHA-256)
                              2. Распаковка ZIP (любые .json файлы, не только traffic.json)
                              3. Валидация JSON (обязательные поля: timestamp, src_ip, dst_ip, proto)
                              4. Вставка ВСЕХ валидных логов в ClickHouse → таблица network_logs
                              5. Отправка сырых логов в ml2-http-service (POST /analyze)
                              6. ML агрегирует 18 признаков → Isolation Forest → порог 0.65
                              7. ТОЛЬКО аномалии (is_anomaly=true) → запись в PostgreSQL incidents
                              8. Отправка Telegram-уведомления (best-effort, c retry)
                                      │
                                      ▼
                              Фронтенд:
                              - GET /api/incidents → список инцидентов
                              - GET /api/incidents/{id} → детали инцидента
                              - GET /api/agents/{agent_id}/logs → СЫРЫЕ ЛОГИ из ClickHouse
                              - GET /api/stats → агрегированная статистика
                              - GET /api/agents → реестр агентов
```

## REST API

| Метод | URI | Назначение |
|-------|-----|------------|
| POST | `/api/auth/login` | Аутентификация администратора (JWT) |
| POST | `/api/agent/logs` | Приём ZIP-архива от агента (Agent Auth) |
| POST | `/api/admin/agents/tokens` | Генерация токена агента (Admin JWT) |
| GET | `/api/agents` | Список агентов |
| GET | `/api/agents/{agent_id}/logs` | **Сырые логи из ClickHouse для инцидента** |
| GET | `/api/incidents` | Список инцидентов с пагинацией/фильтрацией |
| GET | `/api/incidents/{id}` | Детали инцидента |
| PUT | `/api/incidents/{id}/status` | Смена статуса инцидента |
| GET | `/api/stats` | Агрегированная статистика для дашборда |
| GET | `/healthz` | Health check |

## Ключевые соответствия ТЗ

- **Создание админа через ENV**: `INIT_ADMIN_LOGIN`, `INIT_ADMIN_PASSWORD`
- **Валидация JSON**: обязательные поля `timestamp`, `src_ip`, `dst_ip`, `proto`; проверка IPv4
- **10000 логов → ClickHouse**: все валидные, без исключений
- **ML-порог 0.65**: только аномалии попадают в incidents
- **50 инцидентов в PostgreSQL**: только аномалии, не все 10000
- **Разворачивание сырых логов**: `GET /api/agents/{agent_id}/logs` читает ClickHouse
- **Telegram-уведомления**: при создании инцидента (best-effort, exponential backoff)
- **Circuit Breaker**: для ML-сервиса (3 failures → open, 30s timeout)