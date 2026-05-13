# Архитектура системы мониторинга сети

## Схема передачи данных между компонентами

```
┌──────────────┐     ZIP/traffic.json     ┌───────────────────────────────────────┐
│   Агент       │ ────── POST ──────────► │          Go Backend (:8080)           │
│ (OpenWRT/RPi) │     /api/agent/logs     │                                       │
│              │                         │  1. Проверка токена агента (SHA-256)   │
│              │                         │  2. Распаковка ZIP                     │
│              │                         │  3. Валидация JSON-логов               │
│              │                         │  4. Сохранение в ClickHouse            │
│              │                         │  5. Передача сырых логов в ML2         │
│              │                         │  6. Создание инцидента (если аномалия) │
│              │                         │  7. Отправка Telegram (опционально)    │
└──────────────┘                         └───────────────────────────────────────┘
                                                   │
                     ┌─────────────────────────────┼──────────────────────────┐
                     │                             │                          │
                     ▼                             ▼                          ▼
          ┌──────────────────┐       ┌──────────────────────┐       ┌─────────────────┐
          │   ClickHouse     │       │   ml2-http-service   │       │   PostgreSQL    │
          │   :9000          │       │   :5000              │       │   :5432         │
          │                  │       │                      │       │                 │
          │ Сырые логи:      │       │ 1. Агрегация в 18    │       │ Инциденты       │
          │ - network_logs   │       │    признаков:        │       │ Агенты          │
          │ - network_logs_  │       │    - packet_count    │       │ Пользователи    │
          │   hourly (MV)    │       │    - duration        │       │ Алерты          │
          │                  │       │    - packets_per_sec │       │ Аудит           │
          │                  │       │    - unique_src_ip   │       │                 │
          │                  │       │    - unique_dst_port │       │                 │
          │                  │       │    - avg_length/ttl  │       │                 │
          │                  │       │    - proto_tcp/udp/  │       │                 │
          │                  │       │      icmp            │       │                 │
          │                  │       │    - unique_tcp_     │       │                 │
          │                  │       │      flags           │       │                 │
          │                  │       │    - icmp_count      │       │                 │
          │                  │       │                      │       │                 │
          │                  │       │ 2. Isolation Forest  │       │                 │
          │                  │       │    (загружает .pkl)  │       │                 │
          │                  │       │                      │       │                 │
          │                  │       │ 3. Классификация:    │       │                 │
          │                  │       │    port_scan/ddos/   │       │                 │
          │                  │       │    anomaly           │       │                 │
          │                  │       │                      │       │                 │
          │                  │       │ 4. Рекомендации      │       │                 │
          └──────────────────┘       └──────────────────────┘       └─────────────────┘
                                                   │
                     ┌─────────────────────────────┘
                     │
                     ▼
          ┌──────────────────────┐
          │   Telegram Bot API   │
          │                      │
          │ Уведомление:         │
          │ 🚨 АНОМАЛИЯ         │
          │ Тип: port_scan       │
          │ Severity: 4/5        │
          │ ML score: 0.72       │
          │ [Расследовать]       │
          │ [Ложное срабатывание]│
          └──────────────────────┘
```

## Что и кому передаётся

### 1. Агент → Go Backend
**Что:** ZIP-архив с одним файлом `traffic.json` (массив JSON-объектов)
**Как:** `POST /api/agent/logs` + `Authorization: Bearer <agent_token>` + multipart
**Пример:**
```json
{
  "timestamp": 1713623722.45,
  "src_mac": "00:1A:2B:3C:4D:5E",
  "dst_mac": "FF:FF:FF:FF:FF:FF",
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

### 2. Go Backend → ClickHouse
**Что:** Те же сырые логи, вставка батчем
**Таблица:** `network_logs` с колонками: timestamp, agent_id, src_ip, dst_ip, src_port, dst_port, proto, ttl, length, tcp_flags, src_mac, dst_mac, icmp_type, icmp_code, vlan, eth_type

### 3. Go Backend → ml2-http-service
**Что:** Сырые логи (не агрегированные!)
**Как:** HTTP POST `http://ml2-http-service:5000/analyze`
**Тело запроса:**
```json
{
  "agent_id": "uuid-строкой",
  "window_seconds": 300,
  "start_time": "2026-05-11T12:00:00Z",
  "end_time": "2026-05-11T12:05:00Z",
  "logs": [
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
    // ... все логи за окно
  ]
}
```

### 4. ml2-http-service → Go Backend (ответ)
**Что делает ml2 внутри:**
1. Агрегирует все сырые логи в **18 признаков** (TimeWindowAggregator из ml2/)
2. Нормализует через `StandardScaler`
3. Запускает `Isolation Forest.predict()` (модель из `/models/anomaly_model.pkl`)
4. Классифицирует угрозу (port_scan/ddos/anomaly)
5. Генерирует рекомендации

**Ответ:**
```json
{
  "is_anomaly": true,
  "anomaly_score": 0.7215,
  "confidence": 0.7215,
  "threat_type": "port_scan",
  "recommendations": [
    "Проверьте источник трафика...",
    "Ограничьте источник на perimeter firewall..."
  ]
}
```

### 5. Go Backend → PostgreSQL
**Что:** Инцидент (только если `is_anomaly = true`)
**Таблица:** `incidents` с колонками: id, agent_id, threat_type, severity, status, ml_score, details (JSONB)

### 6. Go Backend → Telegram (опционально)
**Что:** Форматированное сообщение
```text
🚨 ОБНАРУЖЕНА АНОМАЛИЯ
Тип: port_scan
Серьёзность: 4/5
Время: 2026-05-11T12:05:00Z
Оценка ML: 0.72
Подробности: https://monitor.local/incidents/uuid
```

### 7. Go Backend → Frontend (REST API)
**Что:** JSON через REST эндпоинты

| Endpoint | Что возвращает |
|---|---|
| `GET /api/stats` | overview (total/new incidents, active agents, logs, avg ML), timeseries (по часам), threat_distribution, top_sources |
| `GET /api/incidents` | Список инцидентов с пагинацией и фильтрацией |
| `GET /api/incidents/{id}` | Детали одного инцидента |
| `GET /api/agents` | Список агентов с last_seen, logs_sent_today |

### 8. Frontend → Пользователь (браузер)
**Что:** Интерфейс администратора:
- 📊 Dashboard: KPI-карточки + графики (AreaChart, PieChart, BarChart)
- 🛡️ Инциденты: таблица с фильтрами + Inspector-панель
- 📡 Агенты: карточки + генерация токенов

## Краткий data flow (одним абзацем)

> **Агент** 🡒 ZIP с JSON-логами 🡒 **Go Backend** 🡒 сохраняет в ClickHouse + отправляет сырые логи в **ml2-http-service** 🡒 ml2 сам агрегирует в 18 признаков, запускает Isolation Forest, классифицирует угрозу 🡒 возвращает `{ is_anomaly, score, threat_type }` 🡒 Go создаёт инцидент в PostgreSQL 🡒 (опционально) Telegram 🡒 Frontend отображает на дашборде.

## Быстрый запуск

```bash
cp .env.example .env
# Отредактировать .env (DB_PASSWORD, JWT_SECRET, INIT_ADMIN_PASSWORD)
docker compose up --build -d
open http://localhost:3000