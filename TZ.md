# Техническое задание: Серверное приложение для мониторинга сети и детекции аномалий

## 1. Обзор архитектуры

### 1.1. Диаграмма компонентов

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose (v2)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────┐     ┌─────────────────┐               │
│  │   Agent (External) │→│  Go Backend      │               │
│  │   (OpenWRT/RPi) │ZIP│  (Clean Arch)    │               │
│  └─────────────────┘   │  :8080           │               │
│                        └────────┬────────┘               │
│                                 │                          │
│           ┌─────────────────────┼─────────────────────┐   │
│           │                     │                     │   │
│           ▼                     ▼                     ▼   │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐│
│  │   PostgreSQL    │ │   ClickHouse    │ │   ML Service    ││
│  │   15+           │ │   23.3+         │ │   Python 3.7+   ││
│  │   :5432         │ │   :8123         │ │   :5000         ││
│  │   Metadata      │ │   Network Logs  │ │   Isolation     ││
│  │   - users       │ │   - network_logs│ │   Forest        ││
│  │   - agents      │ │                 │ │                 ││
│  │   - incidents   │ │                 │ │                 ││
│  │   - alerts      │ │                 │ │                 ││
│  └─────────────────┘ └─────────────────┘ └────────┬────────┘│
│                                                   │          │
│                                                   ▼          │
│                                          ┌─────────────────┐│
│                                          │   Telegram Bot  ││
│                                          │   API           ││
│                                          └─────────────────┘│
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 1.2. Сервисы и их назначение

| № | Сервис | Язык/Технология | Порт | Назначение |
|---|--------|----------------|------|-----------|
| 1 | `backend` | Go 1.21+ (Clean Architecture) | 8080 | Основной API: приём логов, аутентификация, бизнес-логика |
| 2 | `postgres` | PostgreSQL 15+ | 5432 | Хранение метаданных: пользователи, агенты, инциденты, алерты |
| 3 | `clickhouse` | ClickHouse 23.3+ | 8123 (HTTP), 9000 (native) | Хранение и аналитика сетевых логов (временные ряды) |
| 4 | `ml-service` | Python 3.7+ (scikit-learn) | 5000 | ML-инференс: загрузка модели, предсказание аномалий |
| 5 | `frontend` *(опционально)* | React 18 + TypeScript | 3000 | Веб-интерфейс администратора |

**Всего: 4 обязательных сервиса + 1 опциональный.**

---

## 2. Технологический стек (Go Backend)

### 2.1. Обязательные зависимости

```go
// go.mod
module network-monitor-backend

go 1.21

require (
    // HTTP & Routing
    github.com/gorilla/mux v1.8.1
    
    // Database
    github.com/jackc/pgx/v5 v5.5.0          // PostgreSQL driver
    github.com/ClickHouse/clickhouse-go/v2 v2.20.0  // ClickHouse driver
    github.com/pressly/goose/v3 v3.18.0     // Database migrations
    
    // Auth & Security
    github.com/golang-jwt/jwt/v5 v5.2.0     // JWT tokens
    golang.org/x/crypto v0.18.0             // bcrypt, SHA256
    
    // Utilities
    github.com/google/uuid v1.5.0           // UUID generation
    github.com/go-playground/validator/v10 v10.16.0  // Struct validation
    go.uber.org/zap v1.26.0                 // Structured logging
    
    // File handling
    archive/zip                             // Standard lib
    encoding/json                           // Standard lib
)
```

### 2.2. Clean Architecture структура

```
internal/
├── cmd/
│   └── server/
│       └── main.go              # Точка входа, инициализация зависимостей
│
├── config/
│   ├── config.go                # Структура конфига
│   └── loader.go                # Загрузка из ENV/файла
│
├── pkg/                         # Переиспользуемые утилиты
│   ├── logger/
│   ├── jwt/
│   ├── hash/
│   └── httpclient/
│
├── internal/
│   ├── domain/                  # Бизнес-объекты (entities)
│   │   ├── user.go
│   │   ├── agent.go
│   │   ├── incident.go
│   │   ├── network_log.go
│   │   └── ml_request.go
│   │
│   ├── repository/              # Интерфейсы доступа к данным
│   │   ├── postgres/
│   │   │   ├── user_repo.go
│   │   │   ├── agent_repo.go
│   │   │   ├── incident_repo.go
│   │   │   └── migrations/      # SQL-файлы для goose
│   │   └── clickhouse/
│   │       └── log_repo.go
│   │
│   ├── service/                 # Бизнес-логика
│   │   ├── auth_service.go
│   │   ├── log_ingest_service.go
│   │   ├── ml_service.go        # HTTP-клиент к ML-сервису
│   │   ├── incident_service.go
│   │   └── notification_service.go  # Telegram
│   │
│   ├── handler/                 # HTTP-обработчики (gorilla/mux)
│   │   ├── auth_handler.go
│   │   ├── agent_handler.go
│   │   ├── incident_handler.go
│   │   └── stats_handler.go
│   │
│   └── middleware/
│       ├── auth.go              # JWT validation
│       ├── logging.go           # Request logging
│       └── recover.go           # Panic recovery
│
└── migrations/                  # Goose migration files
    ├── 00001_init_schema.down.sql
    ├── 00001_init_schema.up.sql
    └── ...
```

---

## 3. Схема данных

### 3.1. PostgreSQL (метаданные)

```sql
-- users: администраторы системы
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) CHECK (role IN ('admin', 'viewer')) DEFAULT 'viewer',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- agents: клиентские агенты, отправляющие логи
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    token_hash CHAR(64) UNIQUE NOT NULL,  -- SHA256 от токена
    last_seen TIMESTAMPTZ,
    status VARCHAR(20) CHECK (status IN ('active', 'inactive')) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- incidents: выявленные аномалии
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    threat_type VARCHAR(50) CHECK (threat_type IN ('ddos', 'port_scan', 'anomaly', 'other')),
    severity INTEGER CHECK (severity BETWEEN 1 AND 5),
    status VARCHAR(30) CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive')) DEFAULT 'new',
    ml_score FLOAT,                    -- anomaly_score от модели
    details JSONB,                     -- дополнительная информация (топ IP, метрики)
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id)
);

-- alerts: история отправленных уведомлений
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    channel VARCHAR(50) DEFAULT 'telegram',
    chat_id VARCHAR(100),
    sent_at TIMESTAMPTZ,
    status VARCHAR(20) CHECK (status IN ('sent', 'failed', 'retrying')),
    error_message TEXT
);

-- audit_log: аудит действий администратора
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    details JSONB
);

-- Индексы для ускорения запросов
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_created ON incidents(created_at DESC);
CREATE INDEX idx_agents_token ON agents(token_hash);
CREATE INDEX idx_audit_user ON audit_log(user_id, created_at);
```

### 3.2. ClickHouse (сетевые логи)

```sql
-- network_logs: сырые логи от агентов
CREATE TABLE network_logs (
    timestamp DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    agent_id UUID,
    src_ip IPv4,
    dst_ip IPv4,
    src_port UInt16,
    dst_port UInt16,
    proto UInt8,
    ttl UInt8,
    length UInt16,
    tcp_flags String,
    src_mac String,
    dst_mac String,
    icmp_type Nullable(UInt8),
    icmp_code Nullable(UInt8),
    vlan Nullable(UInt16),
    eth_type String,
    
    -- Материализованные колонки для быстрых фильтров
    hour DateTime MATERIALIZED toStartOfHour(timestamp),
    day Date MATERIALIZED toDate(timestamp)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (agent_id, timestamp, src_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS 
    index_granularity = 8192,
    compress_primary_key = true;

-- Проекция для агрегаций по времени (опционально, для ускорения дашборда)
CREATE MATERIALIZED VIEW network_logs_hourly
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (agent_id, hour, src_ip)
AS SELECT
    agent_id,
    toStartOfHour(timestamp) AS hour,
    src_ip,
    count() AS packet_count,
    uniq(dst_ip) AS unique_dst_ips,
    uniq(dst_port) AS unique_dst_ports,
    avg(length) AS avg_length,
    sum(length) AS total_bytes
FROM network_logs
GROUP BY agent_id, hour, src_ip;

-- Индексы (вторичные) для частых запросов
CREATE INDEX idx_src_ip ON network_logs src_ip TYPE set(10000) GRANULARITY 4;
CREATE INDEX idx_dst_port ON network_logs dst_port TYPE set(1000) GRANULARITY 4;
```

---

## 4. REST API Specification

### 4.1. Аутентификация

**Все защищённые эндпоинты требуют заголовок:**
```
Authorization: Bearer <jwt_token>
```

**Формат ошибки:**
```json
{
  "error": {
    "code": "AUTH_REQUIRED",
    "message": "Valid authorization token required",
    "details": {}
  }
}
```

### 4.2. Эндпоинты

#### 4.2.1. Аутентификация администратора

```
POST /api/auth/login
Content-Type: application/json

Request:
{
  "login": "admin",
  "password": "secure_password"
}

Response (200 OK):
{
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_at": "2024-01-15T12:00:00Z",
    "user": {
      "id": "uuid",
      "login": "admin",
      "role": "admin"
    }
  }
}

Response (401 Unauthorized):
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid login or password"
  }
}
```

#### 4.2.2. Генерация токена для агента

```
POST /api/admin/agents/tokens
Authorization: Bearer <admin_jwt>

Request:
{
  "agent_name": "router-office-1"
}

Response (201 Created):
{
  "data": {
    "agent_id": "uuid",
    "token": "plain_text_token_abc123",  -- Показывается ТОЛЬКО один раз!
    "created_at": "2024-01-15T10:00:00Z"
  }
}
```

#### 4.2.3. Приём логов от агента (КЛЮЧЕВОЙ ЭНДПОИНТ)

```
POST /api/agent/logs
Authorization: Bearer <agent_token>
Content-Type: multipart/form-data

Form field:
- name: "archive"
- filename: "logs_20240115_120000.zip"
- content: ZIP-архив, содержащий ОДИН файл `traffic.json`

Структура traffic.json (массив объектов):
[
  {
    "timestamp": 1705320000.123,
    "src_mac": "00:1A:2B:3C:4D:5E",
    "dst_mac": "FF:FF:FF:LL:FF:FF",
    "vlan": null,
    "eth_type": "0x0800",
    "src_ip": "192.168.1.10",
    "dst_ip": "10.0.0.5",
    "icmp_type": null,
    "icmp_code": null,
    "proto": 6,
    "ttl": 64,
    "src_port": 54321,
    "dst_port": 80,
    "tcp_flags": "SYN",
    "length": 64
  }
]

Response (202 Accepted) - обработка асинхронная:
{
  "data": {
    "batch_id": "uuid",
    "records_received": 15000,
    "records_valid": 14987,
    "records_invalid": 13,
    "processing_status": "queued"
  }
}

Response (400 Bad Request) - невалидный ZIP/JSON:
{
  "error": {
    "code": "INVALID_PAYLOAD",
    "message": "ZIP archive is corrupted or missing traffic.json",
    "details": {
      "invalid_records": [
        {"index": 42, "reason": "missing required field: src_ip"},
        {"index": 105, "reason": "invalid IP format: '999.999.999.999'"}
      ]
    }
  }
}

Response (401 Unauthorized):
{
  "error": {
    "code": "INVALID_TOKEN",
    "message": "Agent token is invalid or revoked"
  }
}
```

#### 4.2.4. Получение списка инцидентов

```
GET /api/incidents
Authorization: Bearer <admin_jwt>

Query params:
- page: integer (default: 1)
- limit: integer (default: 50, max: 200)
- status: string (optional: new|investigating|resolved|false_positive)
- threat_type: string (optional: ddos|port_scan|anomaly|other)
- agent_id: uuid (optional)
- severity_min: integer (1-5, optional)
- severity_max: integer (1-5, optional)
- from: RFC3339 datetime (optional)
- to: RFC3339 datetime (optional)
- sort_by: string (default: created_at, options: created_at|severity|ml_score)
- order: string (default: desc, options: asc|desc)

Response (200 OK):
{
  "data": {
    "items": [
      {
        "id": "uuid",
        "agent_id": "uuid",
        "agent_name": "router-office-1",
        "created_at": "2024-01-15T12:05:00Z",
        "threat_type": "port_scan",
        "severity": 4,
        "status": "new",
        "ml_score": 0.72,
        "summary": {
          "unique_src_ips": 1,
          "unique_dst_ports": 150,
          "packet_count": 5000,
          "time_window_sec": 300
        }
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total": 127,
      "total_pages": 3
    }
  }
}
```

#### 4.2.5. Детали инцидента

```
GET /api/incidents/{id}
Authorization: Bearer <admin_jwt>

Response (200 OK):
{
  "data": {
    "id": "uuid",
    "agent_id": "uuid",
    "created_at": "2024-01-15T12:05:00Z",
    "threat_type": "port_scan",
    "severity": 4,
    "status": "new",
    "ml_score": 0.72,
    "details": {
      "top_dst_ports": [22, 80, 443, 3389, 8080],
      "top_dst_ips": ["10.0.0.5", "10.0.0.6"],
      "tcp_flags_distribution": {"SYN": 4800, "ACK": 200},
      "packets_per_second": 16.67,
      "entropy_dst_ports": 0.92
    },
    "raw_logs_sample": [
      -- 10-20 примеров сырых логов из ClickHouse для этого инцидента
    ],
    "timeline": [
      {"timestamp": "2024-01-15T12:00:00Z", "event": "incident_created"},
      {"timestamp": "2024-01-15T12:05:00Z", "event": "alert_sent", "channel": "telegram"}
    ]
  }
}
```

#### 4.2.6. Обновление статуса инцидента

```
PUT /api/incidents/{id}/status
Authorization: Bearer <admin_jwt>
Content-Type: application/json

Request:
{
  "status": "investigating",  -- new|investigating|resolved|false_positive
  "comment": "Начал расследование, блокирую источник"  -- опционально
}

Response (200 OK):
{
  "data": {
    "id": "uuid",
    "status": "investigating",
    "updated_at": "2024-01-15T12:10:00Z",
    "updated_by": "admin"
  }
}
```

#### 4.2.7. Агрегированная статистика

```
GET /api/stats
Authorization: Bearer <admin_jwt>

Query params:
- period: string (default: 24h, options: 1h|6h|24h|7d|30d)
- group_by: string (default: hour, options: hour|day)

Response (200 OK):
{
  "data": {
    "overview": {
      "total_incidents": 45,
      "new_incidents": 12,
      "active_agents": 8,
      "total_logs_processed": 2500000,
      "avg_ml_score": 0.34
    },
    "timeseries": [
      {
        "timestamp": "2024-01-15T00:00:00Z",
        "incident_count": 3,
        "log_volume": 45000,
        "avg_severity": 2.5
      }
    ],
    "threat_distribution": {
      "ddos": 5,
      "port_scan": 28,
      "anomaly": 10,
      "other": 2
    },
    "top_sources": [
      {"ip": "192.168.1.100", "incident_count": 8, "threat_types": ["port_scan"]}
    ]
  }
}
```

#### 4.2.8. Список агентов

```
GET /api/agents
Authorization: Bearer <admin_jwt>

Response (200 OK):
{
  "data": {
    "items": [
      {
        "id": "uuid",
        "name": "router-office-1",
        "token_prefix": "abc123...",  -- первые 8 символов для идентификации
        "last_seen": "2024-01-15T11:58:00Z",
        "status": "active",
        "logs_sent_today": 144,
        "last_incident_at": "2024-01-15T12:05:00Z"
      }
    ]
  }
}
```

#### 4.2.9. Health check

```
GET /healthz

Response (200 OK):
{
  "status": "ok",
  "services": {
    "postgres": "connected",
    "clickhouse": "connected", 
    "ml_service": "healthy",
    "telegram": "ok"
  },
  "version": "1.0.0",
  "uptime_sec": 3600
}
```

---

## 5. Обработка ZIP-архива: детальный алгоритм

### 5.1. Валидация и распаковка

```go
// Псевдокод обработчика POST /api/agent/logs

func (h *AgentHandler) UploadLogs(w http.ResponseWriter, r *http.Request) {
    // 1. Проверка токена агента (middleware)
    agent := r.Context().Value(ctxAgentKey).(*domain.Agent)
    
    // 2. Парсинг multipart form (max 50MB)
    r.ParseMultipartForm(50 << 20)
    file, _, err := r.FormFile("archive")
    
    // 3. Валидация ZIP
    zipReader, err := zip.NewReader(file, fileSize)
    if len(zipReader.File) != 1 {
        return Error(w, ErrSingleFileExpected, http.StatusBadRequest)
    }
    if zipReader.File[0].Name != "traffic.json" {
        return Error(w, ErrWrongFilename, http.StatusBadRequest)
    }
    
    // 4. Распаковка в memory buffer (не на диск!)
    rc, _ := zipReader.File[0].Open()
    defer rc.Close()
    
    // 5. Stream-парсинг JSON массива с валидацией схемы
    decoder := json.NewDecoder(rc)
    token, _ := decoder.Token() // должен быть '['
    
    var validLogs []domain.NetworkLog
    var errors []ValidationError
    
    for decoder.More() {
        var raw map[string]interface{}
        if err := decoder.Decode(&raw); err != nil {
            errors = append(errors, ValidationError{Reason: "json_parse_error"})
            continue
        }
        
        // Валидация обязательных полей
        if !validateRequiredFields(raw) {
            errors = append(errors, ValidationError{Reason: "missing_required_field"})
            continue
        }
        
        // Конвертация в доменную модель
        log, err := domain.NewNetworkLogFromMap(raw)
        if err != nil {
            errors = append(errors, ValidationError{Reason: err.Error()})
            continue
        }
        log.AgentID = agent.ID
        validLogs = append(validLogs, log)
    }
    
    // 6. Асинхронная запись в ClickHouse + запуск ML
    go h.processLogsBatch(validLogs, agent.ID)
    
    // 7. Немедленный ответ
    RespondJSON(w, http.StatusAccepted, ProcessResponse{
        BatchID: uuid.New(),
        RecordsReceived: len(validLogs) + len(errors),
        RecordsValid: len(validLogs),
        RecordsInvalid: len(errors),
        Status: "queued",
    })
}
```

### 5.2. Асинхронная обработка батча

```go
func (s *LogIngestService) processLogsBatch(logs []domain.NetworkLog, agentID uuid.UUID) {
    // 1. Пакетная вставка в ClickHouse (batch insert)
    if err := s.clickhouseRepo.BatchInsert(context.Background(), logs); err != nil {
        s.logger.Error("clickhouse insert failed", zap.Error(err))
        // Retry logic или fallback в очередь
        return
    }
    
    // 2. Подготовка признаков для ML (агрегация по временным окнам)
    features := s.extractFeatures(logs)  // см. раздел 6
    
    // 3. Вызов ML-сервиса
    mlResult, err := s.mlClient.Analyze(context.Background(), ml.AnalyzeRequest{
        AgentID: agentID,
        Features: features,
        TimeWindow: s.config.ML.WindowSizeSeconds,
    })
    if err != nil {
        s.logger.Error("ml service call failed", zap.Error(err))
        // Circuit breaker: не блокируем основной поток
        return
    }
    
    // 4. Если аномалия — создаём инцидент
    if mlResult.IsAnomaly {
        incident := &domain.Incident{
            AgentID: agentID,
            ThreatType: classifyThreat(mlResult, features),
            Severity: calculateSeverity(mlResult.Score, len(logs)),
            MLScore: mlResult.Score,
            Details: buildIncidentDetails(mlResult, features),
        }
        if err := s.incidentRepo.Create(context.Background(), incident); err != nil {
            s.logger.Error("failed to create incident", zap.Error(err))
            return
        }
        
        // 5. Отправка уведомления в Telegram
        go s.notificationService.SendTelegram(context.Background(), incident)
    }
}
```

---

## 6. Интеграция с ML-сервисом

### 6.1. Формат запроса к ML-сервису

```go
// internal/domain/ml_request.go
type AnalyzeRequest struct {
    AgentID      uuid.UUID            `json:"agent_id"`
    TimeWindow   float64              `json:"window_seconds"`  // 5.0
    StartTime    time.Time            `json:"start_time"`      // RFC3339
    EndTime      time.Time            `json:"end_time"`
    
    // Агрегированные признаки (извлекаются из сырых логов)
    Features     FeatureVector        `json:"features"`
}

type FeatureVector struct {
    PacketCount        uint64    `json:"packet_count"`
    PacketsPerSecond   float64   `json:"pps"`
    UniqueSrcIPs       uint64    `json:"unique_src_ips"`
    UniqueDstIPs       uint64    `json:"unique_dst_ips"`
    UniqueDstPorts     uint64    `json:"unique_dst_ports"`
    UniqueSrcPorts     uint64    `json:"unique_src_ports"`
    
    // Протоколы
    ProtoTCP           uint64    `json:"proto_tcp"`
    ProtoUDP           uint64    `json:"proto_udp"`
    ProtoICMP          uint64    `json:"proto_icmp"`
    
    // TCP флаги
    TCPFlagsSYN        uint64    `json:"tcp_syn"`
    TCPFlagsACK        uint64    `json:"tcp_ack"`
    TCPFlagsFIN        uint64    `json:"tcp_fin"`
    TCPFlagsRST        uint64    `json:"tcp_rst"`
    
    // Статистики длины пакетов
    AvgLength          float64   `json:"avg_length"`
    MinLength          uint16    `json:"min_length"`
    MaxLength          uint16    `json:"max_length"`
    
    // TTL
    AvgTTL             float64   `json:"avg_ttl"`
    
    // Энтропия портов (мера случайности распределения)
    DstPortEntropy     float64   `json:"dst_port_entropy"`
    
    // ICMP
    ICMPCount          uint64    `json:"icmp_count"`
    
    // Разброс целевых IP (для детекции сканирования)
    ConnectionSpread   float64   `json:"connection_spread"`  // unique_dst_ips / packet_count
}
```

### 6.2. Формат ответа от ML-сервиса

```go
type AnalyzeResponse struct {
    IsAnomaly    bool                `json:"is_anomaly"`
    AnomalyScore float64             `json:"anomaly_score"`  // -1.0 .. 1.0
    Confidence   float64             `json:"confidence"`     // 0.0 .. 1.0
    
    // Классификация типа угрозы (если аномалия)
    ThreatType   string              `json:"threat_type"`    // port_scan|ddos|anomaly|other
    
    // Дополнительные метрики для отчёта
    TopSuspiciousIPs []string        `json:"top_suspicious_ips"`  // до 10 IP
    TopTargetedPorts []uint16        `json:"top_targeted_ports"`  // до 10 портов
    
    // Рекомендации для администратора
    Recommendations []string         `json:"recommendations"`
}
```

### 6.3. HTTP-клиент к ML-сервису

```go
// internal/service/ml_service.go
type MLClient interface {
    Analyze(ctx context.Context, req ml.AnalyzeRequest) (*ml.AnalyzeResponse, error)
    HealthCheck(ctx context.Context) error
}

type mlHTTPClient struct {
    baseURL    string
    httpClient *http.Client
    timeout    time.Duration
    logger     *zap.Logger
}

func (c *mlHTTPClient) Analyze(ctx context.Context, req ml.AnalyzeRequest) (*ml.AnalyzeResponse, error) {
    ctx, cancel := context.WithTimeout(ctx, c.timeout)
    defer cancel()
    
    body, _ := json.Marshal(req)
    httpReq, _ := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/analyze", bytes.NewReader(body))
    httpReq.Header.Set("Content-Type", "application/json")
    
    resp, err := c.httpClient.Do(httpReq)
    // ... обработка ошибок, retry при 5xx, circuit breaker ...
    
    var result ml.AnalyzeResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}
```

---

## 7. Telegram уведомления

### 7.1. Конфигурация

```go
// config/config.go
type TelegramConfig struct {
    BotToken    string        `env:"TELEGRAM_BOT_TOKEN,required"`
    AdminChatID string        `env:"TELEGRAM_ADMIN_CHAT_ID,required"`
    Timeout     time.Duration `env:"TELEGRAM_TIMEOUT" default:"10s"`
    RetryCount  int           `env:"TELEGRAM_RETRY_COUNT" default:"3"`
    
    // Пороги для отправки алертов
    MinSeverity int     `env:"TELEGRAM_MIN_SEVERITY" default:"3"`  // 1-5
    MinScore    float64 `env:"TELEGRAM_MIN_ML_SCORE" default:"0.6"`
}
```

### 7.2. Формат сообщения

```
🚨 ОБНАРУЖЕНА АНОМАЛИЯ

Тип: Сканирование портов
Серьёзность: 🔴 Высокая (4/5)
Агент: router-office-1
Время: 15.01.2024 12:05:00

📊 Метрики:
• Пакетов: 5 000
• Уникальных портов: 150
• Оценка ML: 0.72

🎯 Подозрительные источники:
• 192.168.1.100 → порты: 22,80,443,3389

🔗 Подробности:
https://monitor.local/incidents/uuid-here

[Расследовать] [Ложное срабатывание]  ← inline-кнопки
```

### 7.3. Обработка retry и ошибок

```go
func (s *NotificationService) SendTelegram(ctx context.Context, incident *domain.Incident) error {
    if incident.Severity < s.config.MinSeverity || incident.MLScore < s.config.MinScore {
        return nil  // Не отправляем малозначимые алерты
    }
    
    message := buildTelegramMessage(incident)
    inlineKeyboard := buildIncidentActions(incident.ID)
    
    for attempt := 1; attempt <= s.config.RetryCount; attempt++ {
        err := s.telegramAPI.SendMessageWithKeyboard(
            s.config.AdminChatID, 
            message, 
            inlineKeyboard,
        )
        if err == nil {
            // Успех — записываем в БД
            s.alertRepo.RecordSent(ctx, incident.ID, "telegram", s.config.AdminChatID)
            return nil
        }
        
        // Логирование ошибки
        s.logger.Warn("telegram send failed", 
            zap.Int("attempt", attempt), 
            zap.Error(err))
        
        // Exponential backoff перед следующей попыткой
        if attempt < s.config.RetryCount {
            select {
            case <-time.After(time.Duration(1<<attempt) * time.Second):
            case <-ctx.Done():
                return ctx.Err()
            }
        }
    }
    
    // Все попытки исчерпаны
    s.alertRepo.RecordFailed(ctx, incident.ID, "telegram", "max retries exceeded")
    return ErrNotificationFailed
}
```

---

## 8. Docker Compose конфигурация

```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build: 
      context: .
      dockerfile: cmd/server/Dockerfile
    container_name: nm-backend
    ports:
      - "8080:8080"
    environment:
      - APP_ENV=production
      - APP_PORT=8080
      
      # PostgreSQL
      - DB_POSTGRES_HOST=postgres
      - DB_POSTGRES_PORT=5432
      - DB_POSTGRES_USER=nm_user
      - DB_POSTGRES_PASSWORD=${DB_PASSWORD}
      - DB_POSTGRES_DB=network_monitor
      
      # ClickHouse
      - DB_CLICKHOUSE_HOST=clickhouse
      - DB_CLICKHOUSE_PORT=8123
      - DB_CLICKHOUSE_USER=default
      - DB_CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD}
      
      # ML Service
      - ML_SERVICE_URL=http://ml-service:5000
      - ML_TIMEOUT=30s
      
      # JWT
      - JWT_SECRET=${JWT_SECRET}
      - JWT_EXPIRATION=24h
      
      # Telegram
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
      - TELEGRAM_ADMIN_CHAT_ID=${TELEGRAM_ADMIN_CHAT_ID}
      
      # Initial admin (только при первом запуске!)
      - INIT_ADMIN_LOGIN=admin
      - INIT_ADMIN_PASSWORD=${INIT_ADMIN_PASSWORD}
      
    depends_on:
      postgres:
        condition: service_healthy
      clickhouse:
        condition: service_healthy
      ml-service:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/healthz"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped
    networks:
      - nm-network

  postgres:
    image: postgres:15-alpine
    container_name: nm-postgres
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=nm_user
      - POSTGRES_PASSWORD=${DB_PASSWORD}
      - POSTGRES_DB=network_monitor
    volumes:
      - postgres_/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nm_user -d network_monitor"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - nm-network

  clickhouse:
    image: clickhouse/clickhouse-server:23.3-alpine
    container_name: nm-clickhouse
    ports:
      - "8123:8123"   # HTTP
      - "9000:9000"   # Native
    environment:
      - CLICKHOUSE_USER=default
      - CLICKHOUSE_PASSWORD=${CLICKHOUSE_PASSWORD}
    volumes:
      - clickhouse_/var/lib/clickhouse
      - ./clickhouse/config.xml:/etc/clickhouse-server/config.xml:ro
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8123/ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - nm-network

  ml-service:
    build:
      context: ./ml-service
      dockerfile: Dockerfile
    container_name: nm-ml
    ports:
      - "5000:5000"
    environment:
      - MODEL_PATH=/models/anomaly_model.pkl
      - SCALER_PATH=/models/scaler.pkl
      - API_PORT=5000
    volumes:
      - ./ml-service/models:/models:ro
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:5000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - nm-network

  # Опционально: фронтенд
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: nm-frontend
    ports:
      - "3000:80"
    environment:
      - REACT_APP_API_URL=http://localhost:8080/api
    depends_on:
      - backend
    networks:
      - nm-network

volumes:
  postgres_
  clickhouse_data:

networks:
  nm-network:
    driver: bridge
```

---

## 9. Переменные окружения (.env.example)

```bash
# === Базовые ===
APP_ENV=production
APP_PORT=8080

# === Базы данных ===
DB_PASSWORD=your_secure_postgres_password
CLICKHOUSE_PASSWORD=your_secure_clickhouse_password

# === JWT ===
JWT_SECRET=your_very_long_jwt_secret_key_min_32_chars
JWT_EXPIRATION=24h

# === Telegram ===
TELEGRAM_BOT_TOKEN=123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
TELEGRAM_ADMIN_CHAT_ID=123456789
TELEGRAM_MIN_SEVERITY=3
TELEGRAM_MIN_ML_SCORE=0.6

# === Initial admin (только при первом запуске!) ===
INIT_ADMIN_LOGIN=admin
INIT_ADMIN_PASSWORD=ChangeMe123!

# === ML Service ===
ML_SERVICE_URL=http://ml-service:5000
ML_TIMEOUT=30s
```

---

## 10. Миграции (Goose)

### 10.1. Структура папки

```
internal/repository/postgres/migrations/
├── 00001_init_schema.up.sql
├── 00001_init_schema.down.sql
├── 00002_add_audit_log.up.sql
├── 00002_add_audit_log.down.sql
└── ...
```

### 00001_init_schema.up.sql
```sql
-- +goose Up
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    login VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) CHECK (role IN ('admin', 'viewer')) DEFAULT 'viewer',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- agents
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    token_hash CHAR(64) UNIQUE NOT NULL,
    last_seen TIMESTAMPTZ,
    status VARCHAR(20) CHECK (status IN ('active', 'inactive')) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- incidents
CREATE TABLE incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    threat_type VARCHAR(50) CHECK (threat_type IN ('ddos', 'port_scan', 'anomaly', 'other')),
    severity INTEGER CHECK (severity BETWEEN 1 AND 5),
    status VARCHAR(30) CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive')) DEFAULT 'new',
    ml_score FLOAT,
    details JSONB,
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id)
);

-- alerts
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES incidents(id) ON DELETE CASCADE,
    channel VARCHAR(50) DEFAULT 'telegram',
    chat_id VARCHAR(100),
    sent_at TIMESTAMPTZ,
    status VARCHAR(20) CHECK (status IN ('sent', 'failed', 'retrying')),
    error_message TEXT
);

-- Индексы
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_created ON incidents(created_at DESC);
CREATE INDEX idx_agents_token ON agents(token_hash);

-- +goose Down
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS incidents;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS users;
DROP EXTENSION IF EXISTS "uuid-ossp";
```

### 10.2. Запуск миграций при старте

```go
// cmd/server/main.go
func runMigrations(cfg config.Config) error {
    db, err := pgx.Connect(context.Background(), cfg.Postgres.DSN())
    if err != nil {
        return fmt.Errorf("connect to postgres: %w", err)
    }
    defer db.Close(context.Background())
    
    if err := goose.SetDialect("postgres"); err != nil {
        return err
    }
    
    // Применяем все миграции из embedded FS
    if err := goose.Up(db.Pool().Conn(), "internal/repository/postgres/migrations"); err != nil {
        return fmt.Errorf("run migrations: %w", err)
    }
    
    return nil
}
```

---

## 11. Обработка ошибок и отказоустойчивость

### 11.1. Circuit Breaker для ML-сервиса

```go
type CircuitBreaker struct {
    mu           sync.RWMutex
    failures     int
    lastFailure  time.Time
    state        CBState  // closed, open, half-open
    threshold    int
    timeout      time.Duration
}

func (cb *CircuitBreaker) Call(fn func() error) error {
    if cb.getState() == "open" {
        if time.Since(cb.lastFailure) > cb.timeout {
            cb.setState("half-open")
        } else {
            return ErrCircuitOpen
        }
    }
    
    err := fn()
    if err != nil {
        cb.onFailure()
        return err
    }
    
    cb.onSuccess()
    return nil
}
```

### 11.2. Graceful Shutdown

```go
// cmd/server/main.go
func main() {
    // ... инициализация ...
    
    srv := &http.Server{
        Addr:    ":" + cfg.App.Port,
        Handler: router,
    }
    
    // Graceful shutdown
    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
    
    go func() {
        <-stop
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        logger.Info("shutting down...")
        srv.Shutdown(ctx)
        // Закрыть соединения с БД, очистить ресурсы
    }()
    
    if err := srv.ListenAndServe(); err != http.ErrServerClosed {
        logger.Fatal("server error", zap.Error(err))
    }
}
```

---

## 12. Чек-лист для LLM-генерации кода

При передаче этого ТЗ в LLM для генерации кода, используйте следующие промпты:

```
1. "Создай структуру проекта Go с Clean Architecture по спецификации из раздела 2.2"

2. "Реализуй domain-модели для User, Agent, Incident, NetworkLog по схемам из раздела 3"

3. "Напиши PostgreSQL repository с использованием pgx и интерфейсами из internal/repository"

4. "Реализуй ClickHouse repository для BatchInsert и аналитических запросов"

5. "Создай HTTP-обработчики для эндпоинтов из раздела 4 с использованием gorilla/mux"

6. "Реализуй middleware для JWT-аутентификации и валидации токенов агентов"

7. "Напиши сервис обработки ZIP-архивов с валидацией JSON-схемы по алгоритму из раздела 5"

8. "Реализуй HTTP-клиент к ML-сервису с circuit breaker по спецификации раздела 6"

9. "Добавь отправку уведомлений в Telegram с retry-логикой из раздела 7"

10. "Создай goose-миграции для PostgreSQL по схемам из раздела 10"
```

---

## 13. Примечания по использованию вашего ML-модуля

Ваш существующий Python-код (`main.py`, `anomaly_detector.py`) уже содержит:
- ✅ Извлечение признаков из пакетов
- ✅ Агрегацию по временным окнам
- ✅ Обучение и инференс Isolation Forest
- ✅ Классификацию типов угроз

**Что нужно сделать:**

1. **Обернуть в HTTP-API** (FastAPI/Flask):
   ```python
   # ml-service/app.py
   @app.post("/analyze")
   async def analyze(req: AnalyzeRequest):
       features = extract_features(req.raw_logs)  # ваш существующий код
       score = model.predict([features])[0]       # ваш существующий код
       threat_type = classify(score, features)    # ваш существующий код
       return AnalyzeResponse(...)
   ```

2. **Экспортировать модель** после обучения:
   ```python
   # В конце режима train
   joblib.dump({'model': model, 'scaler': scaler}, '/models/anomaly_model.pkl')
   ```

3. **Не менять логику признаков** — ваш формат `FeatureVector` в разделе 6.1 должен точно соответствовать тому, что ожидает ваша модель.

4. **Добавить health-check эндпоинт**:
   ```python
   @app.get("/health")
   def health():
       return {"status": "ok", "model_loaded": model is not None}
   ```

---

> **Итог**: Это ТЗ содержит всю необходимую информацию для генерации кода: архитектуру, схемы БД, API-контракты, алгоритмы обработки, конфигурацию инфраструктуры. Передавайте разделы по одному в LLM для пошаговой генерации.