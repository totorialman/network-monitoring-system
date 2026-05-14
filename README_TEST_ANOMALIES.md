# Примеры JSON для вызова аномалий

## Структура логов

Формат соответствует `traffic.json` (один объект на строку):

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

Обязательные поля: `timestamp`, `src_ip`, `dst_ip`, `proto`.

---

## 1. Port Scan (сканирование портов)

**Признак**: `unique_dst_ports > 100`

Механика: 1 атакующий IP перебирает 150+ портов на 1 целевом хосте.

```json
[
  {"timestamp": 1713623722.00, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 22, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.01, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 23, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.02, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 25, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.03, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 53, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.04, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.05, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 110, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.06, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 135, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.07, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 139, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.08, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 143, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.09, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 443, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.10, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 445, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.11, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 993, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.12, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 995, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.13, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 1433, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.14, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 1521, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.15, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 3306, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.16, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 3389, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.17, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 5432, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.18, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 5900, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.19, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 6379, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.20, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 8080, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.21, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 8443, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.22, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 9000, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.23, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 9090, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623722.24, "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 27017, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64}
]
```

**Архивировать как ZIP и отправить через** `curl -F "archive=@port_scan.zip" -H "Authorization: Bearer <token>" http://localhost:8080/api/agent/logs`

**Ожидаемый результат**:
- `unique_dst_ports = 25` (в реальном сценарии нужно > 100 портов для срабатывания правила)
- **Для срабатывания нужно 101+ порт** — дополнить массив до 101+ порта
- ML score ≥ 0.65, threat_type: `port_scan`, severity: 4-5

---

## 2. DDoS (SYN-флуд)

**Признак**: `packets_per_second > 1000` И `unique_dst_ip ≤ 5`

Механика: 50+ источников забивают 1 целевой IP SYN-пакетами с высокой частотой.

```json
[
  {"timestamp": 1713623000.000, "src_ip": "10.0.1.1", "dst_ip": "192.168.1.1", "src_port": 1024, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.001, "src_ip": "10.0.1.2", "dst_ip": "192.168.1.1", "src_port": 1025, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.002, "src_ip": "10.0.1.3", "dst_ip": "192.168.1.1", "src_port": 1026, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.003, "src_ip": "10.0.1.4", "dst_ip": "192.168.1.1", "src_port": 1027, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.004, "src_ip": "10.0.1.5", "dst_ip": "192.168.1.1", "src_port": 1028, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.005, "src_ip": "10.0.1.6", "dst_ip": "192.168.1.1", "src_port": 1029, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.006, "src_ip": "10.0.1.7", "dst_ip": "192.168.1.1", "src_port": 1030, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.007, "src_ip": "10.0.1.8", "dst_ip": "192.168.1.1", "src_port": 1031, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.008, "src_ip": "10.0.1.9", "dst_ip": "192.168.1.1", "src_port": 1032, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64},
  {"timestamp": 1713623000.009, "src_ip": "10.0.1.10", "dst_ip": "192.168.1.1", "src_port": 1033, "dst_port": 80, "proto": 6, "ttl": 64, "tcp_flags": "SYN", "length": 64}
]
```

**Архивировать как ZIP и отправить через** `curl -F "archive=@ddos.zip" -H "Authorization: Bearer <token>" http://localhost:8080/api/agent/logs`

**Ожидаемый результат**:
- 10 пакетов за 9 мс → `packets_per_second = 10 / 0.009 ≈ 1111` > 1000 ✅
- `unique_dst_ip = 1` ≤ 5 ✅
- **Для надёжного срабатывания** добавьте 5000+ записей с интервалом < 5 секунд
- ML score ≥ 0.85, threat_type: `ddos`, severity: 5

---

## 3. Generic Anomaly (аномальные TCP-флаги)

**Признак**: Isolation Forest score ≥ 0.65 без соответствия правилам port_scan/ddos

Механика: нестандартные комбинации TCP-флагов (SYN+FIN, FIN+RST, XMAS tree), меняющийся TTL.

```json
[
  {"timestamp": 1713624000.00, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 4444, "dst_port": 4444, "proto": 6, "ttl": 32, "tcp_flags": "SYN+FIN", "length": 128},
  {"timestamp": 1713624000.05, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 4444, "dst_port": 4445, "proto": 6, "ttl": 31, "tcp_flags": "FIN+RST", "length": 200},
  {"timestamp": 1713624000.10, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 4444, "dst_port": 4446, "proto": 6, "ttl": 29, "tcp_flags": "SYN+FIN+PSH", "length": 500},
  {"timestamp": 1713624000.15, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 4444, "dst_port": 4447, "proto": 6, "ttl": 28, "tcp_flags": "SYN+RST+FIN", "length": 64},
  {"timestamp": 1713624000.20, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 4444, "dst_port": 4448, "proto": 6, "ttl": 27, "tcp_flags": "FIN+PSH+URG", "length": 300},
  {"timestamp": 1713624000.25, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.100", "src_port": 4444, "dst_port": 4449, "proto": 6, "ttl": 26, "tcp_flags": "SYN+FIN", "length": 500},
  {"timestamp": 1713624000.30, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 4444, "dst_port": 4450, "proto": 6, "ttl": 25, "tcp_flags": "FIN+RST+PSH", "length": 64},
  {"timestamp": 1713624000.35, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99", "src_port": 4444, "dst_port": 4451, "proto": 6, "ttl": 24, "tcp_flags": "SYN+FIN+PSH+URG", "length": 1000}
]
```

**Архивировать как ZIP и отправить через** `curl -F "archive=@anomaly.zip" -H "Authorization: Bearer <token>" http://localhost:8080/api/agent/logs`

**Ожидаемый результат**:
- `packets_per_second ≈ 8 / 0.35 ≈ 23` < 1000 (не ddos)
- `unique_dst_ports = 8` < 100 (не port_scan)
- Но меняющийся TTL (32→24) + нестандартные TCP-флаги → Isolation Forest score ≥ 0.65
- threat_type: `anomaly`, severity: 3-4

---

## Отправка логов через curl

```bash
# 1. Создать JSON-файл (например, port_scan.json) с массивом логов

# 2. Заархивировать
zip port_scan.zip port_scan.json

# 3. Отправить на сервер
curl -X POST http://localhost:8080/api/agent/logs \
  -H "Authorization: Bearer <agent_token>" \
  -F "archive=@port_scan.zip"

# Ответ:
# {"batch_id":"...","records_received":25,"records_valid":25,"records_invalid":0,"processing_status":"queued"}