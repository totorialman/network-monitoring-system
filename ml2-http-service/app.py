"""
HTTP-сервис для детекции аномалий, основанный на коде из ml2/.

Принимает POST /analyze с массивом сырых сетевых логов (как в traffic.json),
агрегирует их через TimeWindowAggregator (как в ml2/aggregation.py),
запускает предсказание через Isolation Forest (как в ml2/anomaly_detector.py),
классифицирует тип угрозы и возвращает результат.

Модель загружается из /models/anomaly_model.pkl (обучена через ml2/main.py).
"""

import os
import time
from collections import defaultdict
from pathlib import Path
from typing import List, Optional

import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ============================================================
# 18 признаков из TimeWindowAggregator (ml2/aggregation.py)
# ============================================================
FEATURE_ORDER = [
    "packet_count",
    "duration",
    "packets_per_second",
    "unique_src_mac",
    "unique_dst_mac",
    "unique_src_ip",
    "unique_dst_ip",
    "unique_src_port",
    "unique_dst_port",
    "avg_length",
    "min_length",
    "max_length",
    "avg_ttl",
    "unique_tcp_flags",
    "icmp_count",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
]

MODEL_PATH = Path(os.getenv("MODEL_PATH", "/models/anomaly_model.pkl"))


# ============================================================
# Модели данных (Pydantic)
# ============================================================

class RawLog(BaseModel):
    """Один сырой сетевой лог (как в traffic.json)."""
    timestamp: float
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    vlan: Optional[int] = None
    eth_type: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    proto: Optional[int] = None
    ttl: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    length: int = 0


class AnalyzeRequest(BaseModel):
    """Запрос с сырыми логами для ML-анализа."""
    agent_id: str
    window_seconds: float = 300.0
    start_time: str = ""
    end_time: str = ""
    logs: List[RawLog]


class AnalyzeResponse(BaseModel):
    """Результат ML-анализа."""
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    threat_type: str
    detection_method: str = "none"
    recommendations: List[str] = []


# ============================================================
# Агрегация по временному окну (как в ml2/aggregation.py)
# ============================================================

def aggregate_logs(logs: List[RawLog], window_size: float) -> tuple:
    """
    Агрегация массива сырых логов в один вектор признаков.
    Аналог TimeWindowAggregator._aggregate_window() из ml2/.
    """
    if not logs:
        return {}, 0, 0

    packet_count = len(logs)

    # Собираем временные метки
    timestamps = [l.timestamp for l in logs if l.timestamp]
    if timestamps:
        window_start = min(timestamps)
        window_end = max(timestamps)
    else:
        window_start = 0
        window_end = 0

    duration = max(window_end - window_start, 0.001)

    # Уникальные значения
    src_macs = set()
    dst_macs = set()
    src_ips = set()
    dst_ips = set()
    src_ports = set()
    dst_ports = set()
    tcp_flags_set = set()

    # Счётчики протоколов
    proto_counts = defaultdict(int)

    # Статистики длины
    lengths = []
    ttls = []
    icmp_count = 0

    for l in logs:
        if l.src_mac:
            src_macs.add(l.src_mac)
        if l.dst_mac:
            dst_macs.add(l.dst_mac)
        if l.src_ip:
            src_ips.add(l.src_ip)
        if l.dst_ip:
            dst_ips.add(l.dst_ip)
        if l.src_port is not None and l.src_port > 0:
            src_ports.add(l.src_port)
        if l.dst_port is not None and l.dst_port > 0:
            dst_ports.add(l.dst_port)
        if l.proto is not None:
            proto_counts[l.proto] += 1
        if l.tcp_flags:
            tcp_flags_set.add(l.tcp_flags)
        lengths.append(l.length)
        if l.ttl is not None and l.ttl > 0:
            ttls.append(l.ttl)
        if l.icmp_type is not None:
            icmp_count += 1

    avg_length = sum(lengths) / len(lengths) if lengths else 0
    min_length = min(lengths) if lengths else 0
    max_length = max(lengths) if lengths else 0
    avg_ttl = sum(ttls) / len(ttls) if ttls else 0

    features = {
        "packet_count": packet_count,
        "duration": duration,
        "packets_per_second": packet_count / duration,
        "unique_src_mac": len(src_macs),
        "unique_dst_mac": len(dst_macs),
        "unique_src_ip": len(src_ips),
        "unique_dst_ip": len(dst_ips),
        "unique_src_port": len(src_ports),
        "unique_dst_port": len(dst_ports),
        "avg_length": avg_length,
        "min_length": min_length,
        "max_length": max_length,
        "avg_ttl": avg_ttl,
        "unique_tcp_flags": len(tcp_flags_set),
        "icmp_count": icmp_count,
        "proto_tcp": proto_counts.get(6, 0),
        "proto_udp": proto_counts.get(17, 0),
        "proto_icmp": proto_counts.get(1, 0),
    }

    return features, window_start, window_end


# ============================================================
# Классификация угроз (на основе эвристик)
# ============================================================

def classify_threat(features: dict, anomaly_score: float) -> str:
    """
    Определение типа угрозы на основе агрегированных признаков.
    Аналог того, что было в старом ml-service, но на коде из ml2/.
    """
    pps = features.get("packets_per_second", 0)
    unique_dst_ports = features.get("unique_dst_port", 0)
    unique_dst_ip = features.get("unique_dst_ip", 0)
    unique_tcp_flags = features.get("unique_tcp_flags", 0)
    tcp_syn = features.get("proto_tcp", 0)  # приближение

    if pps > 1000 and unique_dst_ip <= 5:
        return "ddos"
    if unique_dst_ports > 50:
        return "port_scan"
    return "anomaly"


def generate_recommendations(threat_type: str, features: dict) -> List[str]:
    """Генерация рекомендаций для администратора."""
    if threat_type == "port_scan":
        return [
            "Зафиксировано сканирование портов. Проверьте источник в журналах сетевого оборудования.",
            "Рекомендуется ограничить доступ с подозрительного IP на межсетевом экране (периметр).",
            "Особое внимание — административные порты (SSH, RDP, веб-интерфейсы).",
            "При повторении инцидента — временная блокировка источника до выяснения.",
        ]
    if threat_type == "ddos":
        return [
            "Обнаружена DDoS-атака. Включите rate limiting на upstream-оборудовании.",
            "Проверьте upstream-защиту (ISP DDoS mitigation) и свяжитесь с провайдером.",
            "Временно заблокируйте наиболее активные источники атаки.",
            "Рассмотрите перенаправление трафика через scrubbing-центр при эскалации.",
        ]
    if threat_type == "anomaly":
        return [
            "Выявлена сетевая аномалия, не классифицированная как известный тип атаки.",
            "Рекомендуется провести ручной анализ трафика источника и корреляцию с другими событиями.",
            "Проверьте легитимность соединений и при необходимости создайте правило фильтрации.",
        ]
    # traffic / other
    return [
        "Зафиксирован необычный сетевой трафик. Проверьте легитимность источника.",
        "Оцените характер соединений и сопоставьте с нормальным профилем сети.",
        "При отсутствии признаков атаки — продолжайте мониторинг в обычном режиме.",
    ]


# ============================================================
# FastAPI приложение
# ============================================================

app = FastAPI(title="Network Monitor ML2 Service", version="2.0.0")
model_bundle = None


def _vector_from_features(features: dict) -> np.ndarray:
    """Конвертация словаря признаков в numpy-массив в порядке FEATURE_ORDER."""
    return np.array([[float(features.get(name, 0)) for name in FEATURE_ORDER]], dtype=float)


def load_model() -> Optional[dict]:
    """Загрузка предобученной модели из файла."""
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    if MODEL_PATH.exists():
        try:
            data = joblib.load(MODEL_PATH)
            # Поддержка обоих форматов: ml2 (pickle) и старый (joblib)
            if isinstance(data, dict) and "model" in data and "scaler" in data:
                return data
            # Если это объект AnomalyDetector из ml2
            elif hasattr(data, "model") and hasattr(data, "scaler"):
                return {"model": data.model, "scaler": data.scaler}
        except Exception:
            pass
    return None


@app.on_event("startup")
def startup() -> None:
    global model_bundle
    model_bundle = load_model()
    if model_bundle:
        print(f"Модель загружена из {MODEL_PATH}")
    else:
        print(f"Модель не найдена в {MODEL_PATH}. Сервис будет работать, но ML-анализ недоступен.")


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "model_loaded": model_bundle is not None,
        "model_path": str(MODEL_PATH),
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """
    Анализ массива сырых сетевых логов.
    
    1. Агрегация в 18 признаков (как в ml2/TimeWindowAggregator)
    2. Предсказание через Isolation Forest
    3. Классификация типа угрозы
    4. Генерация рекомендаций
    """
    if not req.logs:
        return AnalyzeResponse(
            is_anomaly=False,
            anomaly_score=0.0,
            confidence=0.0,
            threat_type="other",
            detection_method="none",
            recommendations=[],
        )

    # 1. Агрегация
    features, window_start, window_end = aggregate_logs(req.logs, req.window_seconds)

    # 2. ML-предсказание
    is_anomaly = False
    anomaly_score = 0.0
    confidence = 0.0
    detection_method = "none"

    if model_bundle:
        x = _vector_from_features(features)
        scaler: StandardScaler = model_bundle["scaler"]
        model: IsolationForest = model_bundle["model"]

        xs = scaler.transform(x)
        prediction = int(model.predict(xs)[0])
        raw_score = float(-model.decision_function(xs)[0])

        is_anomaly = prediction == -1
        anomaly_score = round(float(min(max(raw_score, 0.0), 1.0)), 4)
        confidence = round(float(min(max(abs(raw_score), 0.0), 1.0)), 4)
        if is_anomaly:
            detection_method = "ml"

    # 2.5 Hybrid detection: эвристики как fallback (работает всегда, даже без модели)
    if not is_anomaly or detection_method == "none":
        pps = features.get("packets_per_second", 0)
        unique_dst_ip = features.get("unique_dst_ip", 0)
        unique_dst_ports = features.get("unique_dst_port", 0)

        heuristic_ddos = pps > 1000 and unique_dst_ip <= 5
        heuristic_portscan = unique_dst_ports > 50

        if heuristic_ddos or heuristic_portscan:
            if not is_anomaly:
                is_anomaly = True
            detection_method = "heuristic"
            anomaly_score = 0.85
            if confidence < 0.9:
                confidence = 0.9

    # 3. Классификация угрозы
    threat_type = classify_threat(features, anomaly_score) if is_anomaly else "other"

    # 4. Рекомендации
    recommendations = generate_recommendations(threat_type, features) if is_anomaly else []

    return AnalyzeResponse(
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score,
        confidence=confidence,
        threat_type=threat_type,
        detection_method=detection_method,
        recommendations=recommendations,
    )
