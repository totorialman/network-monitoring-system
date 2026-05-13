from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_ORDER = [
    "packet_count", "pps", "unique_src_ips", "unique_dst_ips", "unique_dst_ports", "unique_src_ports",
    "proto_tcp", "proto_udp", "proto_icmp", "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst",
    "avg_length", "min_length", "max_length", "avg_ttl", "dst_port_entropy", "icmp_count", "connection_spread",
]

MODEL_PATH = Path(os.getenv("MODEL_PATH", "/models/anomaly_model.pkl"))


class FeatureVector(BaseModel):
    packet_count: int = Field(ge=0)
    pps: float = Field(ge=0)
    unique_src_ips: int = Field(ge=0)
    unique_dst_ips: int = Field(ge=0)
    unique_dst_ports: int = Field(ge=0)
    unique_src_ports: int = Field(ge=0)
    proto_tcp: int = Field(ge=0)
    proto_udp: int = Field(ge=0)
    proto_icmp: int = Field(ge=0)
    tcp_syn: int = Field(ge=0)
    tcp_ack: int = Field(ge=0)
    tcp_fin: int = Field(ge=0)
    tcp_rst: int = Field(ge=0)
    avg_length: float = Field(ge=0)
    min_length: int = Field(ge=0)
    max_length: int = Field(ge=0)
    avg_ttl: float = Field(ge=0)
    dst_port_entropy: float = Field(ge=0)
    icmp_count: int = Field(ge=0)
    connection_spread: float = Field(ge=0)


class AnalyzeRequest(BaseModel):
    agent_id: str
    window_seconds: float
    start_time: str
    end_time: str
    features: FeatureVector


class AnalyzeResponse(BaseModel):
    is_anomaly: bool
    anomaly_score: float
    confidence: float
    threat_type: str
    top_suspicious_ips: List[str] = []
    top_targeted_ports: List[int] = []
    recommendations: List[str] = []


app = FastAPI(title="Network Monitor ML Service", version="1.0.0")
model_bundle = None


def _vector(features: FeatureVector) -> np.ndarray:
    return np.array([[float(getattr(features, name)) for name in FEATURE_ORDER]], dtype=float)


def _train_default_model() -> dict:
    rng = np.random.default_rng(42)
    normal = np.column_stack([
        rng.integers(50, 2000, 1500),       # packet_count
        rng.uniform(1, 150, 1500),          # pps
        rng.integers(1, 10, 1500),          # unique_src_ips
        rng.integers(1, 50, 1500),          # unique_dst_ips
        rng.integers(1, 40, 1500),          # unique_dst_ports
        rng.integers(1, 800, 1500),         # unique_src_ports
        rng.integers(20, 1800, 1500),
        rng.integers(0, 400, 1500),
        rng.integers(0, 50, 1500),
        rng.integers(0, 300, 1500),
        rng.integers(10, 1800, 1500),
        rng.integers(0, 80, 1500),
        rng.integers(0, 80, 1500),
        rng.uniform(60, 900, 1500),
        rng.integers(40, 120, 1500),
        rng.integers(80, 1500, 1500),
        rng.uniform(32, 128, 1500),
        rng.uniform(0.0, 0.75, 1500),
        rng.integers(0, 30, 1500),
        rng.uniform(0.001, 0.25, 1500),
    ])
    scaler = StandardScaler()
    x = scaler.fit_transform(normal)
    model = IsolationForest(n_estimators=150, contamination=0.05, random_state=42)
    model.fit(x)
    return {"model": model, "scaler": scaler}


def load_model() -> dict:
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    bundle = _train_default_model()
    joblib.dump(bundle, MODEL_PATH)
    return bundle


@app.on_event("startup")
def startup() -> None:
    global model_bundle
    model_bundle = load_model()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model_loaded": model_bundle is not None}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    x = _vector(req.features)
    scaler: StandardScaler = model_bundle["scaler"]
    model: IsolationForest = model_bundle["model"]
    xs = scaler.transform(x)
    prediction = int(model.predict(xs)[0])
    raw_score = float(-model.decision_function(xs)[0])
    heuristic_score = heuristic_anomaly_score(req.features)
    score = max(raw_score, heuristic_score)
    is_anomaly = prediction == -1 or score >= 0.60
    threat = classify_threat(req.features, is_anomaly)
    recommendations = recommendations_for(threat, req.features) if is_anomaly else []
    return AnalyzeResponse(
        is_anomaly=is_anomaly,
        anomaly_score=round(float(min(max(score, 0.0), 1.0)), 4),
        confidence=round(float(min(max(abs(score), 0.0), 1.0)), 4),
        threat_type=threat,
        top_suspicious_ips=[],
        top_targeted_ports=[],
        recommendations=recommendations,
    )


def heuristic_anomaly_score(f: FeatureVector) -> float:
    score = 0.0
    if f.pps > 1000:
        score += 0.45
    if f.unique_dst_ports > 100:
        score += 0.35
    if f.tcp_syn > max(f.tcp_ack * 3, 50):
        score += 0.25
    if f.connection_spread > 0.25:
        score += 0.20
    if f.dst_port_entropy > 0.85 and f.unique_dst_ports > 50:
        score += 0.20
    return min(score, 1.0)


def classify_threat(f: FeatureVector, is_anomaly: bool) -> str:
    if not is_anomaly:
        return "other"
    if f.pps > 1000 and f.unique_dst_ips <= 5:
        return "ddos"
    if f.unique_dst_ports > 100 or f.connection_spread > 0.25:
        return "port_scan"
    return "anomaly"


def recommendations_for(threat: str, f: FeatureVector) -> List[str]:
    base = ["Проверьте источник трафика и сопоставьте событие с журналами сетевого оборудования."]
    if threat == "port_scan":
        base.append("Ограничьте источник на perimeter firewall и проверьте попытки доступа к административным портам.")
    if threat == "ddos":
        base.append("Включите rate limiting, проверьте upstream-защиту и временно заблокируйте наиболее активные источники.")
    if f.tcp_syn > f.tcp_ack * 3:
        base.append("Высокая доля SYN может указывать на SYN flood или активное сканирование.")
    return base
