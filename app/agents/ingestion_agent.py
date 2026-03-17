"""
Agente de Procesamiento/Ingestión de Registros.

Responsabilidades:
- Recibir y validar registros de acceso en bruto
- Realizar feature engineering
- Ejecutar el modelo de detección de anomalías
- Comunicar los resultados al Agente de Decisión
"""
import os
import numpy as np
import pandas as pd
import joblib
from typing import List, Dict, Any
from pydantic import BaseModel


class LogRecord(BaseModel):
    timestamp: str
    ip_address: str
    user: str
    method: str
    endpoint: str
    status_code: int
    response_bytes: int
    requests_per_minute: int
    user_agent: str


class IngestionResult(BaseModel):
    record_index: int
    original_record: Dict[str, Any]
    anomaly_score: float  # Score del Isolation Forest (más negativo = más anómalo)
    is_anomaly: bool
    feature_flags: Dict[str, bool]  # Flags de características sospechosas


class IngestionAgent:
    """
    Agente 1: Procesamiento e Ingestión de Registros.
    Carga el modelo entrenado y procesa lotes de registros.
    """

    def __init__(self):
        model_dir = os.path.join(os.path.dirname(__file__), "..", "models")
        model_path = os.path.join(model_dir, "isolation_forest.joblib")
        fe_path = os.path.join(model_dir, "feature_engineer.joblib")

        if not os.path.exists(model_path) or not os.path.exists(fe_path):
            raise FileNotFoundError(
                "Modelos no encontrados. Ejecute primero: python -m app.train_model"
            )

        self.model = joblib.load(model_path)
        self.feature_engineer = joblib.load(fe_path)
        print("[IngestionAgent] Modelo y feature engineer cargados correctamente.")

    def process_batch(self, records: List[LogRecord]) -> List[IngestionResult]:
        """
        Procesa un lote de registros y retorna los resultados de análisis.
        Este es el punto de comunicación hacia el Agente de Decisión.
        """
        if not records:
            return []

        # Convertir a DataFrame
        df = pd.DataFrame([r.model_dump() for r in records])

        # Feature engineering (sin re-ajustar el scaler/encoders)
        features = self.feature_engineer.transform(df, fit=False)

        # Obtener scores de anomalía (decision_function)
        anomaly_scores = self.model.decision_function(features.values)

        # Predicciones (-1 = anomalía, 1 = normal)
        predictions = self.model.predict(features.values)

        results = []
        for i, record in enumerate(records):
            # Extraer flags de features sospechosas
            feature_flags = {
                "is_night_access": bool(features.iloc[i].get("is_night", 0)),
                "is_error_status": bool(features.iloc[i].get("is_error_status", 0)),
                "is_extreme_bytes": bool(features.iloc[i].get("is_extreme_bytes", 0)),
                "is_high_rpm": bool(features.iloc[i].get("is_high_rpm", 0)),
                "suspicious_endpoint": bool(features.iloc[i].get("suspicious_endpoint", 0)),
                "suspicious_agent": bool(features.iloc[i].get("suspicious_agent", 0)),
            }

            results.append(IngestionResult(
                record_index=i,
                original_record=record.model_dump(),
                anomaly_score=float(anomaly_scores[i]),
                is_anomaly=bool(predictions[i] == -1),
                feature_flags=feature_flags,
            ))

        anomaly_count = sum(1 for r in results if r.is_anomaly)
        print(f"[IngestionAgent] Procesados {len(results)} registros. "
              f"Anomalías detectadas: {anomaly_count}")

        return results
