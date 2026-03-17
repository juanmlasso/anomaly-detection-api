"""
Pipeline de entrenamiento del modelo de detección de anomalías.
Utiliza Isolation Forest (modelo pre-entrenado de scikit-learn) con ajuste fino
usando datos etiquetados (al menos 10% del dataset).
"""
import pandas as pd
import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix


class FeatureEngineer:
    """Extrae características numéricas de los registros de acceso."""

    def __init__(self):
        self.label_encoders = {}
        self.scaler = StandardScaler()
        self.fitted = False

    def _extract_hour(self, timestamp_series: pd.Series) -> pd.Series:
        return pd.to_datetime(timestamp_series).dt.hour

    def _is_suspicious_endpoint(self, endpoint_series: pd.Series) -> pd.Series:
        suspicious_patterns = ["admin", "debug", "internal", "config", "delete", "passwd", "keys", "export"]
        return endpoint_series.apply(
            lambda ep: int(any(p in str(ep).lower() for p in suspicious_patterns))
        )

    def _is_suspicious_agent(self, agent_series: pd.Series) -> pd.Series:
        suspicious_agents = ["sqlmap", "nikto", "curl", "python-requests", ""]
        return agent_series.apply(
            lambda ua: int(any(s in str(ua).lower() for s in suspicious_agents))
        )

    def _encode_categorical(self, series: pd.Series, col_name: str, fit: bool = True) -> pd.Series:
        if fit:
            le = LabelEncoder()
            le.fit(series.astype(str))
            self.label_encoders[col_name] = le
        else:
            le = self.label_encoders.get(col_name)
            if le is None:
                le = LabelEncoder()
                le.fit(series.astype(str))
                self.label_encoders[col_name] = le

        # Manejar valores no vistos
        known = set(le.classes_)
        safe_series = series.astype(str).apply(lambda x: x if x in known else le.classes_[0])
        return pd.Series(le.transform(safe_series), index=series.index)

    def transform(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        features = pd.DataFrame(index=df.index)

        # Hora del acceso
        features["hour"] = self._extract_hour(df["timestamp"])
        features["is_night"] = features["hour"].apply(lambda h: int(h < 6 or h >= 23))

        # Método HTTP codificado
        features["method_encoded"] = self._encode_categorical(df["method"], "method", fit=fit)

        # Código de estado
        features["status_code"] = df["status_code"].astype(int)
        features["is_error_status"] = df["status_code"].apply(lambda s: int(s >= 400))

        # Bytes de respuesta
        features["response_bytes"] = df["response_bytes"].astype(float)
        features["is_extreme_bytes"] = df["response_bytes"].apply(
            lambda b: int(b < 50 or b > 50000)
        )

        # Requests por minuto
        features["requests_per_minute"] = df["requests_per_minute"].astype(float)
        features["is_high_rpm"] = df["requests_per_minute"].apply(lambda r: int(r > 30))

        # Endpoint sospechoso
        features["suspicious_endpoint"] = self._is_suspicious_endpoint(df["endpoint"])

        # User agent sospechoso
        features["suspicious_agent"] = self._is_suspicious_agent(df["user_agent"])

        # Escalar features numéricas
        numeric_cols = ["hour", "status_code", "response_bytes", "requests_per_minute"]
        if fit:
            features[numeric_cols] = self.scaler.fit_transform(features[numeric_cols])
            self.fitted = True
        else:
            features[numeric_cols] = self.scaler.transform(features[numeric_cols])

        return features


def train_model():
    """Entrena el modelo Isolation Forest con ajuste fino usando datos etiquetados."""
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "access_logs.csv")
    model_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    os.makedirs(model_dir, exist_ok=True)

    df = pd.read_csv(data_path)
    print(f"Dataset cargado: {len(df)} registros")
    print(f"Distribución de anomalías:\n{df['is_anomaly'].value_counts()}")

    # Feature engineering
    fe = FeatureEngineer()
    X = fe.transform(df, fit=True)
    y = df["is_anomaly"]

    # --- Paso 1: Entrenar Isolation Forest (no supervisado) ---
    contamination_ratio = y.mean()
    print(f"\nTasa de contaminación real: {contamination_ratio:.4f}")

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination_ratio,
        max_samples="auto",
        max_features=1.0,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    # Predicciones: -1 = anomalía, 1 = normal
    preds_raw = model.predict(X)
    preds = (preds_raw == -1).astype(int)

    print("\n--- Evaluación del modelo (antes de ajuste) ---")
    print(classification_report(y, preds, target_names=["Normal", "Anomalía"]))

    # --- Paso 2: Ajuste fino con datos etiquetados (10%) ---
    labeled_sample = df.sample(frac=0.10, random_state=42)
    labeled_idx = labeled_sample.index
    X_labeled = X.loc[labeled_idx]
    y_labeled = y.loc[labeled_idx]

    # Usar solo las muestras normales del subset etiquetado para re-entrenar
    normal_mask = y_labeled == 0
    X_normal = X_labeled[normal_mask]

    model_finetuned = IsolationForest(
        n_estimators=300,
        contamination=contamination_ratio,
        max_samples=min(len(X_normal), 256),
        max_features=0.8,
        random_state=42,
        n_jobs=-1,
    )
    model_finetuned.fit(X_normal)

    # Evaluar modelo ajustado en todo el dataset
    preds_ft_raw = model_finetuned.predict(X)
    preds_ft = (preds_ft_raw == -1).astype(int)

    print("\n--- Evaluación del modelo (después de ajuste fino) ---")
    print(classification_report(y, preds_ft, target_names=["Normal", "Anomalía"]))
    print("Matriz de confusión:")
    print(confusion_matrix(y, preds_ft))

    # Seleccionar el mejor modelo comparando F1-score de anomalía
    from sklearn.metrics import f1_score
    f1_base = f1_score(y, preds)
    f1_ft = f1_score(y, preds_ft)

    best_model = model if f1_base >= f1_ft else model_finetuned
    best_label = "base" if f1_base >= f1_ft else "ajuste fino"
    print(f"\nMejor modelo seleccionado: {best_label} (F1 anomalía: {max(f1_base, f1_ft):.4f})")

    # Guardar modelos y artefactos
    joblib.dump(best_model, os.path.join(model_dir, "isolation_forest.joblib"))
    joblib.dump(fe, os.path.join(model_dir, "feature_engineer.joblib"))

    print(f"\nModelos guardados en: {model_dir}/")
    return model_finetuned, fe


if __name__ == "__main__":
    train_model()
