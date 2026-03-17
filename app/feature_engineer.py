"""
Feature Engineering para registros de acceso.
Módulo separado para evitar problemas de serialización con joblib.
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler


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

        known = set(le.classes_)
        safe_series = series.astype(str).apply(lambda x: x if x in known else le.classes_[0])
        return pd.Series(le.transform(safe_series), index=series.index)

    def transform(self, df: pd.DataFrame, fit: bool = True) -> pd.DataFrame:
        features = pd.DataFrame(index=df.index)

        features["hour"] = self._extract_hour(df["timestamp"])
        features["is_night"] = features["hour"].apply(lambda h: int(h < 6 or h >= 23))
        features["method_encoded"] = self._encode_categorical(df["method"], "method", fit=fit)
        features["status_code"] = df["status_code"].astype(int)
        features["is_error_status"] = df["status_code"].apply(lambda s: int(s >= 400))
        features["response_bytes"] = df["response_bytes"].astype(float)
        features["is_extreme_bytes"] = df["response_bytes"].apply(
            lambda b: int(b < 50 or b > 50000)
        )
        features["requests_per_minute"] = df["requests_per_minute"].astype(float)
        features["is_high_rpm"] = df["requests_per_minute"].apply(lambda r: int(r > 30))
        features["suspicious_endpoint"] = self._is_suspicious_endpoint(df["endpoint"])
        features["suspicious_agent"] = self._is_suspicious_agent(df["user_agent"])

        numeric_cols = ["hour", "status_code", "response_bytes", "requests_per_minute"]
        if fit:
            features[numeric_cols] = self.scaler.fit_transform(features[numeric_cols])
            self.fitted = True
        else:
            features[numeric_cols] = self.scaler.transform(features[numeric_cols])

        return features
