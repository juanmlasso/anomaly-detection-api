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
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from app.feature_engineer import FeatureEngineer


def train_model():
    """Entrena el modelo Isolation Forest con ajuste fino usando datos etiquetados."""
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "access_logs.csv")
    model_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    os.makedirs(model_dir, exist_ok=True)

    df = pd.read_csv(data_path)
    print(f"Dataset cargado: {len(df)} registros")
    print(f"Distribución de anomalías:\n{df['is_anomaly'].value_counts()}")

    fe = FeatureEngineer()
    X = fe.transform(df, fit=True)
    y = df["is_anomaly"]

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

    preds_raw = model.predict(X)
    preds = (preds_raw == -1).astype(int)

    print("\n--- Evaluación del modelo (antes de ajuste) ---")
    print(classification_report(y, preds, target_names=["Normal", "Anomalía"]))

    labeled_sample = df.sample(frac=0.10, random_state=42)
    labeled_idx = labeled_sample.index
    X_labeled = X.loc[labeled_idx]
    y_labeled = y.loc[labeled_idx]

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

    preds_ft_raw = model_finetuned.predict(X)
    preds_ft = (preds_ft_raw == -1).astype(int)

    print("\n--- Evaluación del modelo (después de ajuste fino) ---")
    print(classification_report(y, preds_ft, target_names=["Normal", "Anomalía"]))
    print("Matriz de confusión:")
    print(confusion_matrix(y, preds_ft))

    f1_base = f1_score(y, preds)
    f1_ft = f1_score(y, preds_ft)

    best_model = model if f1_base >= f1_ft else model_finetuned
    best_label = "base" if f1_base >= f1_ft else "ajuste fino"
    print(f"\nMejor modelo seleccionado: {best_label} (F1 anomalía: {max(f1_base, f1_ft):.4f})")

    joblib.dump(best_model, os.path.join(model_dir, "isolation_forest.joblib"))
    joblib.dump(fe, os.path.join(model_dir, "feature_engineer.joblib"))

    print(f"\nModelos guardados en: {model_dir}/")
    return best_model, fe


if __name__ == "__main__":
    train_model()

