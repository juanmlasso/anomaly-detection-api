"""
Generador de conjunto de datos sintético de registros de acceso.
Simula logs de acceso con patrones normales y anómalos.
"""
import pandas as pd
import numpy as np
import os
from datetime import datetime, timedelta

np.random.seed(42)

NUM_RECORDS = 2000
ANOMALY_RATIO = 0.10  # 10% anomalías

num_normal = int(NUM_RECORDS * (1 - ANOMALY_RATIO))
num_anomalous = NUM_RECORDS - num_normal

# --- IPs ---
normal_ips = [f"192.168.1.{np.random.randint(1, 254)}" for _ in range(num_normal)]
anomalous_ips = [f"10.0.{np.random.randint(0,255)}.{np.random.randint(1,254)}" for _ in range(num_anomalous)]

# --- Usuarios ---
users_pool = [f"user_{i}" for i in range(1, 51)]
normal_users = np.random.choice(users_pool, num_normal).tolist()
anomalous_users = np.random.choice(users_pool[:10], num_anomalous).tolist()

# --- Endpoints ---
normal_endpoints = ["/api/products", "/api/users", "/api/orders", "/api/search", "/home", "/login", "/dashboard"]
suspicious_endpoints = ["/admin/config", "/api/debug", "/admin/users/delete", "/api/../etc/passwd", "/admin/export-all", "/api/v1/internal/keys"]

normal_endpoint_list = np.random.choice(normal_endpoints, num_normal).tolist()
anomalous_endpoint_list = np.random.choice(suspicious_endpoints, num_anomalous).tolist()

# --- Métodos HTTP ---
normal_methods = np.random.choice(["GET", "POST", "GET", "GET"], num_normal).tolist()
anomalous_methods = np.random.choice(["DELETE", "PUT", "POST", "PATCH"], num_anomalous).tolist()

# --- Códigos de respuesta ---
normal_status = np.random.choice([200, 200, 200, 201, 301, 304], num_normal).tolist()
anomalous_status = np.random.choice([401, 403, 403, 500, 502, 404], num_anomalous).tolist()

# --- Bytes de respuesta ---
normal_bytes = np.random.randint(200, 5000, num_normal).tolist()
anomalous_bytes = np.random.choice(
    list(np.random.randint(0, 50, num_anomalous // 2)) +
    list(np.random.randint(50000, 500000, num_anomalous - num_anomalous // 2)),
    num_anomalous
).tolist()

# --- Requests por minuto (del mismo IP) ---
normal_rpm = np.random.randint(1, 15, num_normal).tolist()
anomalous_rpm = np.random.randint(50, 500, num_anomalous).tolist()

# --- Timestamps ---
base_time = datetime(2025, 3, 1, 0, 0, 0)
normal_hours = np.random.choice(range(7, 23), num_normal)
normal_timestamps = [(base_time + timedelta(hours=int(h), minutes=np.random.randint(0, 60), seconds=np.random.randint(0, 60))).isoformat() for h in normal_hours]
anomalous_hours = np.random.choice([0, 1, 2, 3, 4, 5, 23], num_anomalous)
anomalous_timestamps = [(base_time + timedelta(hours=int(h), minutes=np.random.randint(0, 60), seconds=np.random.randint(0, 60))).isoformat() for h in anomalous_hours]

# --- User agents ---
normal_agents = np.random.choice([
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
], num_normal).tolist()
anomalous_agents = np.random.choice([
    "python-requests/2.31.0",
    "curl/7.88.1",
    "sqlmap/1.7",
    "nikto/2.5.0",
    "",
], num_anomalous).tolist()

# --- Construir DataFrame ---
normal_df = pd.DataFrame({
    "timestamp": normal_timestamps,
    "ip_address": normal_ips,
    "user": normal_users,
    "method": normal_methods,
    "endpoint": normal_endpoint_list,
    "status_code": normal_status,
    "response_bytes": normal_bytes,
    "requests_per_minute": normal_rpm,
    "user_agent": normal_agents,
    "is_anomaly": 0,
})

anomalous_df = pd.DataFrame({
    "timestamp": anomalous_timestamps,
    "ip_address": anomalous_ips,
    "user": anomalous_users,
    "method": anomalous_methods,
    "endpoint": anomalous_endpoint_list,
    "status_code": anomalous_status,
    "response_bytes": anomalous_bytes,
    "requests_per_minute": anomalous_rpm,
    "user_agent": anomalous_agents,
    "is_anomaly": 1,
})

df = pd.concat([normal_df, anomalous_df], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

output_path = os.path.join(os.path.dirname(__file__), "..", "data", "access_logs.csv")
os.makedirs(os.path.dirname(output_path), exist_ok=True)
df.to_csv(output_path, index=False)

print(f"Dataset generado: {len(df)} registros ({num_normal} normales, {num_anomalous} anómalos)")
print(f"Guardado en: {output_path}")
