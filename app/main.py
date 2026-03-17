"""
API REST principal para detección de anomalías en registros de acceso.
Expone el endpoint /analyze que orquesta los agentes de ingestión y decisión.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

from app.agents.ingestion_agent import IngestionAgent, LogRecord
from app.agents.decision_agent import DecisionAgent, AnalysisSummary
from app.train_model import FeatureEngineer

# --- Modelos de Request/Response ---

class AnalyzeRequest(BaseModel):
    """Lote de registros de acceso para analizar."""
    records: List[LogRecord]

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "records": [
                        {
                            "timestamp": "2025-03-01T14:30:00",
                            "ip_address": "192.168.1.100",
                            "user": "user_12",
                            "method": "GET",
                            "endpoint": "/api/products",
                            "status_code": 200,
                            "response_bytes": 1500,
                            "requests_per_minute": 5,
                            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                        },
                        {
                            "timestamp": "2025-03-01T03:15:00",
                            "ip_address": "10.0.45.12",
                            "user": "user_3",
                            "method": "DELETE",
                            "endpoint": "/admin/users/delete",
                            "status_code": 403,
                            "response_bytes": 0,
                            "requests_per_minute": 150,
                            "user_agent": "sqlmap/1.7"
                        }
                    ]
                }
            ]
        }
    }


class ThreatDetail(BaseModel):
    record_index: int
    ip_address: str
    user: str
    endpoint: str
    is_threat: bool
    threat_level: str
    suggested_action: str
    anomaly_score: float
    reasons: List[str]


class AnalyzeResponse(BaseModel):
    """Respuesta del análisis de registros."""
    status: str
    total_records: int
    threats_detected: int
    threat_percentage: float
    actions_summary: Dict[str, int]
    critical_threats: List[ThreatDetail]
    all_decisions: List[ThreatDetail]


# --- Aplicación FastAPI ---

ingestion_agent: Optional[IngestionAgent] = None
decision_agent: Optional[DecisionAgent] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Inicializa los agentes al arrancar la aplicación."""
    global ingestion_agent, decision_agent
    print("=" * 60)
    print("Inicializando Agentes de Detección de Anomalías...")
    print("=" * 60)
    ingestion_agent = IngestionAgent()
    decision_agent = DecisionAgent()
    print("=" * 60)
    print("Sistema listo para analizar registros.")
    print("=" * 60)
    yield
    print("Apagando sistema de detección de anomalías...")


app = FastAPI(
    title="API de Detección de Anomalías en Registros de Acceso",
    description=(
        "Módulo backend que utiliza modelos de IA (Isolation Forest) para la detección "
        "inteligente de comportamientos anómalos en registros de acceso. "
        "Implementa dos agentes: uno de ingestión/procesamiento y otro de decisión."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["Health"])
async def root():
    """Endpoint de estado del servicio."""
    return {
        "service": "Anomaly Detection API",
        "version": "1.0.0",
        "status": "running",
        "agents": ["IngestionAgent", "DecisionAgent"],
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Verificación de salud del servicio y sus agentes."""
    return {
        "status": "healthy",
        "ingestion_agent": ingestion_agent is not None,
        "decision_agent": decision_agent is not None,
    }


@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_logs(request: AnalyzeRequest):
    """
    Analiza un lote de registros de acceso para detectar amenazas.

    **Flujo de agentes:**
    1. El Agente de Ingestión procesa los registros, extrae features y ejecuta el modelo ML
    2. Los resultados se comunican internamente al Agente de Decisión
    3. El Agente de Decisión evalúa el nivel de amenaza y sugiere acciones

    **Acciones posibles:**
    - `BLOCK`: Bloquear IP/usuario inmediatamente
    - `ALERT`: Enviar alerta al equipo de seguridad
    - `MONITOR`: Aumentar monitoreo
    - `ALLOW`: Tráfico normal

    **Niveles de amenaza:**
    - `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`
    """
    if not request.records:
        raise HTTPException(status_code=400, detail="Se requiere al menos un registro para analizar.")

    if ingestion_agent is None or decision_agent is None:
        raise HTTPException(status_code=503, detail="Los agentes no están inicializados.")

    try:
        # --- FLUJO DE AGENTES ---

        # Paso 1: Agente de Ingestión procesa los registros
        ingestion_results = ingestion_agent.process_batch(request.records)

        # Paso 2: Comunicación interna → Agente de Decisión evalúa resultados
        summary: AnalysisSummary = decision_agent.evaluate(ingestion_results)

        # Paso 3: Formatear respuesta
        critical = [
            ThreatDetail(
                record_index=d.record_index,
                ip_address=d.ip_address,
                user=d.user,
                endpoint=d.endpoint,
                is_threat=d.is_threat,
                threat_level=d.threat_level.value,
                suggested_action=d.suggested_action.value,
                anomaly_score=d.anomaly_score,
                reasons=d.reasons,
            )
            for d in summary.critical_threats
        ]

        all_decisions = [
            ThreatDetail(
                record_index=d.record_index,
                ip_address=d.ip_address,
                user=d.user,
                endpoint=d.endpoint,
                is_threat=d.is_threat,
                threat_level=d.threat_level.value,
                suggested_action=d.suggested_action.value,
                anomaly_score=d.anomaly_score,
                reasons=d.reasons,
            )
            for d in summary.decisions
        ]

        return AnalyzeResponse(
            status="completed",
            total_records=summary.total_records,
            threats_detected=summary.threats_detected,
            threat_percentage=summary.threat_percentage,
            actions_summary=summary.actions_summary,
            critical_threats=critical,
            all_decisions=all_decisions,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error en el análisis: {str(e)}")
