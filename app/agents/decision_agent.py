"""
Agente de Decisión.

Responsabilidades:
- Recibir resultados del Agente de Ingestión
- Evaluar el nivel de amenaza basado en scores y flags
- Sugerir acciones: BLOCK, ALERT, MONITOR, ALLOW
- Generar un resumen ejecutivo del análisis
"""
from typing import List, Dict, Any
from enum import Enum
from pydantic import BaseModel
from app.agents.ingestion_agent import IngestionResult


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class SuggestedAction(str, Enum):
    BLOCK = "BLOCK"       # Bloquear IP/usuario inmediatamente
    ALERT = "ALERT"       # Enviar alerta al equipo de seguridad
    MONITOR = "MONITOR"   # Aumentar monitoreo del usuario/IP
    ALLOW = "ALLOW"       # Tráfico normal, sin acción requerida


class DecisionResult(BaseModel):
    record_index: int
    ip_address: str
    user: str
    endpoint: str
    is_threat: bool
    threat_level: ThreatLevel
    suggested_action: SuggestedAction
    anomaly_score: float
    reasons: List[str]


class AnalysisSummary(BaseModel):
    total_records: int
    threats_detected: int
    threat_percentage: float
    actions_summary: Dict[str, int]
    critical_threats: List[DecisionResult]
    decisions: List[DecisionResult]


class DecisionAgent:
    """
    Agente 2: Decisión y Respuesta.
    Recibe los resultados del Agente de Ingestión y determina acciones.
    """

    # Umbrales de decisión basados en anomaly_score del Isolation Forest
    CRITICAL_THRESHOLD = -0.25
    HIGH_THRESHOLD = -0.15
    MEDIUM_THRESHOLD = -0.05

    # Número de flags sospechosas para escalar la severidad
    FLAG_ESCALATION_THRESHOLD = 3

    def __init__(self):
        print("[DecisionAgent] Agente de decisión inicializado.")

    def _evaluate_threat_level(self, result: IngestionResult) -> ThreatLevel:
        """Determina el nivel de amenaza basado en score y flags."""
        score = result.anomaly_score
        active_flags = sum(1 for v in result.feature_flags.values() if v)

        # Si no es anomalía según el modelo, nivel bajo o nulo
        if not result.is_anomaly:
            if active_flags >= self.FLAG_ESCALATION_THRESHOLD:
                return ThreatLevel.MEDIUM
            elif active_flags >= 2:
                return ThreatLevel.LOW
            return ThreatLevel.NONE

        # Es anomalía - evaluar severidad
        if score < self.CRITICAL_THRESHOLD or active_flags >= 5:
            return ThreatLevel.CRITICAL
        elif score < self.HIGH_THRESHOLD or active_flags >= 4:
            return ThreatLevel.HIGH
        elif score < self.MEDIUM_THRESHOLD or active_flags >= 3:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _determine_action(self, threat_level: ThreatLevel) -> SuggestedAction:
        """Mapea nivel de amenaza a acción sugerida."""
        action_map = {
            ThreatLevel.CRITICAL: SuggestedAction.BLOCK,
            ThreatLevel.HIGH: SuggestedAction.BLOCK,
            ThreatLevel.MEDIUM: SuggestedAction.ALERT,
            ThreatLevel.LOW: SuggestedAction.MONITOR,
            ThreatLevel.NONE: SuggestedAction.ALLOW,
        }
        return action_map[threat_level]

    def _build_reasons(self, result: IngestionResult, threat_level: ThreatLevel) -> List[str]:
        """Genera razones legibles para la decisión."""
        reasons = []
        flags = result.feature_flags
        record = result.original_record

        if flags.get("is_night_access"):
            reasons.append(f"Acceso en horario nocturno (timestamp: {record.get('timestamp', 'N/A')})")
        if flags.get("is_error_status"):
            reasons.append(f"Código de estado HTTP de error: {record.get('status_code', 'N/A')}")
        if flags.get("is_extreme_bytes"):
            reasons.append(f"Volumen de respuesta inusual: {record.get('response_bytes', 'N/A')} bytes")
        if flags.get("is_high_rpm"):
            reasons.append(f"Tasa de peticiones elevada: {record.get('requests_per_minute', 'N/A')} req/min")
        if flags.get("suspicious_endpoint"):
            reasons.append(f"Endpoint sospechoso: {record.get('endpoint', 'N/A')}")
        if flags.get("suspicious_agent"):
            reasons.append(f"User-Agent sospechoso: {record.get('user_agent', 'N/A')}")

        if result.is_anomaly:
            reasons.append(f"Score de anomalía del modelo: {result.anomaly_score:.4f}")

        if not reasons:
            reasons.append("Tráfico dentro de parámetros normales")

        return reasons

    def evaluate(self, ingestion_results: List[IngestionResult]) -> AnalysisSummary:
        """
        Evalúa todos los resultados del Agente de Ingestión y genera decisiones.
        Este es el flujo principal de comunicación entre agentes.
        """
        decisions = []
        actions_count = {action.value: 0 for action in SuggestedAction}

        for result in ingestion_results:
            threat_level = self._evaluate_threat_level(result)
            action = self._determine_action(threat_level)
            reasons = self._build_reasons(result, threat_level)

            decision = DecisionResult(
                record_index=result.record_index,
                ip_address=result.original_record.get("ip_address", "N/A"),
                user=result.original_record.get("user", "N/A"),
                endpoint=result.original_record.get("endpoint", "N/A"),
                is_threat=threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM],
                threat_level=threat_level,
                suggested_action=action,
                anomaly_score=result.anomaly_score,
                reasons=reasons,
            )
            decisions.append(decision)
            actions_count[action.value] += 1

        threats = [d for d in decisions if d.is_threat]
        critical = [d for d in decisions if d.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]]

        summary = AnalysisSummary(
            total_records=len(decisions),
            threats_detected=len(threats),
            threat_percentage=round(len(threats) / max(len(decisions), 1) * 100, 2),
            actions_summary=actions_count,
            critical_threats=critical,
            decisions=decisions,
        )

        print(f"[DecisionAgent] Análisis completo: {len(threats)} amenazas de {len(decisions)} registros. "
              f"Acciones: {actions_count}")

        return summary
