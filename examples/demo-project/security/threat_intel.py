"""Threat intelligence pipeline — classifies inbound incidents and suggests response."""
# Production threat intelligence pipeline
import openai
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter(prefix="/api")
client = openai.OpenAI()


@router.post("/analyze-threat")
def analyze_incident(incident_id: str, source_ip: str, alert_payload: dict) -> dict:
    """Classify a SIEM-forwarded incident and recommend a response action.

    Stub — production pipeline pulls IOC enrichment, runs the model, and writes
    a recommended playbook back to the SOAR queue. A human analyst confirms
    every containment action before it executes.
    """
    threat_score = _threat_assessment(alert_payload)
    evidence_summary = _evidence_analysis(alert_payload)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a SOC threat intelligence model. Classify the "
                    "incident severity and suggest the next response action."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"incident_id: {incident_id}\n"
                    f"source_ip: {source_ip}\n"
                    f"threat_score: {threat_score}\n"
                    f"evidence: {evidence_summary}\n"
                    f"alert_payload: {alert_payload}"
                ),
            },
        ],
        response_format={"type": "json_object"},
    )
    return {
        "incident_id": incident_id,
        "result": response.choices[0].message.content,
    }


def _threat_assessment(alert_payload: dict) -> float:
    """Score severity from alert features (stub)."""
    return float(len(alert_payload))


def _evidence_analysis(alert_payload: dict) -> dict:
    """Summarise the evidence carried in the alert (stub)."""
    return {"indicators": list(alert_payload.keys())}


app.include_router(router)
