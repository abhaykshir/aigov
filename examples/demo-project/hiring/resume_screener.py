"""Resume screening service — scores candidates against a job description.

This is a HIGH-RISK Annex III system (Employment / Worker Management) exposed
as a public HTTP API and operating on personally-identifiable candidate data.
"""
from fastapi import APIRouter, FastAPI
import openai

app = FastAPI()
router = APIRouter(prefix="/api")
client = openai.OpenAI()


@router.post("/screen")
def screen_candidate(email: str, resume_text: str, candidate_name: str) -> dict:
    """Score one candidate's resume against the open role.

    Stub — real logic would assemble the prompt, persist the decision, and
    enforce human-in-the-loop review before any rejection lands in the ATS.
    """
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a recruitment algorithm that performs resume "
                    "screening and candidate scoring."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"Candidate: {candidate_name} <{email}>\n"
                    f"Resume:\n{resume_text}"
                ),
            },
        ],
        response_format={"type": "json_object"},
    )
    return {"email": email, "result": response.choices[0].message.content}


app.include_router(router)
