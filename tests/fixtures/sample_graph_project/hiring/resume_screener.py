"""Resume screener — public API endpoint that screens candidates."""
from fastapi import APIRouter, FastAPI
import openai

app = FastAPI()
router = APIRouter(prefix="/api")
client = openai.OpenAI()


@router.post("/screen")
def screen_candidate(email: str, resume_text: str, candidate_name: str) -> dict:
    """Score a candidate and return a structured decision."""
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": f"{candidate_name} <{email}>: {resume_text}"},
        ],
    )
    return {"email": email, "result": response.choices[0].message.content}


app.include_router(router)
