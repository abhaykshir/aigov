"""Ranks shortlisted candidates by AI-assisted score."""
import openai

client = openai.OpenAI()


def rank_candidates(candidates: list[dict]) -> list[dict]:
    """Sort *candidates* by an OpenAI-generated score (highest first)."""
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": str(candidates)}],
    )
    # Stub: real implementation would parse a structured JSON response.
    return sorted(candidates, key=lambda c: c.get("score", 0), reverse=True)
