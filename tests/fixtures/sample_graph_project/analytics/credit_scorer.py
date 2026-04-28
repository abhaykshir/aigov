"""Credit-scoring model — assesses credit applicants for the consumer-loans
product. Uses financial / salary signals."""
import openai

client = openai.OpenAI()


def score_applicant(applicant_id: str, salary: float, credit_history: dict) -> dict:
    """Score one applicant for credit-worthiness."""
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": f"{applicant_id} salary={salary} {credit_history}"},
        ],
    )
    return {"applicant_id": applicant_id, "decision": response.choices[0].message.content}
