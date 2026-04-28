"""Fraud-scoring model — runs as part of the nightly underwriting pipeline."""
# Production fraud scoring pipeline
import openai

client = openai.OpenAI()


def score_payment(policy_number: str, payment_amount: float, bank_account: str) -> dict:
    """Score a single payment for fraud risk."""
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": f"{policy_number} {payment_amount} {bank_account}"},
        ],
    )
    return {"policy_number": policy_number, "score": response.choices[0].message.content}
