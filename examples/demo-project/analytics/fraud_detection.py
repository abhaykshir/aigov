"""Insurance fraud detection — assesses risk on incoming claims."""
# Production fraud scoring pipeline
import openai

client = openai.OpenAI()


def assess_claim_risk(policy_number: str, payment_amount: float, bank_account: str) -> dict:
    """Score a single claim for fraud indicators.

    Stub — the real pipeline batches claims overnight, runs them through the
    model, and writes a recommendation back to the underwriting system. A
    human adjuster reviews every flagged claim before any payout is held.
    """
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an insurance fraud detection model. Analyse the "
                    "claim and return a structured risk assessment."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"policy_number: {policy_number}\n"
                    f"payment_amount: {payment_amount}\n"
                    f"bank_account: {bank_account}"
                ),
            },
        ],
        response_format={"type": "json_object"},
    )
    return {
        "policy_number": policy_number,
        "result": response.choices[0].message.content,
    }
