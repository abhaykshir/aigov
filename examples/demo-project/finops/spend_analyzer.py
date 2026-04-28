"""Cloud-spend anomaly detection — flags unusual billing patterns per account."""
# Production FinOps analysis
import openai

client = openai.OpenAI()


def analyze_cloud_spend(account_id: str, billing_data: dict, payment_method: str) -> dict:
    """Identify cost anomalies and surface optimization opportunities for one account.

    Stub — the real workflow batches the prior month's billing data, runs the
    model, and writes recommendations to the FinOps dashboard. A finance lead
    reviews any recommendation before a workload is paused or rightsized.
    """
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a cloud FinOps model. Identify cost anomalies "
                    "and suggest optimization opportunities."
                ),
            },
            {
                "role": "user",
                "content": (
                    f"account_id: {account_id}\n"
                    f"payment_method: {payment_method}\n"
                    f"billing_data: {billing_data}"
                ),
            },
        ],
        response_format={"type": "json_object"},
    )
    return {
        "account_id": account_id,
        "result": response.choices[0].message.content,
    }
