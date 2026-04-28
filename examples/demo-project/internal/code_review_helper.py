"""Internal developer tool — suggests fixes for code issues using Claude."""
import anthropic

client = anthropic.Anthropic()


def suggest_fix(code_snippet: str, error_message: str) -> str:
    """Ask Claude to diagnose an error and propose a corrected snippet."""
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Code:\n```\n{code_snippet}\n```\n\n"
                    f"Error: {error_message}\n\n"
                    "Explain the bug and provide a corrected version."
                ),
            }
        ],
    )
    return response.content[0].text
