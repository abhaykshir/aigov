"""Internal developer tool — suggests fixes for code issues using Claude."""
import anthropic

client = anthropic.Anthropic()


def suggest_code_fix(code_snippet: str, error_message: str, language: str = "python") -> str:
    """Ask Claude to diagnose an error and suggest a corrected version of the snippet."""
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2048,
        messages=[
            {
                "role": "user",
                "content": (
                    f"Language: {language}\n\n"
                    f"Code:\n```\n{code_snippet}\n```\n\n"
                    f"Error: {error_message}\n\n"
                    "Please explain the bug and provide a corrected version."
                ),
            }
        ],
    )
    return response.content[0].text
