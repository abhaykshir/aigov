"""Public customer support chatbot — handles inbound user messages over HTTP."""
import anthropic
from flask import Flask, jsonify, request

app = Flask(__name__)
client = anthropic.Anthropic()

SYSTEM_PROMPT = (
    "You are a helpful customer service AI assistant. "
    "Always identify yourself as an AI at the start of each conversation."
)


@app.route("/api/chat", methods=["POST"])
def chat():
    """Receive one inbound user message and return the assistant's reply."""
    payload = request.get_json() or {}
    return jsonify(handle_message(
        user_email=payload.get("user_email", ""),
        user_message=payload.get("user_message", ""),
        session_id=payload.get("session_id", ""),
    ))


def handle_message(user_email: str, user_message: str, session_id: str) -> dict:
    """Route a customer message through Claude and return the reply text."""
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )
    return {
        "session_id": session_id,
        "user_email": user_email,
        "reply": response.content[0].text,
    }
