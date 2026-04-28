"""Customer support chatbot — handles inbound queries via Claude over HTTP."""
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
    """Handle one inbound user message and return the assistant's reply."""
    payload = request.get_json() or {}
    user_message = payload.get("user_message", "")
    history = payload.get("history", [])
    return jsonify(handle_customer_query(user_message, history))


def handle_customer_query(user_message: str, history: list[dict]) -> dict:
    """Route a customer message through Claude and return the reply text."""
    messages = history + [{"role": "user", "content": user_message}]
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=messages,
    )
    return {"reply": response.content[0].text}
