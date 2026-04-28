"""Customer support chatbot — Flask endpoint backed by Claude."""
import anthropic
from flask import Flask, jsonify, request

app = Flask(__name__)
client = anthropic.Anthropic()


@app.route("/api/chat", methods=["POST"])
def chat():
    payload = request.get_json() or {}
    user_message = payload.get("user_message", "")
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": user_message}],
    )
    return jsonify({"reply": response.content[0].text})
