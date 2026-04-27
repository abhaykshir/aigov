"""Fixture: a FastAPI app handling user email — public_api + pii signals."""
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter()


@app.get("/users/{user_id}")
def get_user(user_id: int) -> dict:
    return {"id": user_id, "email": "user@example.com"}


@app.post("/users")
def create_user(payload: dict) -> dict:
    email = payload.get("email")
    return {"email": email}
