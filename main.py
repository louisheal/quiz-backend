from fastapi import FastAPI

from app.routes import auth
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

app.include_router(auth.router, prefix="/auth", tags=["auth"])
