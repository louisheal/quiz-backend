from fastapi import APIRouter, Depends

from app.helpers.jwt_token import get_current_user

router = APIRouter()


@router.get("/protected")
async def protected(token: str = Depends(get_current_user)):
    return {"message": "This is a protected endpoint", "token": token}
