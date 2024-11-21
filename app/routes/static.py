from fastapi import APIRouter, Depends

from app.helpers.oauth import TokenService

router = APIRouter()

current_user_validator = TokenService.get_current_user

@router.get("/protected")
async def protected(token: str = Depends(current_user_validator)):
    return {"message": "This is a protected endpoint", "token": token}
