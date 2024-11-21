from fastapi import APIRouter, Depends

from app.helpers.oauth import oauth2_scheme

router = APIRouter()


@router.get("/protected")
async def protected(token: str = Depends(oauth2_scheme)):
    return {"message": "This is a protected endpoint", "token": token}
