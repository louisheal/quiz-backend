import os

import requests
from fastapi import APIRouter
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.helpers.oauth import TOKEN_URL, TokenService

router = APIRouter()

# Constants
USER_INFO_URL = "https://id.twitch.tv/oauth2/userinfo"
REDIRECT_URI = os.getenv("REDIRECT_URI")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")


class AuthCode(BaseModel):
    code: str


@router.post("/token")
async def auth(auth_code: AuthCode):
    """
    Handles the OAuth2 callback from Twitch and retrieves the user's information.

    **Parameters:**
    - `auth_code` *(AuthCode)*: The authorization code returned by Twitch.

    **Returns:**
    - `JSONResponse`: A JSON response containing the JWT and refresh token.

    **Exceptions:**
    - `400 Bad Request`: If the access_code couldn't be validated.
    - `422 Unprocessable Entity`: If the body isn't json or containing a code field.
    """
    token_response = requests.post(
        TOKEN_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": auth_code.code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        },
    )
    if not token_response.status_code == 200:
        raise HTTPException(status_code=400, detail=token_response.json())

    token_data = token_response.json()
    access_token = token_data["access_token"]

    user_response = requests.get(
        USER_INFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    user_response.raise_for_status()
    user_data = user_response.json()

    # Generate JWT and Refresh Token
    token = TokenService.create_access_token(user_data)
    refresh_token = TokenService.create_refresh_token(user_data)

    return JSONResponse(content={"token": token, "refresh_token": refresh_token})


class RefreshToken(BaseModel):
    refresh_token: str


@router.post("/refresh")
async def refresh_jwt_token(refresh_token: RefreshToken):
    """
    Refreshes the JWT using the provided refresh token.

    **Parameters:**
    - `refresh_token` *(RefreshToken)*: The refresh token.

    **Returns:**
    - `JSONResponse`: A JSON response containing the new JWT and refresh token.
    """
    try:
        claims = TokenService.verify_token(refresh_token.refresh_token)
        user_data = claims["user_info"]
        new_jwt_token = TokenService.create_access_token(user_data)
        new_refresh_token = TokenService.create_refresh_token(user_data)
        return JSONResponse(content={"token": new_jwt_token, "refresh_token": new_refresh_token})
    except HTTPException as e:
        raise HTTPException(status_code=401, detail="Invalid refresh token") from e

class VerifyToken(BaseModel):
    token: str


@router.post("/me")
async def verify_token(token: VerifyToken):
    """
    Verifies the provided JWT token and returns the user information.

    **Parameters:**
    - `token` *(VerifyToken)*: The JWT token to verify.

    **Returns:**
    - `JSONResponse`: A JSON response containing the user information if the token is valid.
    """
    try:
        claims = TokenService.verify_token(token.token)
        user_data = claims["user_info"]
        return JSONResponse(content={"user_info": user_data})
    except HTTPException as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e