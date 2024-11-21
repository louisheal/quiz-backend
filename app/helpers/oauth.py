import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import HTTPException
from joserfc import errors, jwt
from joserfc.jwk import OctKey

TOKEN_URL = "https://id.twitch.tv/oauth2/token"
AUTHORIZATION_URL = "https://id.twitch.tv/oauth2/authorize"

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
key = OctKey.import_key(os.getenv("JWT_SECRET"))
ALGORITHM = "HS256"


class TokenService:
    """
    A service for handling token operations such as creating, verifying JWT tokens, and
    generating/decrypting TOTP secrets.
    """

    @staticmethod
    def get_current_user(token: str):
        try:
            claims = TokenService.verify_token(token)
            return claims["user_info"]
        except HTTPException as e:
            raise HTTPException(status_code=401, detail="Invalid token") from e

    @staticmethod
    def _create_token(user_data: dict, expires_delta: Optional[timedelta], default_expire: timedelta) -> str:
        to_encode = {"user_info": user_data, "uuid": str(uuid.uuid4())}
        expire = datetime.now(UTC) + (expires_delta or default_expire)
        to_encode.update({"exp": expire})
        header = {"alg": ALGORITHM}
        encoded_jwt = jwt.encode(header, to_encode, key)
        return encoded_jwt

    @staticmethod
    def create_access_token(user_data: dict, expires_delta: Optional[timedelta] = None) -> str:
        return TokenService._create_token(user_data, expires_delta, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    @staticmethod
    def create_refresh_token(user_data: dict, expires_delta: Optional[timedelta] = None) -> str:
        user_data["refresh"] = True
        user_data["refresh_date"] = datetime.now(UTC).isoformat()
        return TokenService._create_token(user_data, expires_delta, timedelta(days=30))

    @staticmethod
    def verify_token(token: str) -> dict:
        try:
            decoded_token = jwt.decode(token, key)
            claims = decoded_token.claims

            if "refresh" in claims:
                refresh_date = datetime.fromisoformat(claims["refresh_date"])
                if datetime.now(UTC) - refresh_date > timedelta(days=30):
                    raise errors.ExpiredTokenError("Refresh token has expired")
                del claims["refresh"]
                del claims["refresh_date"]

            return claims
        except errors.ExpiredTokenError as e:
            raise HTTPException(status_code=401, detail="Token has expired") from e
        except errors.MissingClaimError as e:
            raise HTTPException(status_code=401, detail="Missing claims in token") from e
        except Exception as e:
            raise HTTPException(status_code=401, detail="Invalid token") from e