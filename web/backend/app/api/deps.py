from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.clickhouse_client import get_clickhouse_client
from app.core.security import decode_access_token
from app.db.base import get_db
from app.db.models import Role, User
from app.services.auth_service import get_user_by_username

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

CredentialsError = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)
) -> User:
    payload = decode_access_token(token)
    if payload is None or "sub" not in payload:
        raise CredentialsError
    user = await get_user_by_username(db, payload["sub"])
    if user is None or not user.is_active:
        raise CredentialsError
    return user


def require_role(*allowed: Role):
    async def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' is not permitted to perform this action",
            )
        return user

    return checker


def get_ch_client():
    return get_clickhouse_client()
