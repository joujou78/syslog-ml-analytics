from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.security import create_access_token
from app.db.base import get_db
from app.db.models import User
from app.schemas.auth import Token
from app.schemas.user import UserRead
from app.services.auth_service import authenticate

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await authenticate(db, form_data.username, form_data.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=token)


@router.get("/me", response_model=UserRead)
async def read_current_user(user: User = Depends(get_current_user)):
    return user
