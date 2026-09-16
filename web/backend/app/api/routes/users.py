from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.db.base import get_db
from app.db.models import Role
from app.schemas.user import UserCreate, UserRead
from app.services.auth_service import create_user

router = APIRouter(prefix="/users", tags=["users"])


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_new_user(
    payload: UserCreate,
    db: AsyncSession = Depends(get_db),
    _admin=Depends(require_role(Role.admin)),
):
    try:
        return await create_user(db, payload)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
