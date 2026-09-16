from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.db.models import Role, User
from app.schemas.user import UserCreate


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def authenticate(db: AsyncSession, username: str, password: str) -> User | None:
    user = await get_user_by_username(db, username)
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def create_user(db: AsyncSession, payload: UserCreate) -> User:
    user = User(username=payload.username, hashed_password=hash_password(payload.password), role=payload.role)
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def any_users_exist(db: AsyncSession) -> bool:
    result = await db.execute(select(User.id).limit(1))
    return result.first() is not None


async def count_admins(db: AsyncSession) -> int:
    result = await db.execute(select(User.id).where(User.role == Role.admin, User.is_active.is_(True)))
    return len(result.all())
