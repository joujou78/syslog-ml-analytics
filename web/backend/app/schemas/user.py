import uuid

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import Role


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=72)
    role: Role = Role.viewer


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    role: Role
    is_active: bool
