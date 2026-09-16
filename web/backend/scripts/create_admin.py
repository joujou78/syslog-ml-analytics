"""
One-time bootstrap: create the first admin account. After that, admins
create further users through the API (POST /api/users), which requires
being logged in as an existing admin -- this script exists only to solve
the chicken-and-egg problem of creating the very first one.

Usage (from web/backend, with the venv active):
    python scripts/create_admin.py --username admin
(prompts for a password rather than taking it as an argument, so it
doesn't end up in shell history)
"""
import argparse
import asyncio
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db.base import SessionLocal  # noqa: E402
from app.db.models import Role  # noqa: E402
from app.schemas.user import UserCreate  # noqa: E402
from app.services.auth_service import create_user, get_user_by_username  # noqa: E402


async def main(username: str) -> None:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match", file=sys.stderr)
        sys.exit(1)

    async with SessionLocal() as db:
        if await get_user_by_username(db, username) is not None:
            print(f"User '{username}' already exists", file=sys.stderr)
            sys.exit(1)
        user = await create_user(db, UserCreate(username=username, password=password, role=Role.admin))
        print(f"Created admin user '{user.username}' ({user.id})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    asyncio.run(main(args.username))
