"""
Resets an existing user's password directly in the database. There is no
API endpoint for this (by design -- see app/services/auth_service.py: it
only ever creates users, never updates a password), so this is the only
way to recover a lost/forgotten password without psql and hand-rolled
bcrypt. Mirrors scripts/create_admin.py's own shape.

Usage (from web/backend, with the venv active):
    python scripts/reset_password.py --username admin
(prompts for the new password rather than taking it as an argument, so
it doesn't end up in shell history)
"""
import argparse
import asyncio
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.security import hash_password  # noqa: E402
from app.db.base import SessionLocal  # noqa: E402
from app.services.auth_service import get_user_by_username  # noqa: E402


async def main(username: str) -> None:
    password = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm new password: ")
    if password != confirm:
        print("Passwords do not match", file=sys.stderr)
        sys.exit(1)

    async with SessionLocal() as db:
        user = await get_user_by_username(db, username)
        if user is None:
            print(f"No user '{username}' exists -- use create_admin.py to create one instead", file=sys.stderr)
            sys.exit(1)
        user.hashed_password = hash_password(password)
        await db.commit()
        print(f"Password reset for user '{user.username}' ({user.id})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    asyncio.run(main(args.username))
