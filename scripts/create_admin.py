from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from app.db import SessionLocal, init_db  # noqa: E402
from app.models import AdminUser  # noqa: E402
from app.security import hash_password  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or update admin user password.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    init_db()

    with SessionLocal() as db:
        user = db.scalar(select(AdminUser).where(AdminUser.username == args.username))
        if user is None:
            user = AdminUser(username=args.username, password_hash=hash_password(args.password), is_active=True)
            db.add(user)
            db.commit()
            print(f"Admin user created: {args.username}")
            return

        user.password_hash = hash_password(args.password)
        user.is_active = True
        db.commit()
        print(f"Admin user password updated: {args.username}")


if __name__ == "__main__":
    main()

