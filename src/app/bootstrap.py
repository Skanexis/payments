from sqlalchemy import select

from .config import get_settings
from .db import SessionLocal
from .models import AdminUser, PaymentLog
from .security import hash_password
from .utils import utcnow


def ensure_default_admin() -> None:
    settings = get_settings()

    with SessionLocal() as db:
        existing = db.scalar(select(AdminUser).where(AdminUser.username == settings.admin_username))
        if existing:
            return

        admin = AdminUser(
            username=settings.admin_username,
            password_hash=hash_password(settings.admin_password),
            is_active=True,
        )
        db.add(admin)
        db.add(
            PaymentLog(
                payment_id=None,
                level="info",
                message=f"Default admin user created: {settings.admin_username}",
                context_json=None,
                created_at=utcnow(),
            )
        )
        db.commit()

