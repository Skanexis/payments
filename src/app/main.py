from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .api.admin import router as admin_router
from .api.internal import router as internal_router
from .api.public import router as public_router
from .config import get_settings
from .db import init_db
from .services.monitor import PaymentMonitor


settings = get_settings()


def configure_logging() -> None:
    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)

    stream_handler = logging.StreamHandler()
    file_handler = RotatingFileHandler(
        logs_dir / "app.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=[stream_handler, file_handler],
        force=True,
    )


configure_logging()
logger = logging.getLogger(__name__)
monitor = PaymentMonitor(settings)


def log_startup_configuration() -> None:
    if not settings.tron_wallet_address and not settings.bsc_wallet_address:
        logger.warning("No wallet address configured: auto matching will not detect payments")
    if not settings.admin_api_key or settings.admin_api_key.startswith("change-me"):
        logger.warning("ADMIN_API_KEY looks unsafe; set a strong random value")
    if not settings.session_secret or settings.session_secret.startswith("change-me") or len(settings.session_secret) < 32:
        logger.warning("SESSION_SECRET looks weak; set a random secret >= 32 chars")
    if not settings.admin_password or settings.admin_password.startswith("change-me"):
        logger.warning("ADMIN_PASSWORD is default; set a strong unique password")
    if settings.environment == "prod" and settings.base_url.startswith("http://"):
        logger.warning("BASE_URL uses HTTP in prod mode")


def build_allowed_hosts() -> list[str]:
    hosts = {"127.0.0.1", "localhost"}
    parsed = urlparse(settings.base_url)
    if parsed.hostname:
        hosts.add(parsed.hostname)
    return sorted(hosts)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log_startup_configuration()
    await monitor.start()
    try:
        yield
    finally:
        await monitor.stop()
        await asyncio.sleep(0)


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=build_allowed_hosts())

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=settings.environment == "prod",
    same_site="lax",
    max_age=max(300, settings.session_max_age_seconds),
)


@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)

    # CSP allows current inline scripts/styles used by templates while restricting external origins.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    if settings.environment == "prod":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith("/admin"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response

static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(public_router)
app.include_router(admin_router, prefix="/admin")
app.include_router(internal_router, prefix="/api/admin")
