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
from .security_audit import log_security_event, request_security_context
from .services.monitor import PaymentMonitor


settings = get_settings()
_redirect_status_codes = {301, 302, 303, 307, 308}


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

    path = request.url.path
    is_admin_path = path.startswith("/admin")
    is_admin_api_path = path.startswith("/api/admin")
    session_admin_id = None
    try:
        session_admin_id = request.session.get("admin_user_id")
    except Exception:
        session_admin_id = None

    if path == "/admin/login" and request.method not in {"GET", "POST"}:
        sec_context = request_security_context(request)
        sec_context["status_code"] = str(response.status_code)
        sec_context["auth_channel"] = "login_endpoint"
        log_security_event(
            event_code="SEC_ADMIN_LOGIN_METHOD_PROBE",
            message="Unsupported HTTP method used on /admin/login",
            context=sec_context,
            dedupe_key="login-method|" + sec_context.get("ip", "") + "|" + request.method,
            dedupe_window_seconds=75,
        )

    if path == "/admin/login" and request.method == "POST":
        content_type = request.headers.get("content-type", "").lower()
        if ("application/x-www-form-urlencoded" not in content_type) and ("multipart/form-data" not in content_type):
            sec_context = request_security_context(request)
            sec_context["status_code"] = str(response.status_code)
            sec_context["auth_channel"] = "login_non_form"
            log_security_event(
                event_code="SEC_ADMIN_LOGIN_METHOD_PROBE",
                message="Non-form payload used for /admin/login",
                context=sec_context,
                dedupe_key="login-non-form|" + sec_context.get("ip", ""),
                dedupe_window_seconds=75,
            )

    if is_admin_path and path != "/admin/login" and not session_admin_id:
        location = response.headers.get("location", "")
        if response.status_code in _redirect_status_codes and "/admin/login" in location:
            sec_context = request_security_context(request)
            sec_context["status_code"] = str(response.status_code)
            sec_context["auth_channel"] = "direct_admin_path"
            log_security_event(
                event_code="SEC_ADMIN_UNAUTH_PANEL_ACCESS",
                message="Unauthorized request to admin endpoint redirected to login",
                context=sec_context,
                dedupe_key="admin-redirect|" + sec_context.get("ip", "") + "|" + path,
                dedupe_window_seconds=60,
            )

    if is_admin_api_path and response.status_code == 405:
        sec_context = request_security_context(request)
        sec_context["status_code"] = str(response.status_code)
        sec_context["auth_channel"] = "api_method_probe"
        log_security_event(
            event_code="SEC_ADMIN_API_METHOD_PROBE",
            message="Unsupported HTTP method on /api/admin endpoint",
            context=sec_context,
            dedupe_key="api-method|" + sec_context.get("ip", "") + "|" + request.method + "|" + path,
            dedupe_window_seconds=60,
        )

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
