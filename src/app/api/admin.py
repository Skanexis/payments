from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from hmac import compare_digest
from secrets import token_urlsafe
from threading import Lock
from typing import Any
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import AdminUser, ObservedTransfer, Payment, PaymentLog, PaymentStatus
from ..security import verify_password
from ..services.blockchain_clients import BscUsdtClient, BtcClient, EthUsdtClient, TronUsdtClient
from ..services.payment_service import PaymentService
from ..templating import templates
from ..utils import ensure_utc, format_amount, loads_json, to_decimal, utcnow


router = APIRouter()
settings = get_settings()
payment_service = PaymentService(settings)
tron_client = TronUsdtClient(settings)
bsc_client = BscUsdtClient(settings)
eth_client = EthUsdtClient(settings)
btc_client = BtcClient(settings)

TRANSFER_STATUS_META: dict[str, dict[str, str]] = {
    "matched": {
        "label": "Matched",
        "description": "Transfer successfully linked to payment and finalized.",
        "tone": "matched",
    },
    "awaiting_confirmations": {
        "label": "Awaiting Confirmations",
        "description": "Transfer linked, waiting for required network confirmations.",
        "tone": "awaiting_confirmations",
    },
    "already_linked": {
        "label": "Already Linked",
        "description": "This tx hash is already bound to another payment.",
        "tone": "already_linked",
    },
    "amount_mismatch": {
        "label": "Amount Mismatch",
        "description": "No active invoice with this exact amount was found.",
        "tone": "amount_mismatch",
    },
    "before_invoice": {
        "label": "Before Invoice",
        "description": "Transfer time is earlier than invoice creation window.",
        "tone": "before_invoice",
    },
    "after_expired": {
        "label": "After Expired",
        "description": "Transfer time is later than invoice expiry + grace window.",
        "tone": "after_expired",
    },
    "conflict": {
        "label": "Conflict",
        "description": "Amount matches multiple active invoices; manual review required.",
        "tone": "conflict",
    },
    "unmatched": {
        "label": "Unmatched",
        "description": "Transfer could not be auto-matched; manual review required.",
        "tone": "unmatched",
    },
    "seen": {
        "label": "Seen",
        "description": "Transfer detected and tracked by monitor.",
        "tone": "seen",
    },
}

MATCHED_TRANSFER_STATUSES = {"matched", "awaiting_confirmations", "already_linked"}
ISSUE_TRANSFER_STATUSES = {"amount_mismatch", "before_invoice", "after_expired", "conflict", "unmatched"}

LOG_LEVEL_META: dict[str, dict[str, str]] = {
    "info": {"label": "Info", "tone": "info"},
    "warning": {"label": "Warning", "tone": "warn"},
    "error": {"label": "Error", "tone": "danger"},
    "debug": {"label": "Debug", "tone": "muted"},
}

CSRF_SESSION_KEY = "csrf_token"
_login_attempts: dict[str, list[datetime]] = defaultdict(list)
_login_attempts_lock = Lock()


def _redirect_to_login() -> RedirectResponse:
    return RedirectResponse("/admin/login", status_code=303)


def _current_admin(request: Request, db: Session) -> AdminUser | None:
    admin_id = request.session.get("admin_user_id")
    if not admin_id:
        return None
    user = db.get(AdminUser, admin_id)
    if not user or not user.is_active:
        return None
    return user


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _ensure_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if token and isinstance(token, str):
        return token
    new_token = token_urlsafe(32)
    request.session[CSRF_SESSION_KEY] = new_token
    return new_token


def _validate_csrf(request: Request, submitted_token: str) -> bool:
    expected = request.session.get(CSRF_SESSION_KEY)
    if not expected or not submitted_token:
        return False
    return compare_digest(str(expected), submitted_token.strip())


def _is_login_rate_limited(request: Request) -> bool:
    ip = _client_ip(request)
    now = utcnow()
    window = timedelta(minutes=max(1, settings.admin_login_window_minutes))
    max_attempts = max(1, settings.admin_login_max_attempts)

    with _login_attempts_lock:
        attempts = _login_attempts.get(ip, [])
        attempts = [item for item in attempts if (now - item) <= window]
        _login_attempts[ip] = attempts
        return len(attempts) >= max_attempts


def _register_login_failure(request: Request) -> None:
    ip = _client_ip(request)
    now = utcnow()
    window = timedelta(minutes=max(1, settings.admin_login_window_minutes))

    with _login_attempts_lock:
        attempts = _login_attempts.get(ip, [])
        attempts = [item for item in attempts if (now - item) <= window]
        attempts.append(now)
        _login_attempts[ip] = attempts


def _clear_login_failures(request: Request) -> None:
    ip = _client_ip(request)
    with _login_attempts_lock:
        if ip in _login_attempts:
            del _login_attempts[ip]


def _page_context(request: Request, admin: AdminUser | None, **extra: Any) -> dict[str, Any]:
    context = {"request": request, "admin_user": admin, "csrf_token": _ensure_csrf_token(request)}
    context.update(extra)
    return context


def _safe_decimal(value: Any) -> Decimal:
    try:
        return to_decimal(value)
    except Exception:
        return Decimal("0")


def _payment_amount(payment: Payment) -> Decimal:
    if payment.actual_amount is not None:
        return _safe_decimal(payment.actual_amount)
    return _safe_decimal(payment.pay_amount)


def _format_balance(value: Decimal | None, *, precision: int) -> str | None:
    if value is None:
        return None
    return format_amount(value, precision=precision)


def _fetch_live_balances() -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}

    for network, info in payment_service.get_networks().items():
        wallet = payment_service.get_network_wallet(network)
        precision = payment_service.network_precision(network)
        if not wallet:
            rows[network] = {
                "title": info.title,
                "wallet": "",
                "balance": None,
                "error": "wallet is not configured",
            }
            continue

        try:
            if network == "tron_usdt":
                balance = tron_client.fetch_wallet_balance(wallet)
            elif network == "bsc_usdt":
                balance = bsc_client.fetch_wallet_balance(wallet)
            elif network == "eth_usdt":
                balance = eth_client.fetch_wallet_balance(wallet)
            elif network == "btc":
                balance = btc_client.fetch_wallet_balance(wallet)
            else:
                balance = None
        except Exception:
            balance = None

        rows[network] = {
            "title": info.title,
            "wallet": wallet,
            "balance": _format_balance(balance, precision=precision),
            "error": None if balance is not None else "api unavailable or access denied",
        }

    return rows


def _asset_total_text(amounts: dict[str, Decimal]) -> str:
    if not amounts:
        return "0"
    parts: list[str] = []
    for symbol in sorted(amounts.keys()):
        value = amounts[symbol]
        precision = 8 if symbol == "BTC" else 6
        parts.append(f"{format_amount(value, precision=precision)} {symbol}")
    return ", ".join(parts)


def _payment_asset_symbol(payment: Payment) -> str:
    symbol = (payment.asset_symbol or "").strip().upper()
    if symbol:
        return symbol
    fallback = payment_service.network_asset_symbol(payment.network).strip().upper()
    return fallback or "ASSET"


def _build_enterprise_stats(db: Session, payments: list[Payment]) -> dict[str, Any]:
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    hour_ago = now - timedelta(hours=1)
    stale_cutoff = now - timedelta(minutes=max(15, settings.monitor_interval_seconds * 3))

    paid_payments = [p for p in payments if p.status == PaymentStatus.paid.value]
    active_payments = [p for p in payments if p.status in (PaymentStatus.pending.value, PaymentStatus.confirming.value)]

    paid_volume_total_by_asset: dict[str, Decimal] = {}
    paid_volume_24h_by_asset: dict[str, Decimal] = {}
    settlement_minutes: list[float] = []

    for payment in paid_payments:
        amount = _payment_amount(payment)
        symbol = _payment_asset_symbol(payment)
        paid_volume_total_by_asset[symbol] = paid_volume_total_by_asset.get(symbol, Decimal("0")) + amount

        paid_at = ensure_utc(payment.paid_at)
        created_at = ensure_utc(payment.created_at)
        if paid_at and paid_at >= day_ago:
            paid_volume_24h_by_asset[symbol] = paid_volume_24h_by_asset.get(symbol, Decimal("0")) + amount
        if paid_at and created_at:
            settlement_minutes.append(max(0.0, (paid_at - created_at).total_seconds() / 60.0))

    pending_exposure_by_asset: dict[str, Decimal] = {}
    stale_active_count = 0
    for payment in active_payments:
        symbol = _payment_asset_symbol(payment)
        pending_exposure_by_asset[symbol] = pending_exposure_by_asset.get(symbol, Decimal("0")) + _safe_decimal(
            payment.pay_amount
        )
        created_at = ensure_utc(payment.created_at)
        if created_at and created_at < stale_cutoff:
            stale_active_count += 1

    transfers_24h = db.scalars(
        select(ObservedTransfer).where(ObservedTransfer.last_seen_at >= day_ago)
    ).all()
    transfers_1h = db.scalars(
        select(ObservedTransfer).where(ObservedTransfer.last_seen_at >= hour_ago)
    ).all()

    transfer_total_24h = len(transfers_24h)
    transfer_matched_24h = sum(1 for transfer in transfers_24h if transfer.match_status in MATCHED_TRANSFER_STATUSES)
    transfer_issues_24h = sum(1 for transfer in transfers_24h if transfer.match_status in ISSUE_TRANSFER_STATUSES)

    match_rate_24h: float | None = None
    if transfer_total_24h > 0:
        match_rate_24h = round((transfer_matched_24h / transfer_total_24h) * 100, 1)

    minute_buckets: dict[str, int] = {}
    for transfer in transfers_1h:
        ts = ensure_utc(transfer.transfer_timestamp) or ensure_utc(transfer.last_seen_at)
        if ts is None:
            continue
        bucket = ts.strftime("%Y-%m-%d %H:%M")
        minute_buckets[bucket] = minute_buckets.get(bucket, 0) + 1

    peak_tpm = max(minute_buckets.values()) if minute_buckets else 0
    transfers_last_hour = len(transfers_1h)
    if transfers_last_hour >= 120 or peak_tpm >= 8:
        load_level = "high"
    elif transfers_last_hour >= 40 or peak_tpm >= 4:
        load_level = "medium"
    else:
        load_level = "low"

    avg_settlement_minutes: float | None = None
    if settlement_minutes:
        avg_settlement_minutes = round(sum(settlement_minutes) / len(settlement_minutes), 1)

    live_balances = _fetch_live_balances()
    network_rows: list[dict[str, Any]] = []
    max_network_hour = 0
    network_hour_counts: dict[str, int] = {}

    for network in payment_service.get_networks().keys():
        count = sum(1 for transfer in transfers_1h if transfer.network == network)
        network_hour_counts[network] = count
        max_network_hour = max(max_network_hour, count)

    for network, info in payment_service.get_networks().items():
        network_active = [p for p in active_payments if p.network == network]
        network_pending_volume = Decimal("0")
        for payment in network_active:
            network_pending_volume += _safe_decimal(payment.pay_amount)

        network_issues = sum(
            1
            for transfer in transfers_24h
            if transfer.network == network and transfer.match_status in ISSUE_TRANSFER_STATUSES
        )

        balance_info = live_balances.get(network, {})
        hour_count = network_hour_counts.get(network, 0)
        load_percent = 0
        if max_network_hour > 0:
            load_percent = round((hour_count / max_network_hour) * 100)

        network_rows.append(
            {
                "network": network,
                "title": info.title,
                "asset_symbol": info.asset_symbol,
                "required_confirmations": payment_service.required_confirmations(network),
                "active_payments": len(network_active),
                "pending_volume": format_amount(network_pending_volume, precision=info.precision),
                "transfers_last_hour": hour_count,
                "issues_last_24h": network_issues,
                "load_percent": load_percent,
                "live_balance": balance_info.get("balance"),
                "live_balance_error": balance_info.get("error"),
                "wallet": balance_info.get("wallet") or "",
            }
        )

    return {
        "paid_volume_total": _asset_total_text(paid_volume_total_by_asset),
        "paid_volume_24h": _asset_total_text(paid_volume_24h_by_asset),
        "pending_exposure": _asset_total_text(pending_exposure_by_asset),
        "avg_settlement_minutes": avg_settlement_minutes,
        "transfer_total_24h": transfer_total_24h,
        "transfer_matched_24h": transfer_matched_24h,
        "transfer_issues_24h": transfer_issues_24h,
        "match_rate_24h": match_rate_24h,
        "transfers_last_hour": transfers_last_hour,
        "peak_tpm": peak_tpm,
        "load_level": load_level,
        "stale_active_count": stale_active_count,
        "network_rows": network_rows,
    }


def _build_log_rows(logs: list[PaymentLog]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in logs:
        context = loads_json(item.context_json)
        level_key = item.level.lower()
        level_meta = LOG_LEVEL_META.get(level_key, {"label": level_key.upper(), "tone": "muted"})

        event_code = str(context.get("event_code") or "-")
        reason = str(context.get("reason") or context.get("match_status") or "")
        reason_description = str(context.get("reason_description") or "")

        summary_parts: list[str] = []
        for key in (
            "network",
            "tx_hash",
            "amount",
            "confirmations",
            "required_confirmations",
            "ip",
            "username",
            "candidate_count",
            "error_type",
            "error_text",
        ):
            value = context.get(key)
            if value is None or value == "":
                continue
            summary_parts.append(f"{key}: {value}")

        rows.append(
            {
                "item": item,
                "level_label": level_meta["label"],
                "level_tone": level_meta["tone"],
                "event_code": event_code,
                "reason": reason,
                "reason_description": reason_description,
                "summary": summary_parts,
            }
        )
    return rows


def _build_transfer_rows(transfers: list[ObservedTransfer]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}

    for transfer in transfers:
        meta = TRANSFER_STATUS_META.get(
            transfer.match_status,
            {
                "label": transfer.match_status,
                "description": "Unknown status",
                "tone": "seen",
            },
        )
        required = payment_service.required_confirmations(transfer.network)
        progress = 0
        if required > 0:
            progress = max(0, min(100, round((transfer.confirmations / required) * 100)))

        status_counts[transfer.match_status] = status_counts.get(transfer.match_status, 0) + 1
        rows.append(
            {
                "transfer": transfer,
                "status_label": meta["label"],
                "status_description": meta["description"],
                "status_tone": meta["tone"],
                "note": transfer.note or meta["description"],
                "required_confirmations": required,
                "progress_percent": progress,
            }
        )

    return rows, status_counts


@router.get("/login")
def login_page(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is not None:
        return RedirectResponse("/admin", status_code=303)

    return templates.TemplateResponse(
        "login.html",
        _page_context(request, admin, error=None),
    )


@router.post("/login")
def login_action(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    if not _validate_csrf(request, csrf_token):
        return templates.TemplateResponse(
            "login.html",
            _page_context(request, None, error="Сессия устарела. Обновите страницу и попробуйте снова."),
            status_code=400,
        )

    if _is_login_rate_limited(request):
        return templates.TemplateResponse(
            "login.html",
            _page_context(
                request,
                None,
                error=(
                    f"Слишком много попыток входа. Подождите {settings.admin_login_window_minutes} минут "
                    "и попробуйте снова."
                ),
            ),
            status_code=429,
        )

    admin = db.scalar(select(AdminUser).where(AdminUser.username == username.strip()))
    if admin is None or not verify_password(password, admin.password_hash):
        _register_login_failure(request)
        payment_service.add_log(
            db=db,
            payment_id=None,
            level="warning",
            message="Failed admin login attempt",
            context={
                "event_code": "ADMIN_LOGIN_FAILED",
                "username": username.strip(),
                "ip": _client_ip(request),
            },
        )
        db.commit()
        return templates.TemplateResponse(
            "login.html",
            _page_context(request, None, error="Неверный логин или пароль"),
        )

    _clear_login_failures(request)
    request.session.clear()
    request.session["admin_user_id"] = admin.id
    request.session[CSRF_SESSION_KEY] = token_urlsafe(32)
    payment_service.add_log(
        db=db,
        payment_id=None,
        level="info",
        message="Admin login successful",
        context={"event_code": "ADMIN_LOGIN_SUCCESS", "username": admin.username, "ip": _client_ip(request)},
    )
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    admin_id = request.session.get("admin_user_id")
    admin = db.get(AdminUser, admin_id) if admin_id else None
    if admin is not None:
        payment_service.add_log(
            db=db,
            payment_id=None,
            level="info",
            message="Admin logged out",
            context={"event_code": "ADMIN_LOGOUT", "username": admin.username, "ip": _client_ip(request)},
        )
        db.commit()
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


@router.get("")
@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payments = db.scalars(select(Payment).order_by(Payment.created_at.desc()).limit(100)).all()
    payments_for_stats = db.scalars(select(Payment).order_by(Payment.created_at.desc()).limit(5000)).all()

    stats_total = db.scalar(select(func.count()).select_from(Payment)) or 0
    stats_pending = (
        db.scalar(select(func.count()).select_from(Payment).where(Payment.status == PaymentStatus.pending.value))
        or 0
    )
    stats_paid = (
        db.scalar(select(func.count()).select_from(Payment).where(Payment.status == PaymentStatus.paid.value))
        or 0
    )
    stats_confirming = (
        db.scalar(select(func.count()).select_from(Payment).where(Payment.status == PaymentStatus.confirming.value))
        or 0
    )

    enterprise = _build_enterprise_stats(db, payments_for_stats)

    return templates.TemplateResponse(
        "admin_dashboard.html",
        _page_context(
            request,
            admin,
            payments=payments,
            stats_total=stats_total,
            stats_pending=stats_pending,
            stats_paid=stats_paid,
            stats_confirming=stats_confirming,
            enterprise=enterprise,
            now=utcnow(),
        ),
    )


@router.get("/payments/new")
def new_payment_page(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    return templates.TemplateResponse(
        "payment_new.html",
        _page_context(
            request,
            admin,
            error=None,
            values={},
            network_options=payment_service.network_options(),
            default_ttl=settings.payment_ttl_minutes,
        ),
    )


@router.post("/payments/new")
def create_payment_page(
    request: Request,
    title: str = Form(...),
    network: str = Form(...),
    base_amount: str = Form(...),
    description: str = Form(""),
    ttl_minutes: int = Form(30),
    external_id: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    values = {
        "title": title,
        "network": network,
        "base_amount": base_amount,
        "description": description,
        "ttl_minutes": ttl_minutes,
        "external_id": external_id,
    }

    if not _validate_csrf(request, csrf_token):
        return templates.TemplateResponse(
            "payment_new.html",
            _page_context(
                request,
                admin,
                error="Сессия формы устарела. Обновите страницу и отправьте форму снова.",
                values=values,
                network_options=payment_service.network_options(),
                default_ttl=settings.payment_ttl_minutes,
            ),
            status_code=400,
        )

    try:
        amount_decimal = Decimal(base_amount)
    except (InvalidOperation, ValueError):
        return templates.TemplateResponse(
            "payment_new.html",
            _page_context(
                request,
                admin,
                error="Некорректная сумма",
                values=values,
                network_options=payment_service.network_options(),
                default_ttl=settings.payment_ttl_minutes,
            ),
        )

    try:
        payment = payment_service.create_payment(
            db=db,
            title=title,
            description=description or None,
            network=network,
            base_amount=amount_decimal,
            ttl_minutes=ttl_minutes,
            external_id=external_id.strip() or None,
            metadata={"created_from": "admin_ui", "created_by": admin.username},
        )
    except Exception as exc:
        return templates.TemplateResponse(
            "payment_new.html",
            _page_context(
                request,
                admin,
                error=str(exc),
                values=values,
                network_options=payment_service.network_options(),
                default_ttl=settings.payment_ttl_minutes,
            ),
        )

    return RedirectResponse(f"/admin/payments/{payment.id}", status_code=303)


@router.get("/payments/{payment_id}")
def payment_detail(payment_id: str, request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payment = db.get(Payment, payment_id)
    if payment is None:
        return RedirectResponse("/admin", status_code=303)

    logs = db.scalars(
        select(PaymentLog).where(PaymentLog.payment_id == payment_id).order_by(PaymentLog.created_at.desc()).limit(200)
    ).all()
    payment_data = payment_service.serialize_payment(payment)
    error = request.query_params.get("error")
    info = request.query_params.get("info")

    return templates.TemplateResponse(
        "payment_detail.html",
        _page_context(
            request,
            admin,
            payment=payment,
            payment_data=payment_data,
            logs=logs,
            log_rows=_build_log_rows(logs),
            pay_url=f"{settings.base_url.rstrip('/')}/pay/{payment.id}",
            amount_text=format_amount(payment.pay_amount, precision=payment_service.network_precision(payment.network)),
            expires_at=ensure_utc(payment.expires_at),
            error=error,
            info=info,
            required_confirmations=payment_service.required_confirmations(payment.network),
        ),
    )


@router.post("/payments/{payment_id}/cancel")
def cancel_payment(
    payment_id: str,
    request: Request,
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payment = db.get(Payment, payment_id)
    if payment is None:
        return RedirectResponse("/admin", status_code=303)
    if not _validate_csrf(request, csrf_token):
        return RedirectResponse(
            f"/admin/payments/{payment.id}?error={quote_plus('Session expired. Refresh and retry action')}",
            status_code=303,
        )
    if payment.status == PaymentStatus.pending.value:
        payment.status = PaymentStatus.cancelled.value
        payment.updated_at = utcnow()
        payment_service.add_log(
            db=db,
            payment_id=payment.id,
            level="warning",
            message="Payment cancelled manually",
            context={"event_code": "PAYMENT_CANCELLED_MANUALLY", "cancelled_by": admin.username},
        )
        db.commit()

    return RedirectResponse(f"/admin/payments/{payment.id}", status_code=303)


@router.post("/payments/{payment_id}/mark-paid")
def manual_mark_paid(
    payment_id: str,
    request: Request,
    manual_tx_hash: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payment = db.get(Payment, payment_id)
    if payment is None:
        return RedirectResponse("/admin", status_code=303)
    if not _validate_csrf(request, csrf_token):
        return RedirectResponse(
            f"/admin/payments/{payment_id}?error={quote_plus('Session expired. Refresh and retry action')}",
            status_code=303,
        )

    tx_hash = manual_tx_hash.strip() or f"manual-{payment.id}"
    if payment.status in (PaymentStatus.pending.value, PaymentStatus.confirming.value):
        try:
            payment_service.mark_paid(
                db=db,
                payment=payment,
                tx_hash=tx_hash,
                payer_address="manual",
                amount=Decimal(str(payment.pay_amount)),
                confirmations=payment_service.required_confirmations(payment.network),
                raw_data={"manual": True, "actor": admin.username},
            )
        except Exception as exc:
            return RedirectResponse(
                f"/admin/payments/{payment.id}?error={quote_plus(str(exc))}",
                status_code=303,
            )
        return RedirectResponse(
            f"/admin/payments/{payment.id}?info={quote_plus('Marked as paid manually')}",
            status_code=303,
        )

    return RedirectResponse(
        f"/admin/payments/{payment.id}?info={quote_plus('Payment is already finalized')}",
        status_code=303,
    )


@router.get("/logs")
def logs_page(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    logs = db.scalars(select(PaymentLog).order_by(PaymentLog.created_at.desc()).limit(300)).all()
    log_rows = _build_log_rows(logs)

    error_count = sum(1 for item in log_rows if item["level_tone"] == "danger")
    warning_count = sum(1 for item in log_rows if item["level_tone"] == "warn")

    return templates.TemplateResponse(
        "logs.html",
        _page_context(
            request,
            admin,
            logs=logs,
            log_rows=log_rows,
            log_error_count=error_count,
            log_warning_count=warning_count,
            log_total_count=len(log_rows),
        ),
    )


@router.get("/transfers")
def transfers_page(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    transfers = db.scalars(select(ObservedTransfer).order_by(ObservedTransfer.last_seen_at.desc()).limit(400)).all()
    transfer_rows, status_counts = _build_transfer_rows(transfers)

    return templates.TemplateResponse(
        "transfers.html",
        _page_context(
            request,
            admin,
            transfers=transfers,
            transfer_rows=transfer_rows,
            status_counts=status_counts,
            transfer_status_meta=TRANSFER_STATUS_META,
            matched_statuses=sorted(MATCHED_TRANSFER_STATUSES),
            issue_statuses=sorted(ISSUE_TRANSFER_STATUSES),
        ),
    )
