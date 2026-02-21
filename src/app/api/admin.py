from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
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
from ..models import AdminUser, ObservedTransfer, Payment, PaymentLog, PaymentStatus, QuickPaymentTemplate
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

LOG_PARAM_META: dict[str, dict[str, str]] = {
    "network": {"label": "Network", "icon": "network"},
    "tx_hash": {"label": "TX", "icon": "tx"},
    "amount": {"label": "Amount", "icon": "amount"},
    "confirmations": {"label": "Conf", "icon": "confirmations"},
    "required_confirmations": {"label": "Need", "icon": "required"},
    "ip": {"label": "IP", "icon": "ip"},
    "username": {"label": "User", "icon": "user"},
    "candidate_count": {"label": "Candidates", "icon": "count"},
    "error_type": {"label": "Err Type", "icon": "error"},
    "error_text": {"label": "Err Text", "icon": "message"},
    "quote_amount": {"label": "Quote", "icon": "quote"},
    "btc_usd_rate": {"label": "Rate", "icon": "rate"},
    "rate_source": {"label": "Source", "icon": "source"},
    "payment_id": {"label": "Payment", "icon": "payment"},
    "payer_address": {"label": "From", "icon": "meta"},
    "match_status": {"label": "Status", "icon": "meta"},
    "before_count": {"label": "Before", "icon": "meta"},
    "after_count": {"label": "After", "icon": "meta"},
    "cancelled_by": {"label": "Cancelled By", "icon": "user"},
}

LOG_EVENT_META: dict[str, dict[str, str]] = {
    "ADMIN_LOGIN_FAILED": {
        "title": "Failed Admin Login",
        "description": "Wrong credentials or suspicious access attempt.",
        "tone": "warn",
    },
    "ADMIN_LOGIN_SUCCESS": {
        "title": "Admin Login",
        "description": "Administrator successfully authenticated.",
        "tone": "info",
    },
    "ADMIN_LOGOUT": {
        "title": "Admin Logout",
        "description": "Administrator session closed.",
        "tone": "info",
    },
    "TRANSFER_FETCH_FAILED": {
        "title": "Transfer Fetch Error",
        "description": "Node/API request failed, monitor could not load transfers.",
        "tone": "danger",
    },
    "TRANSFER_APPLY_FAILED": {
        "title": "Transfer Apply Error",
        "description": "Transfer was detected but could not be applied to payment state.",
        "tone": "danger",
    },
    "TRANSFER_MATCHED": {
        "title": "Transfer Matched",
        "description": "Transfer matched invoice by network/amount/time window.",
        "tone": "success",
    },
    "TRANSFER_AWAITING_CONFIRMATIONS": {
        "title": "Awaiting Confirmations",
        "description": "Transfer linked, waiting for required confirmations.",
        "tone": "info",
    },
    "TRANSFER_ALREADY_LINKED": {
        "title": "Transfer Already Linked",
        "description": "Tx hash already belongs to another payment.",
        "tone": "warn",
    },
    "TRANSFER_UNMATCHED": {
        "title": "Unmatched Transfer",
        "description": "Transfer was observed but not auto-matched.",
        "tone": "warn",
    },
    "BTC_RATE_LOCKED": {
        "title": "BTC Rate Locked",
        "description": "BTC/USD quote locked at invoice creation time.",
        "tone": "info",
    },
    "PAYMENT_CANCELLED_MANUALLY": {
        "title": "Payment Cancelled",
        "description": "Invoice was cancelled by administrator.",
        "tone": "warn",
    },
    "TEMPLATE_CREATED": {
        "title": "Template Created",
        "description": "Quick payment template added in admin panel.",
        "tone": "info",
    },
    "TEMPLATE_UPDATED": {
        "title": "Template Updated",
        "description": "Quick payment template was edited.",
        "tone": "info",
    },
}

CSRF_SESSION_KEY = "csrf_token"
_login_attempts: dict[str, list[datetime]] = defaultdict(list)
_login_attempts_lock = Lock()
USDT_NETWORK_CHOICES = ("tron_usdt", "bsc_usdt", "eth_usdt")
_dashboard_cache_lock = Lock()
_dashboard_cache: dict[str, Any] = {"expires_at": None, "enterprise": None}


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


def _network_currency(network: str) -> str:
    if network == "btc":
        return "BTC"
    return "USDT"


def _default_usdt_network() -> str:
    for network in USDT_NETWORK_CHOICES:
        if payment_service.get_network_wallet(network):
            return network
    return USDT_NETWORK_CHOICES[0]


def _resolve_template_network(currency: str, usdt_network: str) -> str:
    normalized_currency = currency.strip().upper()
    if normalized_currency == "BTC":
        return "btc"
    if normalized_currency == "USDT":
        return usdt_network
    raise ValueError("Unsupported currency")


def _validate_usdt_network(network: str) -> str:
    normalized = network.strip().lower()
    if normalized not in USDT_NETWORK_CHOICES:
        raise ValueError("USDT network must be one of tron_usdt, bsc_usdt, eth_usdt")
    return normalized


def _format_usd_value(value: Decimal | str | float | int) -> str:
    return format_amount(_safe_decimal(value), precision=2)


def _validate_template_amount(value: Decimal) -> Decimal:
    normalized = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    usdt_min = _safe_decimal(settings.payment_min_base_amount)
    usdt_max = _safe_decimal(settings.payment_max_base_amount)
    btc_min = _safe_decimal(settings.btc_min_base_amount)
    btc_max = _safe_decimal(settings.btc_max_base_amount)
    min_allowed = max(usdt_min, btc_min)
    max_allowed = min(usdt_max, btc_max)

    if normalized < min_allowed:
        raise ValueError(f"Template amount must be >= {_format_usd_value(min_allowed)} USD")
    if normalized > max_allowed:
        raise ValueError(f"Template amount must be <= {_format_usd_value(max_allowed)} USD")
    return normalized


def _serialize_template(template: QuickPaymentTemplate) -> dict[str, Any]:
    created_at = ensure_utc(template.created_at)
    updated_at = ensure_utc(template.updated_at)
    return {
        "id": template.id,
        "title": template.title,
        "description": template.description or "",
        "usd_amount": _safe_decimal(template.usd_amount),
        "usd_amount_text": _format_usd_value(template.usd_amount),
        "ttl_minutes": template.ttl_minutes,
        "usdt_network": template.usdt_network,
        "is_active": bool(template.is_active),
        "created_by": template.created_by or "",
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _list_template_rows(db: Session) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(QuickPaymentTemplate).order_by(
            QuickPaymentTemplate.is_active.desc(),
            QuickPaymentTemplate.updated_at.desc(),
        )
    ).all()
    return [_serialize_template(item) for item in rows]


def _invalidate_dashboard_cache() -> None:
    with _dashboard_cache_lock:
        _dashboard_cache["enterprise"] = None
        _dashboard_cache["expires_at"] = None


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
    fifteen_min_ago = now - timedelta(minutes=15)
    five_min_ago = now - timedelta(minutes=5)
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
    transfers_15m = db.scalars(
        select(ObservedTransfer).where(ObservedTransfer.last_seen_at >= fifteen_min_ago)
    ).all()
    transfers_5m = db.scalars(
        select(ObservedTransfer).where(ObservedTransfer.last_seen_at >= five_min_ago)
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
    transfers_last_15m = len(transfers_15m)
    transfers_last_5m = len(transfers_5m)
    avg_tpm_5m = round(transfers_last_5m / 5, 2)
    payments_created_60m = sum(1 for p in payments if (ensure_utc(p.created_at) or now) >= hour_ago)
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
        "transfers_last_15m": transfers_last_15m,
        "transfers_last_5m": transfers_last_5m,
        "avg_tpm_5m": avg_tpm_5m,
        "payments_created_60m": payments_created_60m,
        "peak_tpm": peak_tpm,
        "load_level": load_level,
        "stale_active_count": stale_active_count,
        "network_rows": network_rows,
    }


def _get_enterprise_stats_cached(db: Session, payments: list[Payment]) -> dict[str, Any]:
    cache_seconds = max(0, settings.dashboard_stats_cache_seconds)
    if cache_seconds == 0:
        return _build_enterprise_stats(db, payments)

    now = utcnow()
    with _dashboard_cache_lock:
        cached_stats = _dashboard_cache.get("enterprise")
        expires_at = _dashboard_cache.get("expires_at")
        if cached_stats is not None and isinstance(expires_at, datetime) and now < expires_at:
            return cached_stats

    enterprise = _build_enterprise_stats(db, payments)
    with _dashboard_cache_lock:
        _dashboard_cache["enterprise"] = enterprise
        _dashboard_cache["expires_at"] = now + timedelta(seconds=cache_seconds)
    return enterprise


def _build_log_rows(logs: list[PaymentLog]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in logs:
        context = loads_json(item.context_json)
        level_key = item.level.lower()
        level_meta = LOG_LEVEL_META.get(level_key, {"label": level_key.upper(), "tone": "muted"})

        raw_event_code = str(context.get("event_code") or "").strip()
        event_code = raw_event_code.upper() if raw_event_code else "-"
        event_meta = LOG_EVENT_META.get(event_code, {})
        event_title = event_meta.get("title") or item.message
        event_description = event_meta.get("description") or ""
        event_tone = event_meta.get("tone") or level_meta["tone"]

        reason = str(context.get("reason") or context.get("match_status") or "")
        reason_description = str(context.get("reason_description") or "")
        if reason_description and not event_description:
            event_description = reason_description

        details: list[dict[str, str]] = []
        ordered_keys = (
            "network",
            "tx_hash",
            "amount",
            "confirmations",
            "required_confirmations",
            "payer_address",
            "quote_amount",
            "btc_usd_rate",
            "rate_source",
            "match_status",
            "ip",
            "username",
            "candidate_count",
            "before_count",
            "after_count",
            "cancelled_by",
            "error_type",
            "error_text",
        )
        used_keys: set[str] = set()

        for key in ordered_keys:
            value = context.get(key)
            if value is None or value == "":
                continue
            meta = LOG_PARAM_META.get(key, {"label": key.replace("_", " ").title(), "icon": "meta"})
            details.append(
                {
                    "key": key,
                    "label": meta["label"],
                    "icon": meta["icon"],
                    "value": str(value),
                }
            )
            used_keys.add(key)

        for key, value in context.items():
            key_text = str(key)
            if key_text in used_keys or key_text in ("event_code", "reason", "reason_description"):
                continue
            if value is None or value == "":
                continue
            meta = LOG_PARAM_META.get(key_text, {"label": key_text.replace("_", " ").title(), "icon": "meta"})
            details.append(
                {
                    "key": key_text,
                    "label": meta["label"],
                    "icon": meta["icon"],
                    "value": str(value),
                }
            )

        if item.payment_id:
            details.append(
                {
                    "key": "payment_id",
                    "label": "Payment",
                    "icon": "payment",
                    "value": item.payment_id[:8],
                }
            )

        rows.append(
            {
                "item": item,
                "level_key": level_key,
                "level_label": level_meta["label"],
                "level_tone": level_meta["tone"],
                "event_code": event_code,
                "event_title": event_title,
                "event_description": event_description,
                "event_tone": event_tone,
                "reason": reason,
                "reason_description": reason_description,
                "details": details,
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

    enterprise = _get_enterprise_stats_cached(db, payments_for_stats)

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
            chart_payments=payments_for_stats,
            now=utcnow(),
        ),
    )


@router.get("/payments")
def payments_page(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payments = db.scalars(select(Payment).order_by(Payment.created_at.desc()).limit(200)).all()
    network_options = payment_service.network_options()
    error = request.query_params.get("error")
    info = request.query_params.get("info")

    return templates.TemplateResponse(
        "payments.html",
        _page_context(
            request,
            admin,
            payments=payments,
            quick_templates=_list_template_rows(db),
            network_options=network_options,
            usdt_network_options=[item for item in network_options if item["code"] in USDT_NETWORK_CHOICES],
            default_template_ttl=settings.payment_ttl_minutes,
            default_template_usdt_network=_default_usdt_network(),
            quick_template_limit=max(1, settings.quick_templates_max_count),
            error=error,
            info=info,
        ),
    )


@router.post("/payments/templates/new")
def create_quick_template(
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    usd_amount: str = Form(...),
    ttl_minutes: int = Form(...),
    usdt_network: str = Form("tron_usdt"),
    is_active: bool = Form(False),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()
    if not _validate_csrf(request, csrf_token):
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Session expired. Refresh and try again')}",
            status_code=303,
        )

    existing_count = db.scalar(select(func.count()).select_from(QuickPaymentTemplate)) or 0
    if existing_count >= max(1, settings.quick_templates_max_count):
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template limit reached. Delete or deactivate old templates.')}",
            status_code=303,
        )

    title_value = title.strip()
    if not title_value:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template title is required')}",
            status_code=303,
        )
    if len(title_value) > 255:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template title is too long (max 255)')}",
            status_code=303,
        )

    description_value = description.strip()
    if len(description_value) > 5000:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template description is too long (max 5000)')}",
            status_code=303,
        )

    try:
        amount_decimal = Decimal(usd_amount)
    except (InvalidOperation, ValueError):
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Invalid USD amount')}",
            status_code=303,
        )
    try:
        amount_decimal = _validate_template_amount(amount_decimal)
    except ValueError as exc:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus(str(exc))}",
            status_code=303,
        )

    try:
        usdt_network_code = _validate_usdt_network(usdt_network)
    except ValueError as exc:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus(str(exc))}",
            status_code=303,
        )

    if ttl_minutes < settings.payment_ttl_min_minutes or ttl_minutes > settings.payment_ttl_max_minutes:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('TTL is out of allowed range')}",
            status_code=303,
        )

    now = utcnow()
    item = QuickPaymentTemplate(
        title=title_value,
        description=description_value or None,
        usd_amount=amount_decimal,
        ttl_minutes=ttl_minutes,
        usdt_network=usdt_network_code,
        is_active=bool(is_active),
        created_by=admin.username,
        created_at=now,
        updated_at=now,
    )
    db.add(item)
    payment_service.add_log(
        db=db,
        payment_id=None,
        level="info",
        message="Quick payment template created",
        context={
            "event_code": "TEMPLATE_CREATED",
            "username": admin.username,
            "title": title_value,
            "quote_amount": _format_usd_value(amount_decimal),
            "network": usdt_network_code,
        },
    )
    db.commit()
    return RedirectResponse(
        f"/admin/payments?info={quote_plus('Template created successfully')}",
        status_code=303,
    )


@router.post("/payments/templates/{template_id}/update")
def update_quick_template(
    template_id: int,
    request: Request,
    title: str = Form(...),
    description: str = Form(""),
    usd_amount: str = Form(...),
    ttl_minutes: int = Form(...),
    usdt_network: str = Form("tron_usdt"),
    is_active: bool = Form(False),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()
    if not _validate_csrf(request, csrf_token):
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Session expired. Refresh and try again')}",
            status_code=303,
        )

    item = db.get(QuickPaymentTemplate, template_id)
    if item is None:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template not found')}",
            status_code=303,
        )

    title_value = title.strip()
    if not title_value:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template title is required')}",
            status_code=303,
        )
    if len(title_value) > 255:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template title is too long (max 255)')}",
            status_code=303,
        )

    description_value = description.strip()
    if len(description_value) > 5000:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template description is too long (max 5000)')}",
            status_code=303,
        )

    try:
        amount_decimal = Decimal(usd_amount)
    except (InvalidOperation, ValueError):
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Invalid USD amount')}",
            status_code=303,
        )
    try:
        amount_decimal = _validate_template_amount(amount_decimal)
    except ValueError as exc:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus(str(exc))}",
            status_code=303,
        )

    try:
        usdt_network_code = _validate_usdt_network(usdt_network)
    except ValueError as exc:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus(str(exc))}",
            status_code=303,
        )

    if ttl_minutes < settings.payment_ttl_min_minutes or ttl_minutes > settings.payment_ttl_max_minutes:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('TTL is out of allowed range')}",
            status_code=303,
        )

    item.title = title_value
    item.description = description_value or None
    item.usd_amount = amount_decimal
    item.ttl_minutes = ttl_minutes
    item.usdt_network = usdt_network_code
    item.is_active = bool(is_active)
    item.updated_at = utcnow()

    payment_service.add_log(
        db=db,
        payment_id=None,
        level="info",
        message="Quick payment template updated",
        context={
            "event_code": "TEMPLATE_UPDATED",
            "username": admin.username,
            "title": item.title,
            "quote_amount": _format_usd_value(item.usd_amount),
            "network": item.usdt_network,
        },
    )
    db.commit()
    return RedirectResponse(
        f"/admin/payments?info={quote_plus('Template updated successfully')}",
        status_code=303,
    )


@router.post("/payments/quick")
def quick_create_payment(
    request: Request,
    template_id: int = Form(...),
    currency: str = Form("USDT"),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    if not _validate_csrf(request, csrf_token):
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Session expired. Refresh and try again')}",
            status_code=303,
        )

    item = db.get(QuickPaymentTemplate, template_id)
    if item is None:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template not found')}",
            status_code=303,
        )
    if not item.is_active:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Template is inactive')}",
            status_code=303,
        )

    try:
        network_code = _resolve_template_network(currency, item.usdt_network)
    except ValueError as exc:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus(str(exc))}",
            status_code=303,
        )

    if network_code not in payment_service.get_networks():
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Unsupported network')}",
            status_code=303,
        )

    if not payment_service.get_network_wallet(network_code):
        return RedirectResponse(
            f"/admin/payments?error={quote_plus('Wallet is not configured for selected currency/network')}",
            status_code=303,
        )

    try:
        payment = payment_service.create_payment(
            db=db,
            title=item.title,
            description=item.description or None,
            network=network_code,
            base_amount=_safe_decimal(item.usd_amount),
            ttl_minutes=item.ttl_minutes,
            metadata={
                "created_from": "quick_payments",
                "created_by": admin.username,
                "quick_template_id": item.id,
                "quick_template_title": item.title,
                "quick_template_currency": currency.strip().upper() or "USDT",
                "price_model": "usd_fixed",
                "quick_template_amount_usd": _format_usd_value(item.usd_amount),
            },
        )
    except Exception as exc:
        return RedirectResponse(
            f"/admin/payments?error={quote_plus(str(exc))}",
            status_code=303,
        )

    _invalidate_dashboard_cache()
    return RedirectResponse(
        f"/admin/payments/{payment.id}?info={quote_plus('Invoice created from template')}",
        status_code=303,
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
    currency: str = Form("USDT"),
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
        "currency": currency,
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

    network_code = network.strip().lower()
    selected_currency = currency.strip().upper() or "USDT"
    expected_currency = _network_currency(network_code)
    if selected_currency != expected_currency:
        return templates.TemplateResponse(
            "payment_new.html",
            _page_context(
                request,
                admin,
                error="Выбранная валюта не соответствует сети",
                values=values,
                network_options=payment_service.network_options(),
                default_ttl=settings.payment_ttl_minutes,
            ),
            status_code=400,
        )

    try:
        payment = payment_service.create_payment(
            db=db,
            title=title,
            description=description or None,
            network=network_code,
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

    _invalidate_dashboard_cache()
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
    pricing = payment_data.get("metadata", {}).get("pricing", {}) if isinstance(payment_data.get("metadata"), dict) else {}
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
            base_amount_text=format_amount(payment.base_amount, precision=payment_service.network_input_precision(payment.network)),
            expires_at=ensure_utc(payment.expires_at),
            pricing=pricing,
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
        _invalidate_dashboard_cache()

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
        _invalidate_dashboard_cache()
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
