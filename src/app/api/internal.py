from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from hmac import compare_digest
from threading import Lock

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Payment, QuickPaymentTemplate
from ..security_audit import log_security_event, request_security_context
from ..schemas import (
    PaymentCreateRequest,
    PaymentResponse,
    QuickCreateFromTemplateRequest,
    QuickTemplateCreateRequest,
    QuickTemplateResponse,
    QuickTemplateUpdateRequest,
)
from ..services.payment_service import PaymentService
from ..utils import ensure_utc, format_amount, utcnow


router = APIRouter()
settings = get_settings()
payment_service = PaymentService(settings)

_api_access_buckets: dict[str, list[datetime]] = defaultdict(list)
_api_access_lock = Lock()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def verify_admin_api_key(
    request: Request,
    x_api_key: str = Header(default=""),
) -> None:
    key = x_api_key.strip()
    expected = settings.admin_api_key.strip()
    if not expected:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="admin_api_key is not configured")
    if not compare_digest(key, expected):
        sec_context = request_security_context(request)
        sec_context["auth_channel"] = "api_header"
        sec_context["status_code"] = "401"
        log_security_event(
            event_code="SEC_ADMIN_API_INVALID_KEY",
            message="Admin API request rejected due to invalid API key",
            context=sec_context,
            dedupe_key=(
                "api-invalid-key|"
                + sec_context.get("ip", "")
                + "|"
                + sec_context.get("request_path", "")
            ),
            dedupe_window_seconds=45,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def enforce_admin_api_rate_limit(request: Request) -> None:
    ip = _client_ip(request)
    now = utcnow()
    window = timedelta(minutes=1)
    limit = max(30, settings.admin_api_rate_limit_per_minute)

    with _api_access_lock:
        bucket = _api_access_buckets.get(ip, [])
        bucket = [item for item in bucket if (now - item) <= window]
        if len(bucket) >= limit:
            sec_context = request_security_context(request)
            sec_context["auth_channel"] = "api_header"
            sec_context["status_code"] = "429"
            log_security_event(
                event_code="SEC_ADMIN_API_RATE_LIMIT",
                message="Admin API rate limit exceeded",
                context=sec_context,
                dedupe_key="api-rate-limit|" + sec_context.get("ip", ""),
                dedupe_window_seconds=60,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: max {limit} requests/minute",
            )
        bucket.append(now)
        _api_access_buckets[ip] = bucket


API_DEPS = [Depends(verify_admin_api_key), Depends(enforce_admin_api_rate_limit)]


def _template_payload(
    template: QuickPaymentTemplate,
) -> QuickTemplateResponse:
    created_at = ensure_utc(template.created_at)
    updated_at = ensure_utc(template.updated_at)
    return QuickTemplateResponse(
        id=template.id,
        title=template.title,
        description=template.description,
        usd_amount=format_amount(template.usd_amount, precision=2),
        ttl_minutes=template.ttl_minutes,
        usdt_network=template.usdt_network,
        is_active=template.is_active,
        created_by=template.created_by,
        created_at=created_at.isoformat() if created_at else "",
        updated_at=updated_at.isoformat() if updated_at else "",
    )


def _network_by_currency(currency: str, template: QuickPaymentTemplate, requested_network: str | None = None) -> str:
    normalized = currency.strip().upper()
    network = (requested_network or "").strip().lower()
    if normalized == "BTC":
        if network and network != "btc":
            raise HTTPException(status_code=400, detail="BTC supports only btc network")
        return "btc"
    if normalized == "USDT":
        if network and network != template.usdt_network:
            raise HTTPException(status_code=400, detail="USDT template uses fixed template network")
        return template.usdt_network
    raise HTTPException(status_code=400, detail="Unsupported currency")


def _validate_template_amount(value: Decimal) -> Decimal:
    normalized = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    usdt_min = Decimal(str(settings.payment_min_base_amount))
    usdt_max = Decimal(str(settings.payment_max_base_amount))
    btc_min = Decimal(str(settings.btc_min_base_amount))
    btc_max = Decimal(str(settings.btc_max_base_amount))
    min_allowed = max(usdt_min, btc_min)
    max_allowed = min(usdt_max, btc_max)
    if normalized < min_allowed:
        raise HTTPException(status_code=400, detail=f"Template amount must be >= {min_allowed} USD")
    if normalized > max_allowed:
        raise HTTPException(status_code=400, detail=f"Template amount must be <= {max_allowed} USD")
    return normalized


@router.post("/payments", response_model=PaymentResponse, dependencies=API_DEPS)
def create_payment_api(payload: PaymentCreateRequest, db: Session = Depends(get_db)):
    try:
        payment = payment_service.create_payment(
            db=db,
            title=payload.title,
            description=payload.description,
            network=payload.network,
            base_amount=payload.base_amount,
            ttl_minutes=payload.ttl_minutes,
            external_id=payload.external_id,
            metadata=payload.metadata,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return PaymentResponse(**payment_service.serialize_payment(payment))


@router.get("/payments/{payment_id}", response_model=PaymentResponse, dependencies=API_DEPS)
def get_payment_api(payment_id: str, db: Session = Depends(get_db)):
    payment = db.get(Payment, payment_id)
    if payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    return PaymentResponse(**payment_service.serialize_payment(payment))


@router.get("/payments", response_model=list[PaymentResponse], dependencies=API_DEPS)
def list_payments_api(limit: int = 50, db: Session = Depends(get_db)):
    limited = max(1, min(limit, 500))
    payments = db.scalars(select(Payment).order_by(Payment.created_at.desc()).limit(limited)).all()
    return [PaymentResponse(**payment_service.serialize_payment(p)) for p in payments]


@router.get("/networks", dependencies=API_DEPS)
def list_networks_api():
    return payment_service.network_options()


@router.get("/templates", response_model=list[QuickTemplateResponse], dependencies=API_DEPS)
def list_templates_api(limit: int = 200, db: Session = Depends(get_db)):
    limited = max(1, min(limit, 1000))
    templates = db.scalars(
        select(QuickPaymentTemplate).order_by(QuickPaymentTemplate.updated_at.desc()).limit(limited)
    ).all()
    return [_template_payload(item) for item in templates]


@router.post("/templates", response_model=QuickTemplateResponse, dependencies=API_DEPS)
def create_template_api(payload: QuickTemplateCreateRequest, db: Session = Depends(get_db)):
    existing_count = db.scalar(select(func.count()).select_from(QuickPaymentTemplate)) or 0
    if existing_count >= settings.quick_templates_max_count:
        raise HTTPException(
            status_code=400,
            detail=f"Template limit reached ({settings.quick_templates_max_count})",
        )

    if payload.usdt_network not in ("tron_usdt", "bsc_usdt", "eth_usdt"):
        raise HTTPException(status_code=400, detail="Invalid usdt_network")

    title_value = payload.title.strip()
    if not title_value:
        raise HTTPException(status_code=400, detail="title cannot be empty")

    now = utcnow()
    item = QuickPaymentTemplate(
        title=title_value,
        description=(payload.description or "").strip() or None,
        usd_amount=_validate_template_amount(payload.usd_amount),
        ttl_minutes=payload.ttl_minutes,
        usdt_network=payload.usdt_network,
        is_active=payload.is_active,
        created_by="api",
        created_at=now,
        updated_at=now,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return _template_payload(item)


@router.patch("/templates/{template_id}", response_model=QuickTemplateResponse, dependencies=API_DEPS)
def update_template_api(template_id: int, payload: QuickTemplateUpdateRequest, db: Session = Depends(get_db)):
    item = db.get(QuickPaymentTemplate, template_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Template not found")

    fields_set = payload.model_fields_set
    if "title" in fields_set:
        if payload.title is None:
            raise HTTPException(status_code=400, detail="title cannot be null")
        title_value = payload.title.strip()
        if not title_value:
            raise HTTPException(status_code=400, detail="title cannot be empty")
        item.title = title_value
    if "description" in fields_set:
        item.description = (payload.description or "").strip() or None
    if "usd_amount" in fields_set:
        if payload.usd_amount is None:
            raise HTTPException(status_code=400, detail="usd_amount cannot be null")
        item.usd_amount = _validate_template_amount(payload.usd_amount)
    if "ttl_minutes" in fields_set:
        if payload.ttl_minutes is None:
            raise HTTPException(status_code=400, detail="ttl_minutes cannot be null")
        item.ttl_minutes = payload.ttl_minutes
    if "usdt_network" in fields_set:
        if payload.usdt_network is None:
            raise HTTPException(status_code=400, detail="usdt_network cannot be null")
        if payload.usdt_network not in ("tron_usdt", "bsc_usdt", "eth_usdt"):
            raise HTTPException(status_code=400, detail="Invalid usdt_network")
        item.usdt_network = payload.usdt_network
    if "is_active" in fields_set:
        if payload.is_active is None:
            raise HTTPException(status_code=400, detail="is_active cannot be null")
        item.is_active = payload.is_active

    item.updated_at = utcnow()
    db.commit()
    db.refresh(item)
    return _template_payload(item)


@router.post(
    "/templates/{template_id}/quick-create",
    response_model=PaymentResponse,
    dependencies=API_DEPS,
)
def quick_create_from_template_api(
    template_id: int,
    payload: QuickCreateFromTemplateRequest,
    db: Session = Depends(get_db),
):
    item = db.get(QuickPaymentTemplate, template_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Template not found")
    if not item.is_active:
        raise HTTPException(status_code=400, detail="Template is inactive")

    network = _network_by_currency(payload.currency, item, payload.network)
    wallet = payment_service.get_network_wallet(network)
    if not wallet:
        raise HTTPException(status_code=400, detail=f"Wallet is not configured for network: {network}")

    try:
        payment = payment_service.create_payment(
            db=db,
            title=item.title,
            description=item.description,
            network=network,
            base_amount=item.usd_amount,
            ttl_minutes=item.ttl_minutes,
            metadata={
                "created_from": "quick_template_api",
                "template_id": item.id,
                "template_currency": payload.currency,
                "price_model": "usd_fixed",
            },
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return PaymentResponse(**payment_service.serialize_payment(payment))
