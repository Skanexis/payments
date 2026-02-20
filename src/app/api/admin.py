from decimal import Decimal, InvalidOperation
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
from ..services.payment_service import PaymentService
from ..templating import templates
from ..utils import ensure_utc, format_amount, utcnow


router = APIRouter()
settings = get_settings()
payment_service = PaymentService(settings)


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


def _page_context(request: Request, admin: AdminUser | None, **extra: Any) -> dict[str, Any]:
    context = {"request": request, "admin_user": admin}
    context.update(extra)
    return context


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
    db: Session = Depends(get_db),
):
    admin = db.scalar(select(AdminUser).where(AdminUser.username == username.strip()))
    if admin is None or not verify_password(password, admin.password_hash):
        return templates.TemplateResponse(
            "login.html",
            _page_context(request, None, error="Неверный логин или пароль"),
        )

    request.session["admin_user_id"] = admin.id
    return RedirectResponse("/admin", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


@router.get("")
@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payments = db.scalars(select(Payment).order_by(Payment.created_at.desc()).limit(100)).all()
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
            pay_url=f"{settings.base_url.rstrip('/')}/pay/{payment.id}",
            amount_text=format_amount(payment.pay_amount),
            expires_at=ensure_utc(payment.expires_at),
            error=error,
            info=info,
            required_confirmations=payment_service.required_confirmations(payment.network),
        ),
    )


@router.post("/payments/{payment_id}/cancel")
def cancel_payment(payment_id: str, request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payment = db.get(Payment, payment_id)
    if payment is None:
        return RedirectResponse("/admin", status_code=303)
    if payment.status == PaymentStatus.pending.value:
        payment.status = PaymentStatus.cancelled.value
        payment.updated_at = utcnow()
        payment_service.add_log(
            db=db,
            payment_id=payment.id,
            level="warning",
            message="Payment cancelled manually",
            context={"cancelled_by": admin.username},
        )
        db.commit()

    return RedirectResponse(f"/admin/payments/{payment.id}", status_code=303)


@router.post("/payments/{payment_id}/mark-paid")
def manual_mark_paid(
    payment_id: str,
    request: Request,
    manual_tx_hash: str = Form(""),
    db: Session = Depends(get_db),
):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    payment = db.get(Payment, payment_id)
    if payment is None:
        return RedirectResponse("/admin", status_code=303)

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
    return templates.TemplateResponse(
        "logs.html",
        _page_context(request, admin, logs=logs),
    )


@router.get("/transfers")
def transfers_page(request: Request, db: Session = Depends(get_db)):
    admin = _current_admin(request, db)
    if admin is None:
        return _redirect_to_login()

    transfers = db.scalars(select(ObservedTransfer).order_by(ObservedTransfer.last_seen_at.desc()).limit(400)).all()
    return templates.TemplateResponse(
        "transfers.html",
        _page_context(request, admin, transfers=transfers),
    )
