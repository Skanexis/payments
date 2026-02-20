from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Payment
from ..schemas import PaymentStatusResponse
from ..services.payment_service import PaymentService
from ..templating import templates
from ..utils import ensure_utc, format_amount


router = APIRouter()
settings = get_settings()
payment_service = PaymentService(settings)


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "app_name": settings.app_name,
        },
    )


@router.get("/health")
def health():
    return {"ok": True}


@router.get("/pay/{payment_id}", response_class=HTMLResponse)
def pay_page(payment_id: str, request: Request, db: Session = Depends(get_db)):
    payment = db.get(Payment, payment_id)
    if payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    precision = payment_service.network_precision(payment.network)

    return templates.TemplateResponse(
        "public_payment.html",
        {
            "request": request,
            "payment": payment,
            "payment_data": payment_service.serialize_payment(payment),
            "pay_amount": format_amount(payment.pay_amount, precision=precision),
            "base_amount": format_amount(payment.base_amount, precision=precision),
            "expires_at": ensure_utc(payment.expires_at),
        },
    )


@router.get("/api/payments/{payment_id}", response_class=JSONResponse)
def get_payment_status(payment_id: str, db: Session = Depends(get_db)):
    payment = db.get(Payment, payment_id)
    if payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    return payment_service.serialize_payment(payment)


@router.get("/api/payments/{payment_id}/status", response_model=PaymentStatusResponse)
def get_compact_status(payment_id: str, db: Session = Depends(get_db)):
    payment = db.get(Payment, payment_id)
    if payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    precision = payment_service.network_precision(payment.network)

    return PaymentStatusResponse(
        payment_id=payment.id,
        status=payment.status,
        tx_hash=payment.tx_hash,
        amount=format_amount(payment.pay_amount, precision=precision),
        network=payment.network,
        confirmations=payment.confirmations,
        required_confirmations=payment_service.required_confirmations(payment.network),
        updated_at=(ensure_utc(payment.updated_at) or ensure_utc(payment.created_at)).isoformat(),
    )
