from hmac import compare_digest

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Payment
from ..schemas import PaymentCreateRequest, PaymentResponse
from ..services.payment_service import PaymentService


router = APIRouter()
settings = get_settings()
payment_service = PaymentService(settings)


def verify_admin_api_key(x_api_key: str = Header(default="")) -> None:
    if not settings.admin_api_key:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="admin_api_key is not configured")
    if not compare_digest(x_api_key, settings.admin_api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


@router.post("/payments", response_model=PaymentResponse, dependencies=[Depends(verify_admin_api_key)])
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


@router.get("/payments/{payment_id}", response_model=PaymentResponse, dependencies=[Depends(verify_admin_api_key)])
def get_payment_api(payment_id: str, db: Session = Depends(get_db)):
    payment = db.get(Payment, payment_id)
    if payment is None:
        raise HTTPException(status_code=404, detail="Payment not found")
    return PaymentResponse(**payment_service.serialize_payment(payment))


@router.get("/payments", dependencies=[Depends(verify_admin_api_key)])
def list_payments_api(limit: int = 50, db: Session = Depends(get_db)):
    limited = max(1, min(limit, 500))
    payments = db.scalars(select(Payment).order_by(Payment.created_at.desc()).limit(limited)).all()
    return [payment_service.serialize_payment(p) for p in payments]
