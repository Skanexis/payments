from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .models import PaymentStatus


class PaymentCreateRequest(BaseModel):
    external_id: str | None = Field(default=None, max_length=128)
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)
    network: Literal["tron_usdt", "bsc_usdt", "eth_usdt", "btc"]
    base_amount: Decimal = Field(gt=Decimal("0"))
    ttl_minutes: int | None = Field(default=None, ge=1, le=1440)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PaymentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    external_id: str | None
    title: str
    description: str | None
    network: str
    asset_symbol: str
    destination_address: str
    base_amount: str
    pay_amount: str
    actual_amount: str | None
    status: str
    tx_hash: str | None
    payer_address: str | None
    confirmations: int
    required_confirmations: int
    created_at: str
    updated_at: str
    expires_at: str
    paid_at: str | None
    metadata: dict[str, Any]
    pay_url: str


class PaymentStatusResponse(BaseModel):
    payment_id: str
    status: PaymentStatus
    tx_hash: str | None
    amount: str
    network: str
    confirmations: int
    required_confirmations: int
    updated_at: str
