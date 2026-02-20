from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base
from .utils import utcnow


class PaymentStatus(str, Enum):
    pending = "pending"
    confirming = "confirming"
    paid = "paid"
    expired = "expired"
    cancelled = "cancelled"


class NetworkCode(str, Enum):
    tron_usdt = "tron_usdt"
    bsc_usdt = "bsc_usdt"
    eth_usdt = "eth_usdt"
    btc = "btc"


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class Payment(Base):
    __tablename__ = "payments"
    __table_args__ = (
        Index("ix_payments_status_network", "status", "network"),
        Index("ix_payments_created_at", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    external_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    network: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_symbol: Mapped[str] = mapped_column(String(16), nullable=False, default="USDT")
    destination_address: Mapped[str] = mapped_column(String(255), nullable=False)

    base_amount: Mapped[Decimal] = mapped_column(Numeric(24, 8), nullable=False)
    pay_amount: Mapped[Decimal] = mapped_column(Numeric(24, 8), nullable=False)
    actual_amount: Mapped[Decimal | None] = mapped_column(Numeric(24, 8), nullable=True)

    amount_offset_steps: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default=PaymentStatus.pending.value)

    tx_hash: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    payer_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    confirmations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    logs: Mapped[list["PaymentLog"]] = relationship(
        "PaymentLog",
        back_populates="payment",
        cascade="all,delete-orphan",
        lazy="selectin",
    )


class PaymentLog(Base):
    __tablename__ = "payment_logs"
    __table_args__ = (Index("ix_payment_logs_created_at", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    payment_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("payments.id"), nullable=True)
    level: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    context_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    payment: Mapped[Payment | None] = relationship("Payment", back_populates="logs")


class SeenTransaction(Base):
    __tablename__ = "seen_transactions"
    __table_args__ = (Index("ix_seen_transactions_network_hash", "network", "tx_hash"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    network: Mapped[str] = mapped_column(String(32), nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(24, 8), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ObservedTransfer(Base):
    __tablename__ = "observed_transfers"
    __table_args__ = (
        Index("ix_observed_transfers_network_time", "network", "transfer_timestamp"),
        Index("ix_observed_transfers_match_status", "match_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    network: Mapped[str] = mapped_column(String(32), nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    from_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    to_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(24, 8), nullable=True)
    confirmations: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    transfer_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    matched_payment_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("payments.id"), nullable=True)
    match_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unmatched")
    note: Mapped[str | None] = mapped_column(String(255), nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)
