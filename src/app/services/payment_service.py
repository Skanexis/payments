from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Payment, PaymentLog, PaymentStatus, SeenTransaction
from ..utils import dumps_json, ensure_utc, format_amount, loads_json, quantize_amount, to_decimal, utcnow


@dataclass(frozen=True)
class NetworkInfo:
    code: str
    title: str
    asset_symbol: str
    precision: int


NETWORKS: dict[str, NetworkInfo] = {
    "tron_usdt": NetworkInfo(
        code="tron_usdt",
        title="USDT (TRC20)",
        asset_symbol="USDT",
        precision=6,
    ),
    "bsc_usdt": NetworkInfo(
        code="bsc_usdt",
        title="USDT (BEP20)",
        asset_symbol="USDT",
        precision=6,
    ),
    "eth_usdt": NetworkInfo(
        code="eth_usdt",
        title="USDT (ERC20)",
        asset_symbol="USDT",
        precision=6,
    ),
    "btc": NetworkInfo(
        code="btc",
        title="Bitcoin (BTC)",
        asset_symbol="BTC",
        precision=8,
    ),
}


class PaymentService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def get_networks(self) -> dict[str, NetworkInfo]:
        return NETWORKS

    def get_network_wallet(self, network: str) -> str:
        if network == "tron_usdt":
            return self.settings.tron_wallet_address.strip()
        if network == "bsc_usdt":
            return self.settings.bsc_wallet_address.strip()
        if network == "eth_usdt":
            return self.settings.eth_wallet_address.strip()
        if network == "btc":
            return self.settings.btc_wallet_address.strip()
        return ""

    def network_options(self) -> list[dict[str, Any]]:
        options: list[dict[str, Any]] = []
        for network, info in self.get_networks().items():
            wallet = self.get_network_wallet(network)
            options.append(
                {
                    "code": info.code,
                    "title": info.title,
                    "asset_symbol": info.asset_symbol,
                    "wallet": wallet,
                    "configured": bool(wallet),
                    "required_confirmations": self.required_confirmations(network),
                }
            )
        return options

    def required_confirmations(self, network: str) -> int:
        if network == "tron_usdt":
            return max(1, self.settings.tron_required_confirmations)
        if network == "bsc_usdt":
            return max(1, self.settings.bsc_required_confirmations)
        if network == "eth_usdt":
            return max(1, self.settings.eth_required_confirmations)
        if network == "btc":
            return max(1, self.settings.btc_required_confirmations)
        return 1

    def network_precision(self, network: str) -> int:
        info = self.get_networks().get(network)
        if info is None:
            return 6
        return info.precision

    def network_asset_symbol(self, network: str) -> str:
        info = self.get_networks().get(network)
        if info is None:
            return ""
        return info.asset_symbol

    def create_payment(
        self,
        db: Session,
        *,
        title: str,
        network: str,
        base_amount: Decimal,
        description: str | None = None,
        ttl_minutes: int | None = None,
        external_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Payment:
        network_info = self.get_networks().get(network)
        if network_info is None:
            raise ValueError("Unsupported network")

        title_clean = title.strip()
        if not title_clean:
            raise ValueError("Title cannot be empty")

        destination = self.get_network_wallet(network)
        if not destination:
            raise ValueError(f"Wallet is not configured for network: {network}")

        ttl = ttl_minutes if ttl_minutes is not None else self.settings.payment_ttl_minutes
        if ttl < self.settings.payment_ttl_min_minutes or ttl > self.settings.payment_ttl_max_minutes:
            raise ValueError(
                f"ttl_minutes must be in range {self.settings.payment_ttl_min_minutes}-"
                f"{self.settings.payment_ttl_max_minutes}"
            )

        amount_base = self._validate_and_normalize_amount(
            network=network,
            base_amount=base_amount,
            precision=network_info.precision,
        )

        external_id_clean = external_id.strip() if external_id else None
        if external_id_clean:
            existing_external = db.scalar(select(Payment).where(Payment.external_id == external_id_clean))
            if existing_external:
                if self._is_idempotent_duplicate(
                    existing_external=existing_external,
                    network=network,
                    title=title_clean,
                    base_amount=amount_base,
                    precision=network_info.precision,
                ):
                    self.add_log(
                        db=db,
                        payment_id=existing_external.id,
                        level="warning",
                        message="Idempotent request returned existing payment",
                        context={"external_id": external_id_clean},
                    )
                    db.commit()
                    db.refresh(existing_external)
                    return existing_external
                raise ValueError(f"external_id already exists and belongs to another payment: {external_id_clean}")

        if amount_base <= 0:
            raise ValueError("Amount must be > 0")

        pay_amount, offset_steps = self._allocate_amount_slot(
            db=db,
            network=network,
            base_amount=amount_base,
            precision=network_info.precision,
        )
        now = utcnow()
        expires_at = now + timedelta(minutes=ttl)

        payment = Payment(
            external_id=(external_id_clean or None),
            title=title_clean,
            description=(description or None),
            network=network,
            asset_symbol=network_info.asset_symbol,
            destination_address=destination,
            base_amount=amount_base,
            pay_amount=pay_amount,
            actual_amount=None,
            amount_offset_steps=offset_steps,
            status=PaymentStatus.pending.value,
            tx_hash=None,
            payer_address=None,
            confirmations=0,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            paid_at=None,
            metadata_json=dumps_json(metadata or {}),
        )
        db.add(payment)
        db.flush()
        self.add_log(
            db=db,
            payment_id=payment.id,
            level="info",
            message="Payment created",
            context={
                "network": network,
                "base_amount": format_amount(amount_base, precision=network_info.precision),
                "pay_amount": format_amount(pay_amount, precision=network_info.precision),
                "expires_at": ensure_utc(expires_at).isoformat(),
                "required_confirmations": self.required_confirmations(network),
            },
        )
        db.commit()
        db.refresh(payment)
        return payment

    def _allocate_amount_slot(
        self,
        db: Session,
        network: str,
        base_amount: Decimal,
        precision: int,
    ) -> tuple[Decimal, int]:
        step = self._amount_step_for_network(network=network, precision=precision)
        if step <= 0:
            raise ValueError("amount_step must be > 0")

        rows = db.execute(
            select(Payment.pay_amount).where(
                Payment.network == network,
                Payment.status.in_(
                    [
                        PaymentStatus.pending.value,
                        PaymentStatus.confirming.value,
                    ]
                ),
            )
        ).all()
        used = {quantize_amount(row[0], precision=precision) for row in rows}

        max_steps = max(0, self.settings.amount_max_offset_steps)
        for offset_steps in range(max_steps + 1):
            candidate = quantize_amount(base_amount + (step * offset_steps), precision=precision)
            if candidate not in used:
                return candidate, offset_steps

        raise ValueError("No available unique amount slots for this network right now")

    def expire_outdated(self, db: Session) -> int:
        now = utcnow()
        rows = db.scalars(
            select(Payment).where(
                Payment.status == PaymentStatus.pending.value,
                Payment.expires_at < now,
            )
        ).all()
        if not rows:
            return 0

        for payment in rows:
            payment.status = PaymentStatus.expired.value
            payment.updated_at = now
            self.add_log(
                db=db,
                payment_id=payment.id,
                level="warning",
                message="Payment expired",
                context={"expired_at": ensure_utc(now).isoformat()},
            )
        db.commit()
        return len(rows)

    def mark_confirming(
        self,
        db: Session,
        *,
        payment: Payment,
        tx_hash: str,
        payer_address: str | None,
        amount: Decimal,
        confirmations: int,
        raw_data: dict[str, Any] | None = None,
    ) -> Payment:
        if payment.status not in (PaymentStatus.pending.value, PaymentStatus.confirming.value):
            return payment

        self._ensure_tx_hash_is_free(db=db, tx_hash=tx_hash, current_payment_id=payment.id)

        now = utcnow()
        previous_status = payment.status
        previous_confirmations = payment.confirmations
        previous_tx_hash = payment.tx_hash

        payment.status = PaymentStatus.confirming.value
        payment.updated_at = now
        payment.tx_hash = tx_hash
        payment.payer_address = payer_address or payment.payer_address
        network_precision = self.network_precision(payment.network)
        payment.actual_amount = quantize_amount(amount, precision=network_precision)
        payment.confirmations = max(0, confirmations)

        should_log = (
            previous_status != PaymentStatus.confirming.value
            or previous_confirmations != payment.confirmations
            or previous_tx_hash != tx_hash
        )
        if should_log:
            self.add_log(
                db=db,
                payment_id=payment.id,
                level="info",
                message="Transfer detected, waiting for required confirmations",
                context={
                    "tx_hash": tx_hash,
                    "payer_address": payer_address,
                    "amount": format_amount(amount, precision=network_precision),
                    "confirmations": confirmations,
                    "required_confirmations": self.required_confirmations(payment.network),
                },
            )
        self._upsert_seen_transaction(
            db=db,
            network=payment.network,
            tx_hash=tx_hash,
            amount=amount,
            raw_data=raw_data,
        )
        db.commit()
        db.refresh(payment)
        return payment

    def mark_paid(
        self,
        db: Session,
        *,
        payment: Payment,
        tx_hash: str,
        payer_address: str | None,
        amount: Decimal,
        confirmations: int,
        raw_data: dict[str, Any] | None = None,
    ) -> Payment:
        if payment.status not in (PaymentStatus.pending.value, PaymentStatus.confirming.value):
            return payment

        self._ensure_tx_hash_is_free(db=db, tx_hash=tx_hash, current_payment_id=payment.id)

        now = utcnow()
        payment.status = PaymentStatus.paid.value
        payment.updated_at = now
        payment.paid_at = now
        payment.tx_hash = tx_hash
        payment.payer_address = payer_address or None
        network_precision = self.network_precision(payment.network)
        payment.actual_amount = quantize_amount(amount, precision=network_precision)
        payment.confirmations = max(0, confirmations)

        self._upsert_seen_transaction(
            db=db,
            network=payment.network,
            tx_hash=tx_hash,
            amount=amount,
            raw_data=raw_data,
        )
        self.add_log(
            db=db,
            payment_id=payment.id,
            level="info",
            message="Payment marked as paid",
            context={
                "tx_hash": tx_hash,
                "payer_address": payer_address,
                "amount": format_amount(amount, precision=network_precision),
                "confirmations": confirmations,
            },
        )
        db.commit()
        db.refresh(payment)
        return payment

    def _ensure_tx_hash_is_free(self, db: Session, tx_hash: str, current_payment_id: str) -> None:
        collision = db.scalar(
            select(Payment).where(
                Payment.tx_hash == tx_hash,
                Payment.id != current_payment_id,
            )
        )
        if collision is not None:
            raise ValueError(f"tx_hash already linked to payment {collision.id}")

    def _upsert_seen_transaction(
        self,
        db: Session,
        *,
        network: str,
        tx_hash: str,
        amount: Decimal,
        raw_data: dict[str, Any] | None,
    ) -> None:
        existing_seen = db.scalar(select(SeenTransaction).where(SeenTransaction.tx_hash == tx_hash))
        precision = self.network_precision(network)
        if existing_seen is None:
            db.add(
                SeenTransaction(
                    network=network,
                    tx_hash=tx_hash,
                    amount=quantize_amount(amount, precision=precision),
                    detected_at=utcnow(),
                    raw_json=dumps_json(raw_data),
                )
            )
            return
        existing_seen.amount = quantize_amount(amount, precision=precision)
        existing_seen.raw_json = dumps_json(raw_data)

    def _is_idempotent_duplicate(
        self,
        *,
        existing_external: Payment,
        network: str,
        title: str,
        base_amount: Decimal,
        precision: int,
    ) -> bool:
        return (
            existing_external.network == network
            and existing_external.title.strip() == title.strip()
            and quantize_amount(existing_external.base_amount, precision=precision)
            == quantize_amount(base_amount, precision=precision)
        )

    def _validate_and_normalize_amount(self, *, network: str, base_amount: Decimal, precision: int) -> Decimal:
        try:
            raw = to_decimal(base_amount)
        except (ValueError, InvalidOperation) as exc:
            raise ValueError("Invalid amount") from exc

        try:
            min_allowed, max_allowed = self._amount_bounds(network=network, precision=precision)
        except (ValueError, InvalidOperation) as exc:
            raise ValueError("Invalid payment amount range configuration") from exc
        normalized = quantize_amount(raw, precision=precision)

        if raw != normalized:
            raise ValueError(f"Amount supports at most {precision} decimals")
        if normalized < min_allowed:
            raise ValueError(f"Amount must be >= {format_amount(min_allowed, precision=precision)}")
        if normalized > max_allowed:
            raise ValueError(f"Amount must be <= {format_amount(max_allowed, precision=precision)}")
        return normalized

    def _amount_bounds(self, *, network: str, precision: int) -> tuple[Decimal, Decimal]:
        if network == "btc":
            min_allowed = to_decimal(self.settings.btc_min_base_amount)
            max_allowed = to_decimal(self.settings.btc_max_base_amount)
        else:
            min_allowed = to_decimal(self.settings.payment_min_base_amount)
            max_allowed = to_decimal(self.settings.payment_max_base_amount)
        return quantize_amount(min_allowed, precision=precision), quantize_amount(max_allowed, precision=precision)

    def _amount_step_for_network(self, *, network: str, precision: int) -> Decimal:
        raw_step = self.settings.amount_step
        if network == "btc":
            raw_step = self.settings.btc_amount_step
        return quantize_amount(raw_step, precision=precision)

    def add_log(
        self,
        db: Session,
        *,
        payment_id: str | None,
        level: str,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        db.add(
            PaymentLog(
                payment_id=payment_id,
                level=level,
                message=message,
                context_json=dumps_json(context),
                created_at=utcnow(),
            )
        )

    def serialize_payment(self, payment: Payment) -> dict[str, Any]:
        created_at = ensure_utc(payment.created_at)
        updated_at = ensure_utc(payment.updated_at)
        expires_at = ensure_utc(payment.expires_at)
        paid_at = ensure_utc(payment.paid_at)
        precision = self.network_precision(payment.network)

        return {
            "id": payment.id,
            "external_id": payment.external_id,
            "title": payment.title,
            "description": payment.description,
            "network": payment.network,
            "asset_symbol": payment.asset_symbol,
            "destination_address": payment.destination_address,
            "base_amount": format_amount(payment.base_amount, precision=precision),
            "pay_amount": format_amount(payment.pay_amount, precision=precision),
            "actual_amount": format_amount(payment.actual_amount, precision=precision) if payment.actual_amount is not None else None,
            "status": payment.status,
            "tx_hash": payment.tx_hash,
            "payer_address": payment.payer_address,
            "confirmations": payment.confirmations,
            "created_at": created_at.isoformat() if created_at else "",
            "updated_at": updated_at.isoformat() if updated_at else "",
            "expires_at": expires_at.isoformat() if expires_at else "",
            "paid_at": paid_at.isoformat() if paid_at else None,
            "metadata": loads_json(payment.metadata_json),
            "pay_url": f"{self.settings.base_url.rstrip('/')}/pay/{payment.id}",
            "required_confirmations": self.required_confirmations(payment.network),
        }
