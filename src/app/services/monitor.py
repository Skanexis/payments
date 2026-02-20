from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta
from decimal import Decimal

import httpx
from sqlalchemy import and_, or_, select

from ..config import Settings
from ..db import SessionLocal
from ..models import ObservedTransfer, Payment, PaymentStatus
from ..utils import dumps_json, ensure_utc, format_amount, quantize_amount, utcnow
from .blockchain_clients import BscUsdtClient, Transfer, TronUsdtClient
from .payment_service import PaymentService


logger = logging.getLogger(__name__)


class PaymentMonitor:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.service = PaymentService(settings)
        self._clients = {
            "tron_usdt": TronUsdtClient(settings),
            "bsc_usdt": BscUsdtClient(settings),
        }
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        if not self.settings.monitor_enabled:
            logger.info("Payment monitor is disabled by configuration")
            return
        if self._task is not None and not self._task.done():
            return
        self._stop_event.clear()
        self._task = asyncio.create_task(self._run(), name="payment-monitor")
        logger.info("Payment monitor started")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop_event.set()
        await self._task
        logger.info("Payment monitor stopped")

    async def _run(self) -> None:
        interval = max(5, self.settings.monitor_interval_seconds)
        while not self._stop_event.is_set():
            try:
                await asyncio.to_thread(self._tick)
            except Exception:
                logger.exception("Payment monitor tick failed")

            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=interval)
            except TimeoutError:
                continue

    def _tick(self) -> None:
        with SessionLocal() as db:
            expired_count = self.service.expire_outdated(db)
            if expired_count:
                logger.info("Expired %s old pending payments", expired_count)

            now = utcnow()
            active = db.scalars(
                select(Payment).where(
                    or_(
                        and_(
                            Payment.status == PaymentStatus.pending.value,
                            Payment.expires_at >= now,
                        ),
                        Payment.status == PaymentStatus.confirming.value,
                    )
                )
            ).all()
            if not active:
                return

            grouped: dict[str, list[Payment]] = defaultdict(list)
            for payment in active:
                grouped[payment.network].append(payment)

            used_hash_to_payment: dict[str, str] = {}
            rows = db.execute(select(Payment.id, Payment.tx_hash).where(Payment.tx_hash.is_not(None))).all()
            for payment_id, tx_hash in rows:
                if tx_hash:
                    used_hash_to_payment[tx_hash] = payment_id
            used_hashes = set(used_hash_to_payment.keys())
            fetched: dict[str, list[Transfer]] = {}

            for network, payments in grouped.items():
                wallet = self.service.get_network_wallet(network)
                if not wallet:
                    continue

                client = self._clients.get(network)
                if client is None:
                    continue

                try:
                    transfers = client.fetch_recent_transfers(
                        wallet_address=wallet,
                        lookback_minutes=self.settings.monitor_lookback_minutes,
                    )
                    fetched[network] = transfers
                    logger.info("Fetched %s transfers for %s", len(transfers), network)
                except Exception:
                    logger.exception("Failed to fetch transfers for %s", network)
                    self.service.add_log(
                        db=db,
                        payment_id=None,
                        level="error",
                        message=f"Transfer fetch failed for network {network}",
                        context={"network": network},
                    )
                    db.commit()
                    continue

                if self.settings.monitor_track_unmatched_transfers:
                    for transfer in transfers:
                        self._upsert_observed_transfer(
                            db=db,
                            transfer=transfer,
                            match_status=None,
                            matched_payment_id=used_hash_to_payment.get(transfer.tx_hash),
                            note=None,
                        )
                    db.commit()

                # Stable ordering keeps matching deterministic.
                payments.sort(key=lambda p: ensure_utc(p.created_at) or now)

            paid_count = 0
            confirming_count = 0
            matched_hashes: set[str] = set()
            for network, payments in grouped.items():
                transfers = fetched.get(network, [])
                if not transfers:
                    continue

                transfer_by_hash = {item.tx_hash: item for item in transfers}

                # Step 1: continue processing payments that already have a selected tx_hash.
                for payment in payments:
                    if payment.status != PaymentStatus.confirming.value:
                        continue
                    if not payment.tx_hash:
                        continue
                    transfer = transfer_by_hash.get(payment.tx_hash)
                    if transfer is None:
                        continue

                    try:
                        result = self._apply_transfer_match(db=db, payment=payment, transfer=transfer)
                    except Exception:
                        logger.exception("Failed to finalize confirming payment %s", payment.id)
                        self.service.add_log(
                            db=db,
                            payment_id=payment.id,
                            level="error",
                            message="Failed to process confirming payment",
                            context={"tx_hash": payment.tx_hash},
                        )
                        db.commit()
                        continue

                    matched_hashes.add(transfer.tx_hash)
                    used_hashes.add(transfer.tx_hash)
                    if result == "paid":
                        paid_count += 1
                        self._notify_payment_paid(payment.id, network, transfer.tx_hash, transfer.amount)
                        self._upsert_observed_transfer(
                            db=db,
                            transfer=transfer,
                            match_status="matched",
                            matched_payment_id=payment.id,
                            note="finalized",
                        )
                    elif result == "confirming":
                        confirming_count += 1
                        self._upsert_observed_transfer(
                            db=db,
                            transfer=transfer,
                            match_status="awaiting_confirmations",
                            matched_payment_id=payment.id,
                            note="waiting confirmations",
                        )
                    db.commit()

                # Step 2: match new transfers to pending payments.
                pending_for_matching = [p for p in payments if p.status == PaymentStatus.pending.value]
                for payment in pending_for_matching:
                    match = self._match_transfer(payment, transfers, used_hashes)
                    if match is None:
                        continue

                    try:
                        result = self._apply_transfer_match(db=db, payment=payment, transfer=match)
                    except Exception:
                        logger.exception("Failed to apply transfer %s to payment %s", match.tx_hash, payment.id)
                        self.service.add_log(
                            db=db,
                            payment_id=payment.id,
                            level="error",
                            message="Failed to apply transfer to payment",
                            context={"tx_hash": match.tx_hash},
                        )
                        db.commit()
                        continue

                    used_hashes.add(match.tx_hash)
                    matched_hashes.add(match.tx_hash)
                    if result == "paid":
                        paid_count += 1
                        self._notify_payment_paid(payment.id, network, match.tx_hash, match.amount)
                        self._upsert_observed_transfer(
                            db=db,
                            transfer=match,
                            match_status="matched",
                            matched_payment_id=payment.id,
                            note="matched by amount+time window",
                        )
                    elif result == "confirming":
                        confirming_count += 1
                        self._upsert_observed_transfer(
                            db=db,
                            transfer=match,
                            match_status="awaiting_confirmations",
                            matched_payment_id=payment.id,
                            note="matched, waiting confirmations",
                        )
                    db.commit()

                # Step 3: classify non-matched transfers for diagnostics.
                if self.settings.monitor_track_unmatched_transfers:
                    for transfer in transfers:
                        if transfer.tx_hash in matched_hashes:
                            continue
                        if transfer.tx_hash in used_hash_to_payment and transfer.tx_hash not in matched_hashes:
                            self._upsert_observed_transfer(
                                db=db,
                                transfer=transfer,
                                match_status="matched",
                                matched_payment_id=used_hash_to_payment.get(transfer.tx_hash),
                                note="tx hash is already linked to an existing payment",
                            )
                            continue

                        reason = self._classify_unmatched_reason(
                            transfer=transfer,
                            payments=payments,
                        )
                        observed, created, changed = self._upsert_observed_transfer(
                            db=db,
                            transfer=transfer,
                            match_status=reason,
                            matched_payment_id=None,
                            note="not auto-matched",
                        )
                        if created or changed:
                            self.service.add_log(
                                db=db,
                                payment_id=None,
                                level="warning",
                                message="Incoming transfer was not auto-matched",
                                context={
                                    "network": transfer.network,
                                    "tx_hash": transfer.tx_hash,
                                    "amount": format_amount(transfer.amount),
                                    "reason": observed.match_status,
                                },
                            )
                    db.commit()

            if paid_count:
                logger.info("Marked %s payments as paid", paid_count)
            if confirming_count:
                logger.info("Updated %s payments in confirming status", confirming_count)

    def _apply_transfer_match(self, db, payment: Payment, transfer: Transfer) -> str:
        required_confirmations = self.service.required_confirmations(payment.network)
        if transfer.confirmations >= required_confirmations:
            self.service.mark_paid(
                db=db,
                payment=payment,
                tx_hash=transfer.tx_hash,
                payer_address=transfer.from_address,
                amount=transfer.amount,
                confirmations=transfer.confirmations,
                raw_data=transfer.raw,
            )
            return "paid"

        self.service.mark_confirming(
            db=db,
            payment=payment,
            tx_hash=transfer.tx_hash,
            payer_address=transfer.from_address,
            amount=transfer.amount,
            confirmations=transfer.confirmations,
            raw_data=transfer.raw,
        )
        return "confirming"

    def _match_transfer(
        self,
        payment: Payment,
        transfers: list[Transfer],
        used_hashes: set[str],
    ) -> Transfer | None:
        expected = quantize_amount(payment.pay_amount)
        created_at = ensure_utc(payment.created_at) or utcnow()
        expires_at = ensure_utc(payment.expires_at)
        grace_before = timedelta(minutes=max(0, self.settings.match_grace_before_minutes))
        grace_after = timedelta(minutes=max(0, self.settings.match_grace_after_minutes))

        for transfer in transfers:
            if transfer.tx_hash in used_hashes:
                continue
            if quantize_amount(transfer.amount) != expected:
                continue
            if transfer.timestamp < created_at - grace_before:
                continue
            if expires_at and transfer.timestamp > expires_at + grace_after:
                continue
            return transfer
        return None

    def _classify_unmatched_reason(self, transfer: Transfer, payments: Iterable[Payment]) -> str:
        expected_amount_matches = []
        for payment in payments:
            if quantize_amount(payment.pay_amount) != quantize_amount(transfer.amount):
                continue
            expected_amount_matches.append(payment)

        if not expected_amount_matches:
            return "amount_mismatch"

        grace_before = timedelta(minutes=max(0, self.settings.match_grace_before_minutes))
        grace_after = timedelta(minutes=max(0, self.settings.match_grace_after_minutes))
        before_count = 0
        after_count = 0

        for payment in expected_amount_matches:
            created_at = ensure_utc(payment.created_at) or utcnow()
            expires_at = ensure_utc(payment.expires_at)
            if transfer.timestamp < created_at - grace_before:
                before_count += 1
                continue
            if expires_at and transfer.timestamp > expires_at + grace_after:
                after_count += 1
                continue
            return "conflict"

        if before_count == len(expected_amount_matches):
            return "before_invoice"
        if after_count == len(expected_amount_matches):
            return "after_expired"
        return "unmatched"

    def _upsert_observed_transfer(
        self,
        db,
        *,
        transfer: Transfer,
        match_status: str | None,
        matched_payment_id: str | None,
        note: str | None,
    ) -> tuple[ObservedTransfer, bool, bool]:
        observed = db.scalar(select(ObservedTransfer).where(ObservedTransfer.tx_hash == transfer.tx_hash))
        now = utcnow()

        if observed is None:
            observed = ObservedTransfer(
                network=transfer.network,
                tx_hash=transfer.tx_hash,
                from_address=transfer.from_address,
                to_address=transfer.to_address,
                amount=quantize_amount(transfer.amount),
                confirmations=max(0, transfer.confirmations),
                transfer_timestamp=transfer.timestamp,
                matched_payment_id=matched_payment_id,
                match_status=(match_status or "seen"),
                note=note,
                first_seen_at=now,
                last_seen_at=now,
                raw_json=dumps_json(transfer.raw),
            )
            db.add(observed)
            return observed, True, True

        previous_status = observed.match_status
        observed.from_address = transfer.from_address
        observed.to_address = transfer.to_address
        observed.amount = quantize_amount(transfer.amount)
        observed.confirmations = max(0, transfer.confirmations)
        observed.transfer_timestamp = transfer.timestamp
        observed.last_seen_at = now
        observed.raw_json = dumps_json(transfer.raw)
        if matched_payment_id is not None:
            observed.matched_payment_id = matched_payment_id
        if match_status:
            observed.match_status = match_status
        observed.note = note

        return observed, False, previous_status != observed.match_status

    def _notify_payment_paid(self, payment_id: str, network: str, tx_hash: str, amount: Decimal) -> None:
        if not self.settings.telegram_notify_enabled:
            return
        if not self.settings.telegram_bot_token.strip():
            return
        chat_ids = self.settings.telegram_admin_id_list
        if not chat_ids:
            return

        text = (
            "Payment confirmed\n"
            f"ID: {payment_id}\n"
            f"Network: {network}\n"
            f"Amount: {format_amount(amount)} USDT\n"
            f"TX: {tx_hash}"
        )
        timeout = max(3, self.settings.telegram_request_timeout_seconds)
        api_url = f"https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage"

        with httpx.Client(timeout=timeout) as client:
            for chat_id in chat_ids:
                try:
                    client.post(api_url, json={"chat_id": chat_id, "text": text})
                except Exception:
                    logger.exception("Failed to send Telegram payment notification to chat %s", chat_id)
