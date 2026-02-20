from __future__ import annotations

import logging
from decimal import Decimal, InvalidOperation

from sqlalchemy.orm import Session
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from .config import get_settings
from .db import SessionLocal, init_db
from .models import Payment
from .services.payment_service import PaymentService
from .utils import ensure_utc, format_amount


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()
payment_service = PaymentService(settings)


def _authorized(user_id: int | None) -> bool:
    if user_id is None:
        return False
    allowed_ids = settings.telegram_admin_id_list
    if not allowed_ids:
        return True
    return user_id in allowed_ids


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user is None:
        return
    if not _authorized(update.effective_user.id):
        await update.effective_message.reply_text("Access denied.")
        return

    await update.effective_message.reply_text(
        "Commands:\n"
        "/invoice <network> <amount> <title> - create payment\n"
        "/status <payment_id> - get payment status\n"
        "/help - show commands\n"
        "Networks: tron_usdt, bsc_usdt"
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await cmd_start(update, context)


async def cmd_invoice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user is None or update.effective_message is None:
        return
    if not _authorized(update.effective_user.id):
        await update.effective_message.reply_text("Access denied.")
        return

    if len(context.args) < 3:
        await update.effective_message.reply_text("Usage: /invoice <network> <amount> <title>")
        return

    network = context.args[0].strip().lower()
    amount_raw = context.args[1].strip()
    title = " ".join(context.args[2:]).strip()
    if not title:
        await update.effective_message.reply_text("Title is required.")
        return

    try:
        amount = Decimal(amount_raw)
    except (InvalidOperation, ValueError):
        await update.effective_message.reply_text("Invalid amount.")
        return

    with SessionLocal() as db:
        try:
            payment = payment_service.create_payment(
                db=db,
                title=title,
                description="Created from Telegram bot",
                network=network,
                base_amount=amount,
                metadata={"source": "telegram", "telegram_user_id": update.effective_user.id},
            )
        except Exception as exc:
            await update.effective_message.reply_text(f"Failed to create payment: {exc}")
            return

    pay_url = f"{settings.base_url.rstrip('/')}/pay/{payment.id}"
    await update.effective_message.reply_text(
        "Payment created\n"
        f"ID: {payment.id}\n"
        f"Network: {payment.network}\n"
        f"Amount: {format_amount(payment.pay_amount)} {payment.asset_symbol}\n"
        f"Address: {payment.destination_address}\n"
        f"Pay link: {pay_url}"
    )


def _load_payment(db: Session, payment_id: str) -> Payment | None:
    return db.get(Payment, payment_id)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user is None or update.effective_message is None:
        return
    if not _authorized(update.effective_user.id):
        await update.effective_message.reply_text("Access denied.")
        return
    if len(context.args) < 1:
        await update.effective_message.reply_text("Usage: /status <payment_id>")
        return

    payment_id = context.args[0].strip()
    with SessionLocal() as db:
        payment = _load_payment(db, payment_id)

    if payment is None:
        await update.effective_message.reply_text("Payment not found.")
        return

    updated_at = ensure_utc(payment.updated_at) or ensure_utc(payment.created_at)
    await update.effective_message.reply_text(
        "Payment status\n"
        f"ID: {payment.id}\n"
        f"Status: {payment.status}\n"
        f"Amount: {format_amount(payment.pay_amount)} {payment.asset_symbol}\n"
        f"TX: {payment.tx_hash or '-'}\n"
        f"Updated: {updated_at.isoformat() if updated_at else '-'}"
    )


def main() -> None:
    if not settings.telegram_bot_token.strip():
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured")

    init_db()
    app = Application.builder().token(settings.telegram_bot_token).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("invoice", cmd_invoice))
    app.add_handler(CommandHandler("status", cmd_status))

    logger.info("Starting Telegram bot polling")
    app.run_polling(close_loop=False)


if __name__ == "__main__":
    main()

