import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from typing import Any


DEFAULT_AMOUNT_PRECISION = 6


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def to_decimal(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("Invalid decimal value") from exc


def quantize_amount(value: Any, precision: int = DEFAULT_AMOUNT_PRECISION) -> Decimal:
    decimal_value = to_decimal(value)
    quantum = Decimal("1").scaleb(-precision)
    return decimal_value.quantize(quantum, rounding=ROUND_DOWN)


def format_amount(value: Any, precision: int = DEFAULT_AMOUNT_PRECISION) -> str:
    decimal_value = quantize_amount(value, precision=precision)
    return format(decimal_value, "f")


def dumps_json(value: dict[str, Any] | None) -> str | None:
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def loads_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        loaded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    if isinstance(loaded, dict):
        return loaded
    return {}

