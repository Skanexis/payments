from pathlib import Path
from decimal import Decimal, InvalidOperation

from fastapi.templating import Jinja2Templates

from .utils import ensure_utc, format_amount


template_dir = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


def _format_datetime(value):
    value_utc = ensure_utc(value)
    if value_utc is None:
        return "-"
    return value_utc.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_amount_auto(value):
    try:
        dec = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return format_amount(value)
    text = format_amount(dec, precision=8)
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


templates.env.filters["dt"] = _format_datetime
templates.env.filters["amt"] = _format_amount_auto
