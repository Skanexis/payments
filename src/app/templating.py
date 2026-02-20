from pathlib import Path

from fastapi.templating import Jinja2Templates

from .utils import ensure_utc, format_amount


template_dir = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(template_dir))


def _format_datetime(value):
    value_utc = ensure_utc(value)
    if value_utc is None:
        return "-"
    return value_utc.strftime("%Y-%m-%d %H:%M:%S UTC")


templates.env.filters["dt"] = _format_datetime
templates.env.filters["amt"] = format_amount

