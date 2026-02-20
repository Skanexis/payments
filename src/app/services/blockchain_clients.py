from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import httpx

from ..config import Settings


@dataclass(frozen=True)
class Transfer:
    network: str
    tx_hash: str
    amount: Decimal
    from_address: str
    to_address: str
    timestamp: datetime
    confirmations: int
    raw: dict[str, Any]


class TronUsdtClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def fetch_recent_transfers(self, wallet_address: str, lookback_minutes: int) -> list[Transfer]:
        if not wallet_address:
            return []

        url = f"{self.settings.tron_api_base.rstrip('/')}/v1/accounts/{wallet_address}/transactions/trc20"
        params = {
            "limit": 200,
            "contract_address": self.settings.tron_usdt_contract,
            "only_confirmed": "true",
        }
        headers: dict[str, str] = {}
        if self.settings.tron_api_key.strip():
            headers["TRON-PRO-API-KEY"] = self.settings.tron_api_key.strip()

        with httpx.Client(timeout=15) as client:
            response = client.get(url, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()

        data = payload.get("data", [])
        if not isinstance(data, list):
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        output: list[Transfer] = []
        for item in data:
            tx_hash = str(item.get("transaction_id", "")).strip()
            raw_value = str(item.get("value", "")).strip()
            block_timestamp = item.get("block_timestamp")
            to_address = str(item.get("to", "")).strip()
            from_address = str(item.get("from", "")).strip()

            if not tx_hash or not raw_value or not block_timestamp or not to_address:
                continue
            if to_address != wallet_address:
                continue

            token_info = item.get("token_info", {}) or {}
            try:
                decimals = int(token_info.get("decimals", 6))
                amount = Decimal(raw_value) / (Decimal(10) ** decimals)
            except Exception:
                continue

            try:
                timestamp = datetime.fromtimestamp(int(block_timestamp) / 1000, tz=timezone.utc)
            except Exception:
                continue
            if timestamp < cutoff:
                continue

            output.append(
                Transfer(
                    network="tron_usdt",
                    tx_hash=tx_hash,
                    amount=amount,
                    from_address=from_address,
                    to_address=to_address,
                    timestamp=timestamp,
                    confirmations=1,
                    raw=item,
                )
            )
        return output


class BscUsdtClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def fetch_recent_transfers(self, wallet_address: str, lookback_minutes: int) -> list[Transfer]:
        if not wallet_address:
            return []

        params = {
            "module": "account",
            "action": "tokentx",
            "contractaddress": self.settings.bsc_usdt_contract,
            "address": wallet_address,
            "sort": "desc",
            "page": 1,
            "offset": 200,
            "apikey": self.settings.bscscan_api_key or "YourApiKeyToken",
        }
        with httpx.Client(timeout=15) as client:
            response = client.get(self.settings.bscscan_api_base, params=params)
            response.raise_for_status()
            payload = response.json()

        result = payload.get("result", [])
        if not isinstance(result, list):
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        output: list[Transfer] = []
        wallet_lower = wallet_address.lower()

        for item in result:
            tx_hash = str(item.get("hash", "")).strip()
            raw_value = str(item.get("value", "")).strip()
            timestamp_raw = item.get("timeStamp")
            to_address = str(item.get("to", "")).strip()
            from_address = str(item.get("from", "")).strip()

            if not tx_hash or not raw_value or not timestamp_raw or not to_address:
                continue
            if to_address.lower() != wallet_lower:
                continue

            try:
                decimals = int(item.get("tokenDecimal", 18))
                amount = Decimal(raw_value) / (Decimal(10) ** decimals)
                timestamp = datetime.fromtimestamp(int(timestamp_raw), tz=timezone.utc)
            except Exception:
                continue
            if timestamp < cutoff:
                continue

            confirmations_raw = item.get("confirmations", 0)
            try:
                confirmations = int(confirmations_raw)
            except (TypeError, ValueError):
                confirmations = 0

            output.append(
                Transfer(
                    network="bsc_usdt",
                    tx_hash=tx_hash,
                    amount=amount,
                    from_address=from_address,
                    to_address=to_address,
                    timestamp=timestamp,
                    confirmations=confirmations,
                    raw=item,
                )
            )

        return output
