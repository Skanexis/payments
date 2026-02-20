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

    def fetch_wallet_balance(self, wallet_address: str) -> Decimal | None:
        if not wallet_address:
            return None

        url = f"{self.settings.tron_api_base.rstrip('/')}/v1/accounts/{wallet_address}"
        headers: dict[str, str] = {}
        if self.settings.tron_api_key.strip():
            headers["TRON-PRO-API-KEY"] = self.settings.tron_api_key.strip()

        with httpx.Client(timeout=10) as client:
            response = client.get(url, headers=headers)
            response.raise_for_status()
            payload = response.json()

        data = payload.get("data", [])
        if not isinstance(data, list) or not data:
            return Decimal("0")

        account = data[0] if isinstance(data[0], dict) else {}
        trc20 = account.get("trc20", [])
        if not isinstance(trc20, list):
            return Decimal("0")

        contract = self.settings.tron_usdt_contract.strip().lower()
        for item in trc20:
            if not isinstance(item, dict):
                continue
            for key, value in item.items():
                if str(key).strip().lower() != contract:
                    continue
                raw = str(value).strip()
                if not raw:
                    return Decimal("0")
                amount = Decimal(raw)
                if "." in raw:
                    return amount
                return amount / (Decimal(10) ** 6)
        return Decimal("0")


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

    def fetch_wallet_balance(self, wallet_address: str) -> Decimal | None:
        if not wallet_address:
            return None

        params = {
            "module": "account",
            "action": "tokenbalance",
            "contractaddress": self.settings.bsc_usdt_contract,
            "address": wallet_address,
            "tag": "latest",
            "apikey": self.settings.bscscan_api_key or "YourApiKeyToken",
        }
        with httpx.Client(timeout=10) as client:
            response = client.get(self.settings.bscscan_api_base, params=params)
            response.raise_for_status()
            payload = response.json()

        raw = str(payload.get("result", "0") or "0").strip()
        if not raw.isdigit():
            return Decimal("0")

        return Decimal(raw) / (Decimal(10) ** 18)


class EthUsdtClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def fetch_recent_transfers(self, wallet_address: str, lookback_minutes: int) -> list[Transfer]:
        if not wallet_address:
            return []

        params = {
            "chainid": 1,
            "module": "account",
            "action": "tokentx",
            "contractaddress": self.settings.eth_usdt_contract,
            "address": wallet_address,
            "sort": "desc",
            "page": 1,
            "offset": 200,
            "apikey": self.settings.etherscan_api_key or "YourApiKeyToken",
        }
        with httpx.Client(timeout=15) as client:
            response = client.get(self.settings.etherscan_api_base, params=params)
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
                decimals = int(item.get("tokenDecimal", 6))
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
                    network="eth_usdt",
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

    def fetch_wallet_balance(self, wallet_address: str) -> Decimal | None:
        if not wallet_address:
            return None

        params = {
            "chainid": 1,
            "module": "account",
            "action": "tokenbalance",
            "contractaddress": self.settings.eth_usdt_contract,
            "address": wallet_address,
            "tag": "latest",
            "apikey": self.settings.etherscan_api_key or "YourApiKeyToken",
        }
        with httpx.Client(timeout=10) as client:
            response = client.get(self.settings.etherscan_api_base, params=params)
            response.raise_for_status()
            payload = response.json()

        raw = str(payload.get("result", "0") or "0").strip()
        if not raw.isdigit():
            return Decimal("0")
        return Decimal(raw) / (Decimal(10) ** 6)


class BtcClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def fetch_recent_transfers(self, wallet_address: str, lookback_minutes: int) -> list[Transfer]:
        if not wallet_address:
            return []

        base = self.settings.btc_api_base.rstrip("/")
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
        now = datetime.now(timezone.utc)

        with httpx.Client(timeout=15) as client:
            tip_height = self._fetch_tip_height(client, base)
            response = client.get(f"{base}/address/{wallet_address}/txs")
            response.raise_for_status()
            payload = response.json()

        if not isinstance(payload, list):
            return []

        output: list[Transfer] = []
        wallet_lower = wallet_address.lower()
        for item in payload:
            if not isinstance(item, dict):
                continue

            tx_hash = str(item.get("txid", "")).strip()
            if not tx_hash:
                continue

            received_sats = self._received_sats(item, wallet_lower)
            if received_sats <= 0:
                continue

            status = item.get("status", {}) if isinstance(item.get("status"), dict) else {}
            confirmed = bool(status.get("confirmed"))
            block_time = status.get("block_time")
            timestamp = now
            if block_time is not None:
                try:
                    timestamp = datetime.fromtimestamp(int(block_time), tz=timezone.utc)
                except Exception:
                    timestamp = now

            if timestamp < cutoff:
                continue

            confirmations = 0
            if confirmed:
                confirmations = 1
                if tip_height is not None:
                    block_height = status.get("block_height")
                    try:
                        confirmations = max(1, tip_height - int(block_height) + 1)
                    except Exception:
                        confirmations = 1

            output.append(
                Transfer(
                    network="btc",
                    tx_hash=tx_hash,
                    amount=Decimal(received_sats) / (Decimal(10) ** 8),
                    from_address=self._from_address(item),
                    to_address=wallet_address,
                    timestamp=timestamp,
                    confirmations=confirmations,
                    raw=item,
                )
            )

        return output

    def fetch_wallet_balance(self, wallet_address: str) -> Decimal | None:
        if not wallet_address:
            return None

        base = self.settings.btc_api_base.rstrip("/")
        with httpx.Client(timeout=10) as client:
            response = client.get(f"{base}/address/{wallet_address}")
            response.raise_for_status()
            payload = response.json()

        if not isinstance(payload, dict):
            return Decimal("0")

        chain_stats = payload.get("chain_stats", {}) if isinstance(payload.get("chain_stats"), dict) else {}
        mempool_stats = payload.get("mempool_stats", {}) if isinstance(payload.get("mempool_stats"), dict) else {}

        confirmed_sats = int(chain_stats.get("funded_txo_sum", 0) or 0) - int(chain_stats.get("spent_txo_sum", 0) or 0)
        mempool_sats = int(mempool_stats.get("funded_txo_sum", 0) or 0) - int(mempool_stats.get("spent_txo_sum", 0) or 0)
        total_sats = confirmed_sats + mempool_sats
        if total_sats < 0:
            total_sats = 0
        return Decimal(total_sats) / (Decimal(10) ** 8)

    def _fetch_tip_height(self, client: httpx.Client, base: str) -> int | None:
        try:
            response = client.get(f"{base}/blocks/tip/height")
            response.raise_for_status()
            return int(response.text.strip())
        except Exception:
            return None

    def _received_sats(self, tx: dict[str, Any], wallet_lower: str) -> int:
        received_total = 0
        outputs = tx.get("vout", [])
        if not isinstance(outputs, list):
            return 0
        for item in outputs:
            if not isinstance(item, dict):
                continue
            address = str(item.get("scriptpubkey_address", "")).strip().lower()
            if address != wallet_lower:
                continue
            try:
                value = int(item.get("value", 0) or 0)
            except Exception:
                value = 0
            if value > 0:
                received_total += value

        spent_total = 0
        inputs = tx.get("vin", [])
        if isinstance(inputs, list):
            for item in inputs:
                if not isinstance(item, dict):
                    continue
                prevout = item.get("prevout", {}) if isinstance(item.get("prevout"), dict) else {}
                address = str(prevout.get("scriptpubkey_address", "")).strip().lower()
                if address != wallet_lower:
                    continue
                try:
                    value = int(prevout.get("value", 0) or 0)
                except Exception:
                    value = 0
                if value > 0:
                    spent_total += value

        net = received_total - spent_total
        if net < 0:
            return 0
        return net

    def _from_address(self, tx: dict[str, Any]) -> str:
        vin = tx.get("vin", [])
        if not isinstance(vin, list):
            return ""
        for item in vin:
            if not isinstance(item, dict):
                continue
            prevout = item.get("prevout", {}) if isinstance(item.get("prevout"), dict) else {}
            address = str(prevout.get("scriptpubkey_address", "")).strip()
            if address:
                return address
        return ""
