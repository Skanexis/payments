from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Crypto Payment Bot"
    environment: Literal["dev", "prod"] = "dev"
    host: str = "127.0.0.1"
    port: int = 8081
    base_url: str = "http://127.0.0.1:8081"

    database_url: str = "sqlite:///./data/crypto_pay.db"
    session_secret: str = "change-me-session-secret"
    admin_api_key: str = "change-me-admin-api-key"

    admin_username: str = "admin"
    admin_password: str = "change-me-admin-password"

    payment_ttl_minutes: int = 30
    payment_ttl_min_minutes: int = 3
    payment_ttl_max_minutes: int = 1440
    payment_min_base_amount: str = "1"
    payment_max_base_amount: str = "100000"
    amount_step: str = "0.001"
    amount_max_offset_steps: int = 200
    match_grace_before_minutes: int = 10
    match_grace_after_minutes: int = 10

    monitor_enabled: bool = True
    monitor_interval_seconds: int = 20
    monitor_lookback_minutes: int = 240
    monitor_track_unmatched_transfers: bool = True

    tron_wallet_address: str = ""
    tron_usdt_contract: str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    tron_api_base: str = "https://api.trongrid.io"
    tron_api_key: str = ""
    tron_required_confirmations: int = 1

    bsc_wallet_address: str = ""
    bsc_usdt_contract: str = "0x55d398326f99059ff775485246999027b3197955"
    bscscan_api_base: str = "https://api.bscscan.com/api"
    bscscan_api_key: str = ""
    bsc_required_confirmations: int = 3

    telegram_bot_token: str = ""
    telegram_admin_ids: str = ""
    telegram_notify_enabled: bool = False
    telegram_request_timeout_seconds: int = 10

    @property
    def telegram_admin_id_list(self) -> list[int]:
        if not self.telegram_admin_ids.strip():
            return []

        output: list[int] = []
        for chunk in self.telegram_admin_ids.split(","):
            item = chunk.strip()
            if not item:
                continue
            try:
                output.append(int(item))
            except ValueError:
                continue
        return output


@lru_cache
def get_settings() -> Settings:
    return Settings()
