import json
import os
import time
from typing import Optional

import requests


class TelegramNotifier:
    def __init__(self, config_path: str = None, min_interval_seconds: int = 5, timeout_seconds: int = 8):
        self.config_path = config_path or os.path.join("config", "telegram.json")
        self.min_interval_seconds = int(min_interval_seconds)
        self.timeout_seconds = int(timeout_seconds)

        self.bot_token = None
        self.chat_id = None
        self._last_sent_at = 0.0
        self._last_message = None

        self._load_credentials()

    @property
    def is_active(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def _load_credentials(self) -> None:
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        if bot_token and chat_id:
            self.bot_token = bot_token
            self.chat_id = chat_id
            return

        try:
            if not os.path.exists(self.config_path):
                return
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
            self.bot_token = data.get("bot_token") or None
            self.chat_id = data.get("chat_id") or None
        except Exception:
            self.bot_token = None
            self.chat_id = None
        if isinstance(self.bot_token, str) and self.bot_token.strip().startswith("<"):
            self.bot_token = None
        if isinstance(self.chat_id, str) and self.chat_id.strip().startswith("<"):
            self.chat_id = None

    def send(self, message: str, min_interval_seconds: Optional[int] = None) -> bool:
        if not self.is_active:
            return False

        now = time.time()
        interval = self.min_interval_seconds if min_interval_seconds is None else int(min_interval_seconds)
        if interval > 0 and (now - self._last_sent_at) < interval:
            return False

        if self._last_message == message and (now - self._last_sent_at) < max(interval, 1):
            return False

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": str(message)}

        try:
            resp = requests.post(url, data=payload, timeout=self.timeout_seconds)
            ok = bool(getattr(resp, "ok", False))
        except Exception:
            return False

        if ok:
            self._last_sent_at = now
            self._last_message = message
        return ok
