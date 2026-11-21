"""Send a summary of an active workflow branch to a server-configured chat."""

import json
import os
import re
from collections import Counter
from contextlib import closing
from http.client import HTTPSConnection, HTTPException


class TelegramError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def send_summary(findings, explanation_count):
    token = os.environ.get("GHOST_TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("GHOST_TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        raise TelegramError("telegram-not-configured", "Укажите токен Telegram-бота и ID чата в окружении сервера.")
    if not re.fullmatch(r"[0-9]+:[a-zA-Z0-9_-]+", token) or not re.fullmatch(r"-?[0-9]+|@[a-zA-Z0-9_]+", chat_id):
        raise TelegramError("telegram-config-error", "Проверьте формат токена Telegram-бота и ID чата.")

    counts = Counter(finding["severity"] for finding in findings)
    summary = (
        "GHOST//GUARD — результаты проверки\n"
        f"Находок: {len(findings)}\n"
        f"Критических: {counts['critical']}, высоких: {counts['high']}, "
        f"средних: {counts['medium']}, низких: {counts['low']}\n"
        f"Объяснений LLM: {explanation_count}"
    )
    payload = json.dumps({"chat_id": chat_id, "text": summary}).encode()
    try:
        with closing(HTTPSConnection("api.telegram.org", timeout=5)) as connection:
            connection.request("POST", f"/bot{token}/sendMessage", payload, {"Content-Type": "application/json"})
            with connection.getresponse() as response:
                if response.status != 200:
                    raise TelegramError("telegram-provider-error", "Telegram не подтвердил отправку сообщения.")
                data = response.read(64 * 1024 + 1)
    except (OSError, HTTPException) as exc:
        raise TelegramError("telegram-provider-error", "Telegram не ответил на запрос.") from exc

    try:
        if len(data) > 64 * 1024:
            raise ValueError("Telegram response too large")
        result = json.loads(data)
        message_id = result["result"]["message_id"]
        if result.get("ok") is not True or type(message_id) is not int or message_id <= 0:
            raise ValueError("Missing Telegram confirmation")
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise TelegramError("telegram-invalid-response", "Telegram не вернул подтверждение с ID сообщения.") from exc
    return message_id
