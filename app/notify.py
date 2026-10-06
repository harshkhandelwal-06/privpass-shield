"""Notifications: in-app bell + optional webhook forwarding (Slack / Teams / Discord compatible).

Set ALERT_WEBHOOK_URL in .env to forward HIGH/CRITICAL alerts. Payloads contain titles and counts
only - never secrets, passwords or emails of test accounts.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.request

from .models import Notification
from .security import uid

SEVERITY_ICON = {"CRITICAL": "🚨", "HIGH": "⚠️", "WARN": "⚠️", "INFO": "ℹ️"}


def _forward(title: str, body: str, severity: str) -> None:
    url = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
    if not url or not url.startswith("https://") or severity not in {"CRITICAL", "HIGH"}:
        return
    text = f"{SEVERITY_ICON.get(severity, '')} *PrivPass Shield — {title}*\n{body}"
    payload = json.dumps({"text": text, "content": text}).encode()   # Slack/Teams use "text", Discord uses "content"

    def send():
        try:
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=5).close()  # nosec B310 - https-only operator-configured webhook
        except Exception:
            pass
    threading.Thread(target=send, daemon=True).start()


def notify(session, kind: str, title: str, body: str = "", severity: str = "INFO", link: str = "", user_id: str | None = None) -> None:
    """user_id=None broadcasts to admins/analysts; otherwise only that user sees it."""
    from .db import current_workspace
    session.add(Notification(id=uid(), user_id=user_id, kind=kind, severity=severity, title=title[:200], body=body[:2000], link=link))
    if current_workspace.get() != "demo":  # demo activity never reaches the real Slack/Teams channel
        _forward(title, body, severity)
