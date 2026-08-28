"""Internal pub/sub event bus.

The orchestrator publishes scan lifecycle events here; terminal output, the future WebSocket
bridge, and any other consumer subscribe. Handlers are awaited in registration order and a failing
handler never interrupts the scan.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import structlog

from redready.engine.result import utcnow

log = structlog.get_logger(__name__)

EventHandler = Callable[["Event"], Awaitable[None] | None]

MODULE_STARTED = "module_started"
MODULE_COMPLETED = "module_completed"
MODULE_FAILED = "module_failed"
MODULE_SKIPPED = "module_skipped"
FINDING = "finding"
SCAN_STARTED = "scan_started"
SCAN_COMPLETED = "scan_completed"


@dataclass
class Event:
    type: str
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: utcnow().isoformat())


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = {}
        self._wildcard: list[EventHandler] = []

    def subscribe(self, event_type: str | None, handler: EventHandler) -> None:
        """Subscribe to one event type, or to every event when ``event_type`` is ``None``."""
        if event_type is None:
            self._wildcard.append(handler)
        else:
            self._handlers.setdefault(event_type, []).append(handler)

    async def publish(self, event_type: str, **payload: Any) -> Event:
        event = Event(type=event_type, payload=payload)
        for handler in [*self._handlers.get(event_type, []), *self._wildcard]:
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:  # noqa: BLE001 - a bad subscriber must not kill the scan
                log.warning("event_handler_failed", event_name=event_type, error=str(exc))
        return event
