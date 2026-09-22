"""Batches queued events to SENTINEL-X and sends heartbeats.

Detection never waits on the network: :meth:`Forwarder.submit` only maps the
object and writes it to the local queue. A background thread sends batches every
``flush_interval_seconds`` (sooner once ``batch_size`` events are waiting), backs
off exponentially while the server is unreachable, and deletes events only after
a 2xx response. A second thread queues a heartbeat every 60 seconds.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable

from aegis.forwarding.agent import AgentInfo
from aegis.forwarding.queue import EventQueue
from aegis.forwarding.schema import Heartbeat, to_shared_event
from aegis.forwarding.sender import Backoff, Sender
from aegis.posture.base import PostureReport

log = logging.getLogger(__name__)

HEARTBEAT_SECONDS = 60.0


class Forwarder:
    def __init__(self, sender: Sender, queue: EventQueue, agent: AgentInfo, *,
                 batch_size: int = 50, flush_interval: float = 10.0,
                 heartbeat_interval: float = HEARTBEAT_SECONDS,
                 posture_provider: Callable[[], PostureReport | None] | None = None,
                 backoff: Backoff | None = None):
        self.sender = sender
        self.queue = queue
        self.agent = agent
        self.batch_size = max(1, batch_size)
        self.flush_interval = max(0.1, flush_interval)
        self.heartbeat_interval = heartbeat_interval
        self.posture_provider = posture_provider
        self.backoff = backoff or Backoff()

        self._stop = threading.Event()
        self._wake = threading.Event()
        self._threads: list[threading.Thread] = []
        self._flush_lock = threading.Lock()
        #: Delivery statistics, for status output and tests.
        self.sent = 0
        self.failed_attempts = 0
        self.last_status: int | None = None

    # -- producing ---------------------------------------------------------- #
    def submit(self, item, **mapping_options) -> None:
        """Map ``item`` to the shared schema and queue it. Never raises."""
        try:
            self.queue.put(to_shared_event(item, self.agent, **mapping_options))
        except Exception:  # noqa: BLE001 - forwarding must never break detection
            log.exception("Could not queue %s for forwarding", type(item).__name__)
            return
        if len(self.queue) >= self.batch_size:
            self._wake.set()

    def heartbeat(self) -> None:
        posture = self.posture_provider() if self.posture_provider else None
        self.submit(Heartbeat(posture=posture))

    # -- delivering --------------------------------------------------------- #
    def flush_once(self) -> bool:
        """Send the oldest batch. True if it was delivered or nothing was queued."""
        with self._flush_lock:
            rows = self.queue.peek(self.batch_size)
            if not rows:
                return True
            result = self.sender.send([payload for _, payload in rows])
            self.last_status = result.status
            if result.ok:
                self.queue.delete([row_id for row_id, _ in rows])
                self.sent += len(rows)
                self.backoff.reset()
                return True

            self.failed_attempts += 1
            if result.status == 413 and self.batch_size > 1:
                self.batch_size = max(1, self.batch_size // 2)
                log.warning("SENTINEL-X rejected the batch as too large; batch size now %d.",
                            self.batch_size)
            elif result.status in (401, 403):
                log.error("SENTINEL-X refused the API key (HTTP %s); events stay queued.",
                          result.status)
            else:
                log.warning("Forwarding to %s failed (%s); %d event(s) stay queued.",
                            self.sender.url, result.status or result.error, len(self.queue))
            return False

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            if self.flush_once():
                if len(self.queue) >= self.batch_size:
                    continue                      # a backlog: keep sending
                self._wake.wait(self.flush_interval)
                self._wake.clear()
            else:
                self._stop.wait(self.backoff.next_delay())

    def _heartbeat_loop(self) -> None:
        self.heartbeat()
        while not self._stop.wait(self.heartbeat_interval):
            self.heartbeat()

    # -- lifecycle ---------------------------------------------------------- #
    @property
    def running(self) -> bool:
        return bool(self._threads)

    def start(self) -> None:
        if self._threads:
            return
        self._stop.clear()
        for target, name in ((self._flush_loop, "forwarder-flush"),
                             (self._heartbeat_loop, "forwarder-heartbeat")):
            thread = threading.Thread(target=target, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
        log.info("Forwarding to %s started (%d event(s) queued).", self.sender.url,
                 len(self.queue))

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the threads, try one last delivery, and close the queue."""
        self._stop.set()
        self._wake.set()
        for thread in self._threads:
            thread.join(timeout=timeout)
        self._threads.clear()
        try:
            self.flush_once()
        except Exception:  # noqa: BLE001 - best effort on shutdown
            log.debug("Final forwarding flush failed", exc_info=True)
        self.queue.close()
