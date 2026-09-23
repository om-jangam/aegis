"""Machine-learning anomaly *assist* (IsolationForest).

Design stance (see THREAT_MODEL.md): **rules lead, ML assists.** The rules are
the primary, explainable detection layer. This model is a secondary signal that
flags statistical outliers no single rule anticipated. It:

* learns the *baseline* of normal connections for this host (unsupervised),
* is deliberately capped at MEDIUM severity so it never dominates rule findings,
* is **evaluated** (precision/recall) on a labeled scenario — see
  ``evaluation/evaluate_ml.py`` and ``docs/ML_EVALUATION.md`` — so its value is
  measured, not assumed,
* fails safe: any error disables the assist rather than breaking detection.

The feature function is module-level so the training/evaluation harness and the
live scorer use exactly the same representation.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import warnings
from collections import deque

from aegis.config import MODEL_PATH, settings
from aegis.core.events import Event, EventType, NetworkEvent
from aegis.core.models import Finding, Severity
from aegis.detection.ports import COMMON_PORTS as _COMMON_PORTS

log = logging.getLogger(__name__)


def _port_bucket(port: int) -> int:
    if port <= 0:
        return 0
    if port < 1024:
        return 1
    if port < 49152:
        return 2
    return 3


def feature_vector(event: NetworkEvent) -> list[float]:
    """Numeric representation of a network event for the model."""
    try:
        is_private = float(ipaddress.ip_address(event.remote_ip).is_private) \
            if event.remote_ip else 1.0
    except ValueError:
        is_private = 1.0
    return [
        float(event.remote_port),
        float(_port_bucket(event.remote_port)),
        float(event.protocol == "TCP"),
        is_private,
        float(event.remote_port in _COMMON_PORTS),
        float(len(event.process_name)),
    ]


class MLAssist:
    MIN_SAMPLES = 50

    def __init__(self, model_path=MODEL_PATH, load_async: bool = True):
        self._model_path = model_path
        self._buffer: deque[list[float]] = deque(maxlen=3000)
        self._model = None
        self._trained = False
        self._lock = threading.RLock()
        self._ready = threading.Event()
        # Deserialising the model drags in scikit-learn, which costs seconds on a
        # cold start. Blocking the constructor on that delayed the whole service
        # — and the UI behind it — before a single event could be collected.
        # Loading off-thread is safe precisely because rules lead and ML assists:
        # until the model arrives, score() simply returns None and the rule
        # engine carries detection on its own.
        if load_async:
            threading.Thread(target=self._load_and_signal,
                             name="ml-model-load", daemon=True).start()
        else:
            self._load_and_signal()

    def wait_until_ready(self, timeout: float | None = None) -> bool:
        """Block until the saved model has finished loading (or failed to).

        Only needed by tests and the evaluation harness; live detection never
        waits, it just starts scoring once the model is present.
        """
        return self._ready.wait(timeout)

    # -- learning ----------------------------------------------------------- #
    def observe(self, event: Event) -> None:
        if not (settings.auto_learn and settings.anomaly_detection_enabled):
            return
        if isinstance(event, NetworkEvent) and event.type == EventType.NETWORK_CONNECTION:
            with self._lock:
                self._buffer.append(feature_vector(event))

    def train(self) -> bool:
        if not settings.anomaly_detection_enabled:
            return False
        with self._lock:
            if len(self._buffer) < self.MIN_SAMPLES:
                return False
            try:
                import numpy as np
                from sklearn.ensemble import IsolationForest
                X = np.array(self._buffer, dtype=float)
                model = IsolationForest(n_estimators=100, contamination=0.05,
                                        random_state=42)
                model.fit(X)
                self._model = model
                self._trained = True
                log.info("Anomaly model trained on %d samples.", len(X))
                return True
            except Exception:  # noqa: BLE001
                log.exception("Anomaly model training failed")
                return False

    def maybe_train(self) -> bool:
        if not self._trained:
            return self.train()
        return False

    # -- scoring ------------------------------------------------------------ #
    def score(self, event: Event) -> Finding | None:
        if not settings.anomaly_detection_enabled:
            return None
        if not isinstance(event, NetworkEvent) or event.type != EventType.NETWORK_CONNECTION:
            return None
        if event.remote_ip in settings.trusted_remote_ips:
            return None
        # Snapshot the model reference under the lock so a concurrent retrain
        # (which replaces self._model) can't be seen half-updated here.
        with self._lock:
            model = self._model if self._trained else None
        if model is None:
            return None
        try:
            import numpy as np
            raw = float(model.decision_function(
                np.array([feature_vector(event)], dtype=float))[0])
        except Exception:  # noqa: BLE001
            return None
        if raw >= -0.05:
            return None
        # More negative => more anomalous. Cap the assist at MEDIUM.
        score = int(min(55, abs(raw) * 120))
        severity = Severity.MEDIUM if score >= 40 else Severity.LOW
        return Finding(
            rule_id="ML-ANOMALY",
            title="Anomalous connection (ML assist)",
            severity=severity,
            score=score,
            technique="",              # honest: no ATT&CK claim for an anomaly
            tactic="",
            description="Statistical outlier vs the learned baseline of normal traffic.",
            reasons=[f"Anomaly score {raw:.3f}",
                     f"{event.process_name} → {event.remote_ip}:{event.remote_port}"],
            entity=f"{event.remote_ip}:{event.remote_port}",
            source_summary=event.summary())

    # -- persistence -------------------------------------------------------- #
    def save(self) -> None:
        # Snapshot the model under the lock so we don't dump a model that a
        # concurrent train() is halfway through replacing.
        with self._lock:
            if not self._trained:
                return
            model = self._model
        try:
            import joblib
            joblib.dump(model, self._model_path)
        except Exception:  # noqa: BLE001
            log.exception("Could not persist anomaly model")

    def _load_and_signal(self) -> None:
        try:
            self._load()
        finally:
            # Signalled even on failure: waiters care that loading is *finished*,
            # not that it succeeded. A failed load simply leaves the assist idle.
            self._ready.set()

    def _load(self) -> None:
        try:
            import joblib
            from sklearn.exceptions import InconsistentVersionWarning

            if not self._model_path.exists():
                return
            # A model pickled by another scikit-learn version may behave subtly
            # differently, and scoring connections with it would be guesswork.
            # Better to drop it and learn this computer again from scratch.
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", InconsistentVersionWarning)
                model = joblib.load(self._model_path)
            if any(issubclass(w.category, InconsistentVersionWarning) for w in caught):
                log.info("The saved anomaly model was built by a different scikit-learn "
                         "version; learning this computer again instead.")
                self._model_path.unlink(missing_ok=True)
                return
            with self._lock:
                # Training can finish first on a busy host; a stale model from
                # disk must not overwrite one just fitted to live traffic.
                if self._trained:
                    return
                self._model = model
                self._trained = True
            log.info("Loaded anomaly model from %s", self._model_path)
        except Exception:  # noqa: BLE001
            log.exception("Could not load anomaly model; starting fresh")
            with self._lock:
                if not self._trained:
                    self._model, self._trained = None, False

    @property
    def trained(self) -> bool:
        return self._trained
