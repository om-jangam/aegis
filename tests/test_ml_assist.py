"""Tests for the ML anomaly assist (feature stability, train, score, cap)."""
from aegis.core.events import Direction, EventSource, EventType, NetworkEvent
from aegis.core.models import Severity
from aegis.detection.ml_assist import MLAssist, feature_vector


def _net(ip="8.8.8.8", port=443, proc="chrome.exe"):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
                        pid=1, process_name=proc, protocol="TCP",
                        remote_ip=ip, remote_port=port, direction=Direction.OUTBOUND)


def test_feature_vector_stable_length():
    assert len(feature_vector(_net())) == 6
    assert len(feature_vector(_net("192.168.1.2", 4444))) == 6


def test_untrained_model_scores_nothing(tmp_path):
    ml = MLAssist(model_path=tmp_path / "m.joblib")
    assert ml.trained is False
    assert ml.score(_net(port=4444)) is None


def test_train_and_score(tmp_path):
    ml = MLAssist(model_path=tmp_path / "m.joblib")
    # feed a baseline of normal-looking connections
    for i in range(120):
        ml._buffer.append(feature_vector(_net(ip=f"140.82.0.{i % 254}", port=443)))
    assert ml.train() is True
    assert ml.trained is True
    # an outlier should be scorable; severity capped at MEDIUM
    finding = ml.score(_net(ip="45.9.1.1", port=54321, proc="x.exe"))
    if finding is not None:
        assert finding.rule_id == "ML-ANOMALY"
        assert finding.severity.rank <= Severity.MEDIUM.rank
        assert finding.technique == ""       # honest: no ATT&CK claim


def test_train_refuses_with_too_few_samples(tmp_path):
    ml = MLAssist(model_path=tmp_path / "m.joblib")
    ml._buffer.append(feature_vector(_net()))
    assert ml.train() is False


# --- background model loading ----------------------------------------------
# Deserialising the model imports scikit-learn, which took ~15s on a cold start
# and blocked the whole service (and the UI behind it) before a single event
# could be collected. These guard that regression.
def test_construction_does_not_block_on_model_load(tmp_path):
    import time

    ml = MLAssist(model_path=tmp_path / "m.joblib")
    for i in range(120):
        ml._buffer.append(feature_vector(_net(ip=f"140.82.0.{i % 254}", port=443)))
    ml.train()
    ml.save()
    assert (tmp_path / "m.joblib").exists()

    start = time.perf_counter()
    reloaded = MLAssist(model_path=tmp_path / "m.joblib")
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"constructor blocked for {elapsed:.2f}s on model load"

    assert reloaded.wait_until_ready(timeout=60), "background load never finished"
    assert reloaded.trained is True, "the saved model must still be loaded"


def test_synchronous_load_is_available_for_determinism(tmp_path):
    ml = MLAssist(model_path=tmp_path / "m.joblib")
    for i in range(120):
        ml._buffer.append(feature_vector(_net(ip=f"140.82.0.{i % 254}", port=443)))
    ml.train()
    ml.save()

    reloaded = MLAssist(model_path=tmp_path / "m.joblib", load_async=False)
    assert reloaded.trained is True
    assert reloaded.wait_until_ready(timeout=0) is True


def test_ready_is_signalled_even_when_no_model_exists(tmp_path):
    ml = MLAssist(model_path=tmp_path / "missing.joblib")
    assert ml.wait_until_ready(timeout=10), "waiters must not hang when there is no model"
    assert ml.trained is False


def test_live_training_is_not_overwritten_by_a_stale_saved_model(tmp_path):
    """A model fitted to live traffic outranks whatever was last on disk."""
    seed = MLAssist(model_path=tmp_path / "m.joblib")
    for i in range(120):
        seed._buffer.append(feature_vector(_net(ip=f"140.82.0.{i % 254}", port=443)))
    seed.train()
    seed.save()

    ml = MLAssist(model_path=tmp_path / "m.joblib", load_async=False)
    fresh = object()
    ml._model, ml._trained = fresh, True
    ml._load()                                  # a late background load landing
    assert ml._model is fresh
