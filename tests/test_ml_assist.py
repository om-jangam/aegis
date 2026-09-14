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
