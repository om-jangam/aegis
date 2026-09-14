"""Reproducible evaluation of the ML anomaly assist.

Builds a *labeled* scenario (normal vs malicious connections), trains the
IsolationForest on normal traffic only (unsupervised), and measures precision /
recall / F1 on a held-out mixed set. Run:

    python evaluation/evaluate_ml.py

The printed metrics are what back the honesty of the "AI assist" claim — see
docs/ML_EVALUATION.md.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from aegis.core.events import Direction, EventSource, EventType, NetworkEvent
from aegis.detection.ml_assist import feature_vector

RNG = np.random.default_rng(42)

COMMON_PORTS = [80, 443, 443, 443, 53, 22, 993, 587, 8080]
C2_PORTS = [4444, 5555, 31337, 1337, 9001, 6667, 12345]
NORMAL_PROCS = ["chrome.exe", "firefox.exe", "svchost.exe", "Spotify.exe", "Teams.exe"]
MAL_PROCS = ["rundll32.exe", "powershell.exe", "evil.exe", "svch0st.exe", "x.exe"]


def _event(remote_ip, port, proc, proto="TCP"):
    return NetworkEvent(
        type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
        pid=1234, process_name=proc, protocol=proto,
        remote_ip=remote_ip, remote_port=port, direction=Direction.OUTBOUND)


def gen_normal(n: int):
    out = []
    for _ in range(n):
        port = int(RNG.choice(COMMON_PORTS))
        # mostly public web/DNS, some private LAN
        if RNG.random() < 0.3:
            ip = f"192.168.1.{RNG.integers(2, 254)}"
        else:
            ip = f"140.82.{RNG.integers(0, 255)}.{RNG.integers(1, 254)}"
        out.append(_event(ip, port, str(RNG.choice(NORMAL_PROCS))))
    return out


def gen_malicious(n: int):
    out = []
    for _ in range(n):
        r = RNG.random()
        if r < 0.5:                         # C2 default ports
            port = int(RNG.choice(C2_PORTS))
        elif r < 0.8:                       # uncommon high ports
            port = int(RNG.integers(20000, 65000))
        else:                               # odd low port
            port = int(RNG.integers(1, 1024))
        ip = f"45.9.{RNG.integers(0, 255)}.{RNG.integers(1, 254)}"
        out.append(_event(ip, port, str(RNG.choice(MAL_PROCS))))
    return out


def evaluate(contamination: float, train_normal, test, y_true):
    Xtr = np.array([feature_vector(e) for e in train_normal])
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(Xtr)
    Xte = np.array([feature_vector(e) for e in test])
    y_pred = (model.predict(Xte) == -1).astype(int)

    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(y_true)
    return dict(contamination=contamination, precision=precision, recall=recall,
                f1=f1, accuracy=accuracy, fpr=fpr, tp=tp, fp=fp, tn=tn, fn=fn)


def main():
    train_normal = gen_normal(800)                       # train on NORMAL only
    test = gen_normal(200) + gen_malicious(200)          # labeled held-out set
    y_true = np.array([0] * 200 + [1] * 200)

    print("=== ML Anomaly Assist - Evaluation ===")
    print("Train: 800 normal | Test: 200 normal + 200 malicious (unsupervised)")
    print()

    default = evaluate(0.05, train_normal, test, y_true)   # the shipped setting
    print("Default (contamination=0.05) confusion matrix:")
    print("                 pred normal   pred malicious")
    print(f"  true normal        {default['tn']:4d}          {default['fp']:4d}")
    print(f"  true malicious     {default['fn']:4d}          {default['tp']:4d}")
    print()
    print(f"  Precision {default['precision']:.3f} | Recall {default['recall']:.3f} | "
          f"F1 {default['f1']:.3f} | FPR {default['fpr']:.3f}")
    print()

    print("Precision/recall tradeoff vs contamination:")
    print("  contam   precision   recall     F1     FPR")
    results = []
    for c in (0.02, 0.05, 0.10, 0.15, 0.20):
        m = evaluate(c, train_normal, test, y_true)
        results.append(m)
        print(f"   {c:.2f}      {m['precision']:.3f}     {m['recall']:.3f}   "
              f"{m['f1']:.3f}   {m['fpr']:.3f}")
    return default, results


if __name__ == "__main__":
    main()
