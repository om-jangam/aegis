# ML Anomaly Assist — Evaluation

> **Design stance: rules lead, ML assists.** The rule engine (ATT&CK-mapped,
> explainable) is the primary detection layer. The IsolationForest model is a
> *secondary* signal for statistical outliers no single rule anticipated. This
> document measures it honestly, rather than asserting it "uses AI".
>
> Reproduce: `python evaluation/evaluate_ml.py`

## Method

- **Model:** `IsolationForest` (100 trees), trained **unsupervised on normal
  traffic only** — it learns the host's baseline, with no malicious labels.
- **Features** (identical in training, evaluation and live scoring): remote port,
  port bucket, TCP flag, private-vs-public peer, common-port flag, process-name
  length.
- **Dataset:** a labeled synthetic scenario (seed = 42): 800 normal connections
  for training; a held-out test set of **200 normal + 200 malicious**. Malicious
  traffic = C2 default ports (4444, 31337, …), uncommon high ports, and odd low
  ports to public hosts.

## Results (shipped setting: contamination = 0.05)

Confusion matrix:

|                | predicted normal | predicted malicious |
|----------------|:---------------:|:-------------------:|
| **true normal**    | 191 (TN)        | 9 (FP)              |
| **true malicious** | 154 (FN)        | 46 (TP)             |

| Metric | Value |
|--------|------:|
| Precision | **0.836** |
| Recall | 0.230 |
| F1 | 0.361 |
| False-positive rate | **0.045** |
| Accuracy | 0.593 |

## Precision / recall tradeoff (contamination sweep)

| contamination | precision | recall | F1 | FPR |
|:---:|:---:|:---:|:---:|:---:|
| 0.02 | 0.000 | 0.000 | 0.000 | 0.000 |
| **0.05 (shipped)** | **0.836** | 0.230 | 0.361 | **0.045** |
| 0.10 | 0.747 | 0.325 | 0.453 | 0.110 |
| 0.15 | 0.642 | 0.350 | 0.453 | 0.195 |
| 0.20 | 0.582 | 0.355 | 0.441 | 0.255 |

## Honest interpretation

- **The assist is deliberately tuned for high precision and a low false-positive
  rate (4.5%), not high recall.** When it fires, it's usually right (84%); it
  simply stays quiet on the ~77% of malicious cases that look statistically close
  to normal in this feature space.
- **This is the correct posture for a *secondary* signal.** A noisy anomaly model
  that cried wolf would erode trust; a quiet, precise one adds value without
  spamming. Recall is provided by the **rule engine**, which catches C2 ports,
  lateral-movement services, interpreters-on-the-network, scanning, etc. by
  design — not by statistics.
- The sweep shows the expected tradeoff: raising `contamination` lifts recall but
  worsens precision and FPR. 0.05 is chosen to keep FPR low.

## Limitations & where this goes next

- Evaluated on a **synthetic** scenario for reproducibility; real-world traffic is
  messier. The numbers illustrate *behavior and tradeoffs*, not a production SLA.
- The feature set is intentionally small/interpretable. Richer features (bytes
  transferred, connection timing/periodicity for beaconing, JA3/TLS fingerprints)
  and higher-fidelity telemetry (Sysmon/ETW) would improve recall — future work.
- In the app, the assist's severity is **capped at MEDIUM** so it can never
  override an explainable rule finding.
