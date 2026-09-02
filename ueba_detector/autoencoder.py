from __future__ import annotations

import json
import math
import platform
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .features import FEATURE_NAMES, Scaler, fit_scaler


@dataclass
class Score:
    error: float
    threshold: float
    ratio: float
    is_anomaly: bool
    severity: str
    top_features: list[dict[str, float]]


class NeuralAutoencoder:
    def __init__(
        self,
        *,
        scaler: Scaler,
        hidden_dim: int,
        w1: list[list[float]],
        b1: list[float],
        w2: list[list[float]],
        b2: list[float],
        threshold: float,
        train_errors: list[float] | None = None,
    ) -> None:
        self.scaler = scaler
        self.hidden_dim = hidden_dim
        self.w1 = w1
        self.b1 = b1
        self.w2 = w2
        self.b2 = b2
        self.threshold = threshold
        self.train_errors = train_errors or []

    @staticmethod
    def _init_weights(rng: random.Random, rows: int, cols: int) -> list[list[float]]:
        scale = 1.0 / math.sqrt(max(1, cols))
        return [[rng.uniform(-scale, scale) for _ in range(cols)] for _ in range(rows)]

    @staticmethod
    def _quantile(values: list[float], q: float) -> float:
        if not values:
            return 0.0
        ordered = sorted(values)
        idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
        return ordered[idx]

    @classmethod
    def fit(
        cls,
        samples: list[dict[str, Any]],
        *,
        feature_names: list[str] | None = None,
        hidden_dim: int | None = None,
        epochs: int = 220,
        learning_rate: float = 0.015,
        threshold_quantile: float = 0.995,
        seed: int = 42,
    ) -> "NeuralAutoencoder":
        if not samples:
            raise ValueError("Need at least one training sample")

        names = list(feature_names or FEATURE_NAMES)
        if not names or len(names) != len(set(names)):
            raise ValueError("feature_names must be a non-empty list of unique names")
        scaler = fit_scaler(samples, names)
        x_train = [scaler.transform(sample) for sample in samples]
        input_dim = len(scaler.feature_names)
        hidden = hidden_dim or max(3, min(12, input_dim // 2))
        rng = random.Random(seed)

        w1 = cls._init_weights(rng, hidden, input_dim)
        b1 = [0.0 for _ in range(hidden)]
        w2 = cls._init_weights(rng, input_dim, hidden)
        b2 = [0.0 for _ in range(input_dim)]
        model = cls(scaler=scaler, hidden_dim=hidden, w1=w1, b1=b1, w2=w2, b2=b2, threshold=1.0)

        order = list(range(len(x_train)))
        for epoch in range(max(1, epochs)):
            rng.shuffle(order)
            lr = learning_rate / (1.0 + epoch / max(1, epochs))
            for idx in order:
                model._train_one(x_train[idx], lr)

        errors = [model._error(x) for x in x_train]
        mean_error = sum(errors) / len(errors)
        variance = sum((err - mean_error) ** 2 for err in errors) / len(errors)
        threshold = max(cls._quantile(errors, threshold_quantile), mean_error + 3.0 * math.sqrt(variance), 1e-9)
        model.threshold = threshold
        model.train_errors = errors
        return model

    def _forward(self, x: list[float]) -> tuple[list[float], list[float]]:
        hidden: list[float] = []
        for j in range(self.hidden_dim):
            z = self.b1[j] + sum(self.w1[j][i] * x[i] for i in range(len(x)))
            hidden.append(math.tanh(z))

        out: list[float] = []
        for i in range(len(x)):
            value = self.b2[i] + sum(self.w2[i][j] * hidden[j] for j in range(self.hidden_dim))
            out.append(value)
        return hidden, out

    def _train_one(self, x: list[float], lr: float) -> None:
        hidden, out = self._forward(x)
        delta_out = [out[i] - x[i] for i in range(len(x))]

        delta_hidden: list[float] = []
        for j in range(self.hidden_dim):
            grad = sum(delta_out[i] * self.w2[i][j] for i in range(len(x)))
            delta_hidden.append(grad * (1.0 - hidden[j] ** 2))

        for i in range(len(x)):
            for j in range(self.hidden_dim):
                self.w2[i][j] -= lr * delta_out[i] * hidden[j]
            self.b2[i] -= lr * delta_out[i]

        for j in range(self.hidden_dim):
            for i in range(len(x)):
                self.w1[j][i] -= lr * delta_hidden[j] * x[i]
            self.b1[j] -= lr * delta_hidden[j]

    def _error(self, x: list[float]) -> float:
        _, out = self._forward(x)
        return sum((out[i] - x[i]) ** 2 for i in range(len(x))) / len(x)

    def score(self, sample: dict[str, Any]) -> Score:
        x = self.scaler.transform(sample)
        _, out = self._forward(x)
        contributions = [(self.scaler.feature_names[i], (out[i] - x[i]) ** 2) for i in range(len(x))]
        error = sum(value for _, value in contributions) / len(contributions)
        threshold = max(self.threshold, 1e-9)
        ratio = error / threshold
        top_features = [
            {"feature": name, "contribution": value}
            for name, value in sorted(contributions, key=lambda item: item[1], reverse=True)[:5]
        ]

        if ratio >= 5.0:
            severity = "critical"
        elif ratio >= 2.5:
            severity = "high"
        elif ratio >= 1.0:
            severity = "medium"
        else:
            severity = "normal"

        return Score(
            error=error,
            threshold=threshold,
            ratio=ratio,
            is_anomaly=ratio >= 1.0,
            severity=severity,
            top_features=top_features,
        )

    def reconstruction_error(self, sample: dict[str, Any]) -> float:
        return self._error(self.scaler.transform(sample))

    def calibrate_threshold(
        self,
        samples: list[dict[str, Any]],
        *,
        quantile: float = 0.995,
    ) -> float:
        if not samples:
            raise ValueError("Need at least one calibration sample")
        if not 0.0 <= quantile <= 1.0:
            raise ValueError("quantile must be between 0 and 1")
        errors = [self.reconstruction_error(sample) for sample in samples]
        mean_error = sum(errors) / len(errors)
        variance = sum((error - mean_error) ** 2 for error in errors) / len(errors)
        self.threshold = max(
            self._quantile(errors, quantile),
            mean_error + 3.0 * math.sqrt(variance),
            1e-9,
        )
        return self.threshold

    def save(self, path: str | Path, *, provenance: dict[str, Any] | None = None) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "feature_names": self.scaler.feature_names,
            "mean": self.scaler.mean,
            "std": self.scaler.std,
            "hidden_dim": self.hidden_dim,
            "w1": self.w1,
            "b1": self.b1,
            "w2": self.w2,
            "b2": self.b2,
            "threshold": self.threshold,
            "train_errors": self.train_errors,
            "artifact": {
                "schema_version": "1.0.0",
                "created_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                "package_version": __version__,
                "python_version": platform.python_version(),
                "feature_count": len(self.scaler.feature_names),
                "training_samples": len(self.train_errors),
                "provenance": provenance or {},
            },
        }
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "NeuralAutoencoder":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        scaler = Scaler(
            feature_names=list(payload["feature_names"]),
            mean=list(payload["mean"]),
            std=list(payload["std"]),
        )
        return cls(
            scaler=scaler,
            hidden_dim=int(payload["hidden_dim"]),
            w1=payload["w1"],
            b1=payload["b1"],
            w2=payload["w2"],
            b2=payload["b2"],
            threshold=float(payload["threshold"]),
            train_errors=list(payload.get("train_errors", [])),
        )
