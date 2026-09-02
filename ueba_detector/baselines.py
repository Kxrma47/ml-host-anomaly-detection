from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .autoencoder import NeuralAutoencoder
from .combined import parse_timestamp
from .features import FEATURE_NAMES


def select_clean_training_rows(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Exclude explicitly labeled attacks from baseline training data."""
    labeled = any(row.get("scenario") is not None for row in rows)
    selected = [row for row in rows if not labeled or row.get("scenario") == "normal"]
    if not selected:
        raise ValueError("no normal rows remain after labeled-attack exclusion")
    return selected, {
        "input_rows": len(rows),
        "selected_rows": len(selected),
        "excluded_labeled_attacks": len(rows) - len(selected),
    }


def _quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * q))))
    return ordered[index]


def _median(values: list[float]) -> float:
    return _quantile(values, 0.5)


@dataclass
class RobustZScoreDetector:
    feature_names: list[str]
    medians: list[float]
    scales: list[float]
    threshold: float = 1.0

    @classmethod
    def fit(
        cls,
        rows: list[dict[str, Any]],
        feature_names: list[str] | None = None,
    ) -> "RobustZScoreDetector":
        if not rows:
            raise ValueError("need at least one training row")
        names = list(feature_names or FEATURE_NAMES)
        medians: list[float] = []
        scales: list[float] = []
        for name in names:
            values = [float(row.get(name, 0.0) or 0.0) for row in rows]
            median = _median(values)
            mad = _median([abs(value - median) for value in values])
            medians.append(median)
            scales.append(max(mad * 1.4826, abs(median) * 0.01, 1e-6))
        return cls(names, medians, scales)

    def raw_score(self, row: dict[str, Any]) -> float:
        scores = [
            abs(float(row.get(name, 0.0) or 0.0) - median) / scale
            for name, median, scale in zip(self.feature_names, self.medians, self.scales)
        ]
        top = sorted(scores, reverse=True)[: max(1, min(3, len(scores)))]
        return sum(top) / len(top)

    def calibrate(self, rows: list[dict[str, Any]], *, quantile: float = 0.995) -> float:
        if not rows:
            raise ValueError("need calibration rows")
        self.threshold = max(_quantile([self.raw_score(row) for row in rows], quantile), 1e-9)
        return self.threshold

    def predict(self, row: dict[str, Any]) -> bool:
        return self.raw_score(row) >= self.threshold


@dataclass
class EWMADetector:
    feature_names: list[str]
    mean: list[float]
    variance: list[float]
    alpha: float = 0.05
    threshold: float = 1.0

    @classmethod
    def fit(
        cls,
        rows: list[dict[str, Any]],
        feature_names: list[str] | None = None,
        *,
        alpha: float = 0.05,
    ) -> "EWMADetector":
        if not rows:
            raise ValueError("need at least one training row")
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be between zero and one")
        names = list(feature_names or FEATURE_NAMES)
        mean = [float(rows[0].get(name, 0.0) or 0.0) for name in names]
        variance = [1e-6 for _ in names]
        detector = cls(names, mean, variance, alpha=alpha)
        for row in rows[1:]:
            detector.update(row)
        return detector

    def raw_score(self, row: dict[str, Any]) -> float:
        scores = []
        for index, name in enumerate(self.feature_names):
            value = float(row.get(name, 0.0) or 0.0)
            scale = max(math.sqrt(self.variance[index]), abs(self.mean[index]) * 0.01, 1e-6)
            scores.append(abs(value - self.mean[index]) / scale)
        top = sorted(scores, reverse=True)[: max(1, min(3, len(scores)))]
        return sum(top) / len(top)

    def update(self, row: dict[str, Any]) -> None:
        for index, name in enumerate(self.feature_names):
            value = float(row.get(name, 0.0) or 0.0)
            difference = value - self.mean[index]
            self.mean[index] += self.alpha * difference
            self.variance[index] = max(
                1e-6,
                (1.0 - self.alpha) * (self.variance[index] + self.alpha * difference * difference),
            )

    def calibrate(self, rows: list[dict[str, Any]], *, quantile: float = 0.995) -> float:
        if not rows:
            raise ValueError("need calibration rows")
        scores: list[float] = []
        for row in rows:
            scores.append(self.raw_score(row))
            self.update(row)
        self.threshold = max(_quantile(scores, quantile), 1e-9)
        return self.threshold

    def predict_then_update(self, row: dict[str, Any], *, update_if_normal: bool = True) -> bool:
        anomaly = self.raw_score(row) >= self.threshold
        if not anomaly and update_if_normal:
            self.update(row)
        return anomaly


def _metrics(predictions: list[bool], labels: list[bool | None]) -> dict[str, Any]:
    labeled = [(prediction, label) for prediction, label in zip(predictions, labels) if label is not None]
    result: dict[str, Any] = {
        "windows": len(predictions),
        "anomalies": sum(predictions),
        "anomaly_rate": sum(predictions) / len(predictions) if predictions else 0.0,
        "labeled_windows": len(labeled),
    }
    if not labeled:
        return result
    tp = sum(prediction and bool(label) for prediction, label in labeled)
    fp = sum(prediction and not bool(label) for prediction, label in labeled)
    tn = sum(not prediction and not bool(label) for prediction, label in labeled)
    fn = sum(not prediction and bool(label) for prediction, label in labeled)
    result.update(
        {
            "positive_windows": tp + fn,
            "negative_windows": fp + tn,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        }
    )
    return result


def compare_detectors(
    rows: list[dict[str, Any]],
    *,
    evaluation_rows: list[dict[str, Any]] | None = None,
    feature_names: list[str] | None = None,
    epochs: int = 80,
    threshold_quantile: float = 0.995,
    seed: int = 42,
) -> dict[str, Any]:
    if len(rows) < 20:
        raise ValueError("need at least 20 rows for model comparison")
    names = list(feature_names or FEATURE_NAMES)
    ordered = sorted(rows, key=lambda row: parse_timestamp(row.get("timestamp")))
    if evaluation_rows is None:
        train_end = int(len(ordered) * 0.70)
        validation_end = int(len(ordered) * 0.85)
        train = ordered[:train_end]
        validation = ordered[train_end:validation_end]
        test = ordered[validation_end:]
        strategy = "chronological_70_15_15"
    else:
        split = max(1, int(len(ordered) * 0.85))
        train = ordered[:split]
        validation = ordered[split:]
        test = sorted(evaluation_rows, key=lambda row: parse_timestamp(row.get("timestamp")))
        strategy = "external_holdout"
    train_normal, train_selection = select_clean_training_rows(train)
    validation_normal, validation_selection = select_clean_training_rows(validation)

    neural = NeuralAutoencoder.fit(
        train_normal,
        feature_names=names,
        epochs=epochs,
        threshold_quantile=threshold_quantile,
        seed=seed,
    )
    neural.calibrate_threshold(validation_normal, quantile=threshold_quantile)
    robust = RobustZScoreDetector.fit(train_normal, names)
    robust.calibrate(validation_normal, quantile=threshold_quantile)
    ewma = EWMADetector.fit(train_normal, names)
    ewma.calibrate(validation_normal, quantile=threshold_quantile)

    labels = [
        (row.get("scenario") != "normal") if row.get("scenario") is not None else None
        for row in test
    ]
    predictions = {
        "autoencoder": [neural.score(row).is_anomaly for row in test],
        "robust_zscore": [robust.predict(row) for row in test],
        "ewma": [ewma.predict_then_update(row) for row in test],
    }
    return {
        "split": {"strategy": strategy, "train": len(train), "validation": len(validation), "test": len(test)},
        "poisoning_guard": {
            "label_field": "scenario",
            "normal_label": "normal",
            "train": train_selection,
            "validation": validation_selection,
        },
        "features": names,
        "threshold_quantile": threshold_quantile,
        "thresholds": {
            "autoencoder": neural.threshold,
            "robust_zscore": robust.threshold,
            "ewma": ewma.threshold,
        },
        "methods": {name: _metrics(values, labels) for name, values in predictions.items()},
    }
