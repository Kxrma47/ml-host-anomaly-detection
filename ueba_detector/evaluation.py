from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .autoencoder import NeuralAutoencoder
from .combined import (
    COMBINED_FEATURE_NAMES,
    DEFAULT_RULE_THRESHOLDS,
    evaluate_security_rules,
    parse_timestamp,
    score_combined_sample,
)
from .storage import write_jsonl


RULE_VALUE_GETTERS: dict[str, Callable[[dict[str, Any]], int]] = {
    "authentication_failure_burst": lambda row: int(
        row.get("event_authentication_failure_count", 0) or 0
    ),
    "package_change_burst": lambda row: sum(
        int(row.get(name, 0) or 0)
        for name in (
            "event_package_installed_count",
            "event_package_removed_count",
            "event_package_updated_count",
        )
    ),
    "process_start_burst": lambda row: int(row.get("event_process_started_count", 0) or 0),
    "privilege_elevation_burst": lambda row: int(
        row.get("event_privilege_elevation_count", 0) or 0
    ),
}


def _quantile(values: list[int | float], value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(item) for item in values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * value))))
    return ordered[index]


def calibrate_rule_thresholds(
    rows: list[dict[str, Any]],
    *,
    quantile: float = 0.995,
) -> dict[str, Any]:
    if not rows:
        raise ValueError("Need at least one row for rule calibration")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between 0 and 1")

    thresholds: dict[str, int] = {}
    statistics: dict[str, dict[str, Any]] = {}
    for rule_id, getter in RULE_VALUE_GETTERS.items():
        values = [max(0, getter(row)) for row in rows]
        default = DEFAULT_RULE_THRESHOLDS[rule_id]
        calibrated = max(default, int(math.floor(_quantile(values, quantile))) + 1)
        thresholds[rule_id] = calibrated
        statistics[rule_id] = {
            "default_threshold": default,
            "calibrated_threshold": calibrated,
            "p50": _quantile(values, 0.50),
            "p95": _quantile(values, 0.95),
            "p99": _quantile(values, 0.99),
            "calibration_quantile": _quantile(values, quantile),
            "maximum": max(values),
            "default_exceedance_ratio": sum(value >= default for value in values) / len(values),
            "calibrated_exceedance_ratio": sum(value >= calibrated for value in values) / len(values),
        }
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_windows": len(rows),
        "quantile": quantile,
        "thresholds": thresholds,
        "statistics": statistics,
    }


def save_rule_configuration(path: str | Path, configuration: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(configuration, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_rule_thresholds(path: str | Path) -> dict[str, int]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    raw = payload.get("thresholds", payload)
    if not isinstance(raw, dict):
        raise ValueError("Rule configuration must contain a thresholds object")
    thresholds = {**DEFAULT_RULE_THRESHOLDS}
    for rule_id in DEFAULT_RULE_THRESHOLDS:
        if rule_id in raw:
            thresholds[rule_id] = max(1, int(raw[rule_id]))
    return thresholds


def _chronological_split(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    ordered = sorted(rows, key=lambda row: (parse_timestamp(row["timestamp"]), str(row.get("host"))))
    if len(ordered) < 10:
        raise ValueError("Need at least 10 combined windows for chronological evaluation")
    validation_count = max(1, int(len(ordered) * 0.15))
    test_count = max(1, int(len(ordered) * 0.15))
    train_count = len(ordered) - validation_count - test_count
    return (
        ordered[:train_count],
        ordered[train_count : train_count + validation_count],
        ordered[train_count + validation_count :],
    )


def _method_metrics(predictions: list[bool], labels: list[bool | None]) -> dict[str, Any]:
    anomaly_count = sum(predictions)
    labeled = [(prediction, label) for prediction, label in zip(predictions, labels) if label is not None]
    result: dict[str, Any] = {
        "windows": len(predictions),
        "anomalies": anomaly_count,
        "anomaly_rate": anomaly_count / len(predictions) if predictions else 0.0,
        "labeled_windows": len(labeled),
    }
    if not labeled:
        return result
    true_positive = sum(prediction and bool(label) for prediction, label in labeled)
    false_positive = sum(prediction and not bool(label) for prediction, label in labeled)
    true_negative = sum(not prediction and not bool(label) for prediction, label in labeled)
    false_negative = sum(not prediction and bool(label) for prediction, label in labeled)
    result.update(
        {
            "true_positives": true_positive,
            "false_positives": false_positive,
            "true_negatives": true_negative,
            "false_negatives": false_negative,
            "precision": true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0,
            "recall": true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0,
            "false_positive_rate": false_positive / (false_positive + true_negative)
            if false_positive + true_negative
            else 0.0,
            "accuracy": (true_positive + true_negative) / len(labeled),
        }
    )
    return result


def _detection_delays(
    rows: list[dict[str, Any]],
    predictions: dict[str, list[bool]],
) -> dict[str, Any]:
    runs: list[tuple[int, int]] = []
    start: int | None = None
    for index, row in enumerate(rows):
        is_attack = bool(row.get("scenario") and row.get("scenario") != "normal")
        if is_attack and start is None:
            start = index
        if start is not None and (not is_attack or index == len(rows) - 1):
            end = index if is_attack and index == len(rows) - 1 else index - 1
            runs.append((start, end))
            start = None

    result: dict[str, Any] = {}
    for method, values in predictions.items():
        delays: list[int] = []
        missed = 0
        for run_start, run_end in runs:
            first = next((index for index in range(run_start, run_end + 1) if values[index]), None)
            if first is None:
                missed += 1
            else:
                delays.append(first - run_start)
        result[method] = {
            "labeled_attack_runs": len(runs),
            "detected_runs": len(delays),
            "missed_runs": missed,
            "mean_delay_windows": sum(delays) / len(delays) if delays else None,
            "max_delay_windows": max(delays) if delays else None,
        }
    return result


def evaluate_combined_dataset(
    rows: list[dict[str, Any]],
    *,
    epochs: int = 220,
    learning_rate: float = 0.015,
    hidden_dim: int | None = None,
    threshold_quantile: float = 0.995,
    rule_quantile: float = 0.995,
    seed: int = 42,
) -> tuple[dict[str, Any], list[dict[str, Any]], NeuralAutoencoder, dict[str, Any]]:
    train, validation, test = _chronological_split(rows)
    labeled = any(row.get("scenario") for row in rows)
    train_normal = [row for row in train if not labeled or row.get("scenario") == "normal"]
    validation_normal = [
        row for row in validation if not labeled or row.get("scenario") == "normal"
    ]
    if not train_normal:
        raise ValueError("Chronological training split contains no normal windows")
    if not validation_normal:
        validation_normal = validation

    model = NeuralAutoencoder.fit(
        train_normal,
        feature_names=COMBINED_FEATURE_NAMES,
        hidden_dim=hidden_dim,
        epochs=epochs,
        learning_rate=learning_rate,
        threshold_quantile=threshold_quantile,
        seed=seed,
    )
    model.calibrate_threshold(validation_normal, quantile=threshold_quantile)
    rule_configuration = calibrate_rule_thresholds(train_normal, quantile=rule_quantile)
    thresholds = rule_configuration["thresholds"]

    score_rows: list[dict[str, Any]] = []
    predictions = {"ml": [], "rules": [], "combined": []}
    labels: list[bool | None] = []
    disagreement: Counter[str] = Counter()
    for row in test:
        ml_score = model.score(row)
        rules = evaluate_security_rules(row, thresholds)
        combined_score, _, model_ratio = score_combined_sample(
            model,
            row,
            rule_thresholds=thresholds,
        )
        ml_detected = ml_score.is_anomaly
        rules_detected = bool(rules)
        combined_detected = combined_score.is_anomaly
        predictions["ml"].append(ml_detected)
        predictions["rules"].append(rules_detected)
        predictions["combined"].append(combined_detected)
        label = None
        if row.get("scenario"):
            label = row.get("scenario") != "normal"
        labels.append(label)
        disagreement[f"ml_{int(ml_detected)}_rules_{int(rules_detected)}"] += 1
        score_rows.append(
            {
                "timestamp": row.get("timestamp"),
                "host": row.get("host"),
                "scenario": row.get("scenario"),
                "label_is_anomaly": label,
                "ml_error": ml_score.error,
                "ml_ratio": model_ratio,
                "ml_is_anomaly": ml_detected,
                "rules_is_anomaly": rules_detected,
                "combined_ratio": combined_score.ratio,
                "combined_is_anomaly": combined_detected,
                "severity": combined_score.severity,
                "rules": rules,
                "top_features": ml_score.top_features,
            }
        )

    methods = {
        method: _method_metrics(values, labels) for method, values in predictions.items()
    }
    report = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "dataset": {
            "windows": len(rows),
            "train_windows": len(train),
            "model_train_windows": len(train_normal),
            "validation_windows": len(validation),
            "threshold_calibration_windows": len(validation_normal),
            "test_windows": len(test),
            "labeled": labeled,
        },
        "model": {
            "features": len(COMBINED_FEATURE_NAMES),
            "hidden_dim": model.hidden_dim,
            "threshold": model.threshold,
            "threshold_quantile": threshold_quantile,
            "epochs": epochs,
        },
        "rules": rule_configuration,
        "methods": methods,
        "ml_rule_disagreement": dict(sorted(disagreement.items())),
        "detection_latency": _detection_delays(test, predictions) if labeled else {},
    }
    return report, score_rows, model, rule_configuration


def write_evaluation_outputs(
    *,
    report_path: str | Path,
    scores_path: str | Path,
    model_path: str | Path,
    rules_path: str | Path,
    report: dict[str, Any],
    scores: list[dict[str, Any]],
    model: NeuralAutoencoder,
    rule_configuration: dict[str, Any],
) -> None:
    report_target = Path(report_path)
    report_target.parent.mkdir(parents=True, exist_ok=True)
    report_target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_jsonl(scores_path, scores)
    model.save(model_path)
    save_rule_configuration(rules_path, rule_configuration)
