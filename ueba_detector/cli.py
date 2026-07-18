from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

from .autoencoder import NeuralAutoencoder
from .collector import TelemetryCollector, collect_to_file, parse_duration
from .reporting import build_anomaly_event, summarize_jsonl, write_text_summary
from .simulate import generate_normal_samples, generate_test_samples
from .storage import append_jsonl, read_jsonl, write_jsonl


def cmd_collect(args: argparse.Namespace) -> None:
    duration = parse_duration(args.duration)
    collect_to_file(args.output, interval=args.interval, duration=duration)


def cmd_train(args: argparse.Namespace) -> None:
    samples = read_jsonl(args.input)
    model = NeuralAutoencoder.fit(
        samples,
        hidden_dim=args.hidden_dim,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        threshold_quantile=args.threshold_quantile,
        seed=args.seed,
    )
    model.save(args.model)
    print(f"trained on {len(samples)} samples")
    print(f"model saved to {args.model}")
    print(f"anomaly threshold: {model.threshold:.6f}")


def cmd_score(args: argparse.Namespace) -> None:
    model = NeuralAutoencoder.load(args.model)
    samples = read_jsonl(args.input)
    anomalies = []
    scores = []

    for sample in samples:
        score = model.score(sample)
        scores.append(
            {
                "timestamp": sample.get("timestamp"),
                "host": sample.get("host", "unknown"),
                "error": score.error,
                "threshold": score.threshold,
                "ratio": score.ratio,
                "is_anomaly": score.is_anomaly,
                "severity": score.severity,
                "top_features": score.top_features,
                "scenario": sample.get("scenario"),
            }
        )
        if score.is_anomaly:
            anomalies.append(build_anomaly_event(sample, score, model_path=args.model))

    if args.scores_output:
        write_jsonl(args.scores_output, scores)
    write_jsonl(args.report, anomalies)

    if args.summary:
        write_text_summary(anomalies, args.summary)

    print(f"scored {len(samples)} samples")
    print(f"anomalies: {len(anomalies)}")
    print(f"report saved to {args.report}")


def cmd_monitor(args: argparse.Namespace) -> None:
    model = NeuralAutoencoder.load(args.model)
    collector = TelemetryCollector()
    duration = parse_duration(args.duration)
    started = time.time()
    last_reported_at = 0.0

    while True:
        sample = collector.sample()
        score = model.score(sample)
        status = "ANOMALY" if score.is_anomaly else "normal"
        print(f"{sample['timestamp']} {status} ratio={score.ratio:.2f}", flush=True)

        now = time.time()
        if score.is_anomaly and now - last_reported_at >= args.cooldown:
            append_jsonl(args.report, build_anomaly_event(sample, score, model_path=args.model))
            last_reported_at = now

        if duration is not None and time.time() - started >= duration:
            break
        time.sleep(args.interval)


def cmd_demo(args: argparse.Namespace) -> None:
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    train_path = out / "demo_train.jsonl"
    test_path = out / "demo_test.jsonl"
    model_path = out / "demo_model.json"
    report_path = out / "demo_anomalies.jsonl"
    scores_path = out / "demo_scores.jsonl"
    summary_path = out / "demo_summary.txt"
    metrics_path = out / "demo_metrics.json"

    train_samples = generate_normal_samples(count=args.train_samples, seed=args.seed)
    test_samples = generate_test_samples(count=args.test_samples, seed=args.seed + 1)
    write_jsonl(train_path, train_samples)
    write_jsonl(test_path, test_samples)

    model = NeuralAutoencoder.fit(
        train_samples,
        epochs=args.epochs,
        threshold_quantile=args.threshold_quantile,
        seed=args.seed,
    )
    model.save(str(model_path))

    anomalies = []
    scores = []
    for sample in test_samples:
        score = model.score(sample)
        scores.append(
            {
                "timestamp": sample.get("timestamp"),
                "ratio": score.ratio,
                "is_anomaly": score.is_anomaly,
                "severity": score.severity,
                "scenario": sample.get("scenario"),
                "top_features": score.top_features,
            }
        )
        if score.is_anomaly:
            anomalies.append(build_anomaly_event(sample, score, model_path=str(model_path)))

    write_jsonl(scores_path, scores)
    write_jsonl(report_path, anomalies)
    write_text_summary(anomalies, str(summary_path))
    metrics = demo_metrics(scores)
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")

    print(f"demo written to {out}")
    print(f"train samples: {len(train_samples)}")
    print(f"test samples: {len(test_samples)}")
    print(f"anomalies detected: {len(anomalies)}")
    print(f"injected anomalies detected: {metrics['true_positives']}/{metrics['injected_anomalies']}")
    print(f"normal false positives: {metrics['false_positives']}/{metrics['normal_samples']}")
    print(f"summary: {summary_path}")


def demo_metrics(scores: list[dict[str, object]]) -> dict[str, object]:
    normal_samples = sum(1 for item in scores if item.get("scenario") == "normal")
    injected_anomalies = len(scores) - normal_samples
    true_positives = sum(1 for item in scores if item.get("scenario") != "normal" and item.get("is_anomaly"))
    false_positives = sum(1 for item in scores if item.get("scenario") == "normal" and item.get("is_anomaly"))
    false_negatives = sum(1 for item in scores if item.get("scenario") != "normal" and not item.get("is_anomaly"))
    by_scenario = Counter(str(item.get("scenario")) for item in scores if item.get("is_anomaly"))
    return {
        "samples": len(scores),
        "normal_samples": normal_samples,
        "injected_anomalies": injected_anomalies,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "recall": true_positives / injected_anomalies if injected_anomalies else 0.0,
        "false_positive_rate": false_positives / normal_samples if normal_samples else 0.0,
        "detected_by_scenario": dict(sorted(by_scenario.items())),
    }


def cmd_summarize(args: argparse.Namespace) -> None:
    summarize_jsonl(args.input, args.output)
    print(f"summary saved to {args.output}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ueba-detector", description="UEBA host anomaly detector")
    sub = parser.add_subparsers(dest="command", required=True)

    collect = sub.add_parser("collect", help="collect live host telemetry into JSONL")
    collect.add_argument("--output", default="data/train.jsonl")
    collect.add_argument("--interval", type=float, default=60.0)
    collect.add_argument("--duration", default="24h")
    collect.set_defaults(func=cmd_collect)

    train = sub.add_parser("train", help="train neural autoencoder on normal telemetry")
    train.add_argument("--input", required=True)
    train.add_argument("--model", default="models/ueba_model.json")
    train.add_argument("--epochs", type=int, default=220)
    train.add_argument("--learning-rate", type=float, default=0.015)
    train.add_argument("--threshold-quantile", type=float, default=0.995)
    train.add_argument("--hidden-dim", type=int)
    train.add_argument("--seed", type=int, default=42)
    train.set_defaults(func=cmd_train)

    score = sub.add_parser("score", help="score a JSONL telemetry file")
    score.add_argument("--model", required=True)
    score.add_argument("--input", required=True)
    score.add_argument("--report", default="reports/anomalies.jsonl")
    score.add_argument("--scores-output")
    score.add_argument("--summary")
    score.set_defaults(func=cmd_score)

    monitor = sub.add_parser("monitor", help="continuous live detection")
    monitor.add_argument("--model", required=True)
    monitor.add_argument("--report", default="reports/anomalies.jsonl")
    monitor.add_argument("--interval", type=float, default=10.0)
    monitor.add_argument("--duration")
    monitor.add_argument("--cooldown", type=float, default=60.0)
    monitor.set_defaults(func=cmd_monitor)

    demo = sub.add_parser("demo", help="generate synthetic data, train, detect anomalies, and write reports")
    demo.add_argument("--output-dir", default="examples/demo_run")
    demo.add_argument("--train-samples", type=int, default=360)
    demo.add_argument("--test-samples", type=int, default=120)
    demo.add_argument("--epochs", type=int, default=180)
    demo.add_argument("--threshold-quantile", type=float, default=0.999)
    demo.add_argument("--seed", type=int, default=7)
    demo.set_defaults(func=cmd_demo)

    summarize = sub.add_parser("summarize", help="convert anomaly JSONL report to text")
    summarize.add_argument("--input", required=True)
    summarize.add_argument("--output", default="reports/summary.txt")
    summarize.set_defaults(func=cmd_summarize)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
