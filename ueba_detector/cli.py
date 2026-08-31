from __future__ import annotations

import argparse
import json
import os
import time
from collections import Counter
from pathlib import Path

from .agent import SecurityAgent
from .autoencoder import NeuralAutoencoder
from .combined import (
    COMBINED_FEATURE_NAMES,
    build_combined_file,
    build_combined_samples,
    score_combined_sample,
)
from .collector import TelemetryCollector, collect_to_file, parse_duration
from .dashboard import generate_status_dashboard
from .event_collectors import AuthLogCollector, PackageCollector, ProcessCollector, SessionCollector
from .evaluation import (
    calibrate_rule_thresholds,
    evaluate_combined_dataset,
    load_rule_thresholds,
    save_rule_configuration,
    write_evaluation_outputs,
)
from .reporting import build_anomaly_event, summarize_jsonl, write_text_summary
from .readiness import audit_training_data, write_readiness_report
from .simulate import generate_normal_samples, generate_security_events, generate_test_samples
from .storage import RotatingJsonlWriter, read_jsonl, write_jsonl


def cmd_collect(args: argparse.Namespace) -> None:
    duration = parse_duration(args.duration)
    collect_to_file(
        args.output,
        interval=args.interval,
        duration=duration,
        max_file_bytes=int(args.max_file_mb * 1024 * 1024),
        retention_days=args.retention_days,
        compress_rotated=not args.no_compress_rotated,
    )


def cmd_duration_seconds(args: argparse.Namespace) -> None:
    seconds = parse_duration(args.value)
    if seconds is None:
        raise ValueError("duration is required")
    print(max(0, int(round(seconds))))


def _build_event_collectors(args: argparse.Namespace):
    collectors = []
    if not args.no_processes:
        collectors.append(
            ProcessCollector(interval_seconds=args.interval, emit_existing=args.emit_existing_processes)
        )
    if not args.no_sessions:
        collectors.append(
            SessionCollector(interval_seconds=args.interval, emit_existing=args.emit_existing_sessions)
        )
    if not args.no_auth_logs:
        collectors.append(
            AuthLogCollector(
                paths=args.auth_log,
                interval_seconds=args.interval,
                replay_existing=args.replay_auth_logs,
            )
        )
    if not args.no_packages:
        collectors.append(
            PackageCollector(
                interval_seconds=args.package_interval,
                emit_initial_inventory=not args.no_package_inventory,
            )
        )
    return collectors


def cmd_collect_events(args: argparse.Namespace) -> None:
    collectors = _build_event_collectors(args)
    agent = SecurityAgent(
        collectors,
        output=args.output,
        state_path=args.state,
        heartbeat_interval=args.heartbeat_interval,
        max_file_bytes=int(args.max_file_mb * 1024 * 1024),
        retention_days=args.retention_days,
        compress_rotated=not args.no_compress_rotated,
    )
    try:
        agent.run(interval=args.interval, duration=parse_duration(args.duration))
    except KeyboardInterrupt:
        print("security event collection stopped")


def cmd_collect_all(args: argparse.Namespace) -> None:
    telemetry = TelemetryCollector()
    agent = SecurityAgent(
        _build_event_collectors(args),
        output=args.events_output,
        state_path=args.state,
        heartbeat_interval=args.heartbeat_interval,
        max_file_bytes=int(args.max_file_mb * 1024 * 1024),
        retention_days=args.retention_days,
        compress_rotated=not args.no_compress_rotated,
    )
    metric_writer = RotatingJsonlWriter(
        args.metrics_output,
        max_bytes=int(args.max_file_mb * 1024 * 1024),
        retention_days=args.retention_days,
        compress=not args.no_compress_rotated,
    )
    duration = parse_duration(args.duration)
    metric_interval = max(1.0, args.metric_interval)
    event_interval = max(0.1, args.interval)
    started = time.monotonic()
    next_metric_at = 0.0

    try:
        while True:
            now = time.monotonic()
            if now >= next_metric_at:
                sample = telemetry.sample()
                metric_writer.write(sample)
                try:
                    os.chmod(args.metrics_output, 0o600)
                except OSError:
                    pass
                print(f"{sample['timestamp']} collected combined metric sample", flush=True)
                next_metric_at = now + metric_interval

            agent.collect_once()
            elapsed = time.monotonic() - started
            if duration is not None and elapsed >= duration:
                break
            until_metric = max(0.1, next_metric_at - time.monotonic())
            time.sleep(min(event_interval, until_metric))
    except KeyboardInterrupt:
        print("combined collection stopped")


def cmd_build_combined(args: argparse.Namespace) -> None:
    rows = build_combined_file(
        args.metrics,
        args.events,
        args.output,
        window_seconds=args.window_seconds,
    )
    print(f"combined windows: {len(rows)}")
    print(f"features saved to {args.output}")


def cmd_audit_data(args: argparse.Namespace) -> None:
    report = audit_training_data(
        args.metrics,
        args.events,
        window_seconds=args.window_seconds,
        minimum_windows=args.minimum_windows,
        recommended_windows=args.recommended_windows,
        max_rule_exclusion_ratio=args.max_rule_exclusion_ratio,
    )
    write_readiness_report(args.output, report)
    readiness = report["readiness"]
    coverage = report["coverage"]
    combined = report["combined"]
    print(f"training readiness: {str(readiness['state']).upper()}")
    print(
        f"clean windows: {combined['clean_windows']}/{report['configuration']['recommended_windows']} "
        f"({float(readiness['progress_ratio']):.1%})"
    )
    print(
        f"coverage: {float(coverage['coverage_ratio']):.1%}; "
        f"missing windows: {coverage['missing_windows']}; gaps: {coverage['gap_count']}"
    )
    print(
        f"candidate rule-flagged windows: {combined['flagged_windows']}; "
        f"windows excluded from proposed training: {combined['excluded_windows']}"
    )
    for warning in readiness["warnings"]:
        print(f"warning: {warning}")
    for blocker in readiness["blockers"]:
        print(f"blocker: {blocker}")
    print(f"report saved to {args.output}")


def cmd_dashboard(args: argparse.Namespace) -> None:
    report = audit_training_data(
        args.metrics,
        args.events,
        window_seconds=args.window_seconds,
        minimum_windows=args.minimum_windows,
        recommended_windows=args.recommended_windows,
        max_rule_exclusion_ratio=args.max_rule_exclusion_ratio,
    )
    write_readiness_report(args.readiness_output, report)
    data = generate_status_dashboard(
        readiness_path=args.readiness_output,
        metrics_path=args.metrics,
        output_path=args.output,
        evaluation_path=args.evaluation,
    )
    print(
        f"dashboard generated with {len(data['trends'])} trend points; "
        f"readiness: {str(report['readiness']['state']).upper()}"
    )
    print(f"dashboard saved to {args.output}")


def cmd_prune_data(args: argparse.Namespace) -> None:
    for path in args.path:
        writer = RotatingJsonlWriter(path, retention_days=args.retention_days)
        writer.enforce_retention()
        print(f"retention enforced for {path}")


def cmd_train_combined(args: argparse.Namespace) -> None:
    rows = build_combined_file(
        args.metrics,
        args.events,
        args.features_output,
        window_seconds=args.window_seconds,
    )
    model = NeuralAutoencoder.fit(
        rows,
        feature_names=COMBINED_FEATURE_NAMES,
        hidden_dim=args.hidden_dim,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        threshold_quantile=args.threshold_quantile,
        seed=args.seed,
    )
    model.save(args.model)
    print(f"trained combined model on {len(rows)} windows and {len(COMBINED_FEATURE_NAMES)} features")
    print(f"features saved to {args.features_output}")
    print(f"model saved to {args.model}")
    print(f"anomaly threshold: {model.threshold:.6f}")


def cmd_score_combined(args: argparse.Namespace) -> None:
    model = NeuralAutoencoder.load(args.model)
    rule_thresholds = load_rule_thresholds(args.rules) if args.rules else None
    samples = read_jsonl(args.input)
    scores = []
    anomalies = []
    for sample in samples:
        score, rules, model_ratio = score_combined_sample(
            model,
            sample,
            rule_thresholds=rule_thresholds,
        )
        scores.append(
            {
                "timestamp": sample.get("timestamp"),
                "host": sample.get("host", "unknown"),
                "model_ratio": model_ratio,
                "ratio": score.ratio,
                "is_anomaly": score.is_anomaly,
                "severity": score.severity,
                "top_features": score.top_features,
                "rules": rules,
                "scenario": sample.get("scenario"),
            }
        )
        if score.is_anomaly:
            anomaly = build_anomaly_event(sample, score, model_path=args.model)
            anomaly["model_ratio"] = model_ratio
            anomaly["detection_rules"] = rules
            anomalies.append(anomaly)
    if args.scores_output:
        write_jsonl(args.scores_output, scores)
    write_jsonl(args.report, anomalies)
    if args.summary:
        write_text_summary(anomalies, args.summary)
    print(f"scored {len(samples)} combined windows")
    print(f"anomalies: {len(anomalies)}")
    print(f"report saved to {args.report}")


def cmd_calibrate_rules(args: argparse.Namespace) -> None:
    rows = read_jsonl(args.input)
    configuration = calibrate_rule_thresholds(rows, quantile=args.quantile)
    save_rule_configuration(args.output, configuration)
    print(f"calibrated rules on {len(rows)} windows")
    for rule_id, threshold in configuration["thresholds"].items():
        default = configuration["statistics"][rule_id]["default_threshold"]
        print(f"{rule_id}: {default} -> {threshold}")
    print(f"rule configuration saved to {args.output}")


def cmd_evaluate_combined(args: argparse.Namespace) -> None:
    rows = build_combined_file(
        args.metrics,
        args.events,
        args.features_output,
        window_seconds=args.window_seconds,
    )
    report, scores, model, rule_configuration = evaluate_combined_dataset(
        rows,
        epochs=args.epochs,
        learning_rate=args.learning_rate,
        hidden_dim=args.hidden_dim,
        threshold_quantile=args.threshold_quantile,
        rule_quantile=args.rule_quantile,
        seed=args.seed,
    )
    write_evaluation_outputs(
        report_path=args.report,
        scores_path=args.scores_output,
        model_path=args.model,
        rules_path=args.rules_output,
        report=report,
        scores=scores,
        model=model,
        rule_configuration=rule_configuration,
    )
    print(
        f"evaluated {report['dataset']['test_windows']} test windows after chronological "
        f"train/validation/test splitting"
    )
    for method, metrics in report["methods"].items():
        print(
            f"{method}: {metrics['anomalies']} anomalies "
            f"({float(metrics['anomaly_rate']):.1%})"
        )
    print(f"evaluation saved to {args.report}")


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


def cmd_demo_combined(args: argparse.Namespace) -> None:
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    train_metrics = generate_normal_samples(count=args.train_samples, seed=args.seed)
    test_metrics = generate_test_samples(count=args.test_samples, seed=args.seed + 1)
    train_events = generate_security_events(train_metrics, seed=args.seed + 2)
    test_events = generate_security_events(
        test_metrics,
        seed=args.seed + 3,
        inject_event_attacks=True,
    )
    train_rows = build_combined_samples(train_metrics, train_events)
    test_rows = build_combined_samples(test_metrics, test_events)

    paths = {
        "train_metrics": out / "combined_train_metrics.jsonl",
        "test_metrics": out / "combined_test_metrics.jsonl",
        "train_events": out / "combined_train_events.jsonl",
        "test_events": out / "combined_test_events.jsonl",
        "train_features": out / "combined_train_features.jsonl",
        "test_features": out / "combined_test_features.jsonl",
        "model": out / "combined_model.json",
        "report": out / "combined_anomalies.jsonl",
        "scores": out / "combined_scores.jsonl",
        "metrics": out / "combined_metrics.json",
    }
    write_jsonl(paths["train_metrics"], train_metrics)
    write_jsonl(paths["test_metrics"], test_metrics)
    write_jsonl(paths["train_events"], train_events)
    write_jsonl(paths["test_events"], test_events)
    write_jsonl(paths["train_features"], train_rows)
    write_jsonl(paths["test_features"], test_rows)

    model = NeuralAutoencoder.fit(
        train_rows,
        feature_names=COMBINED_FEATURE_NAMES,
        epochs=args.epochs,
        threshold_quantile=args.threshold_quantile,
        seed=args.seed,
    )
    model.save(paths["model"])
    scores = []
    anomalies = []
    for row in test_rows:
        score, rules, model_ratio = score_combined_sample(model, row)
        scores.append(
            {
                "timestamp": row.get("timestamp"),
                "scenario": row.get("scenario"),
                "ratio": score.ratio,
                "is_anomaly": score.is_anomaly,
                "severity": score.severity,
                "top_features": score.top_features,
                "rules": rules,
                "model_ratio": model_ratio,
            }
        )
        if score.is_anomaly:
            anomaly = build_anomaly_event(row, score, model_path=str(paths["model"]))
            anomaly["model_ratio"] = model_ratio
            anomaly["detection_rules"] = rules
            anomalies.append(anomaly)
    write_jsonl(paths["scores"], scores)
    write_jsonl(paths["report"], anomalies)
    metrics = demo_metrics(scores)
    paths["metrics"].write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")

    print(f"combined demo written to {out}")
    print(f"train windows: {len(train_rows)}")
    print(f"test windows: {len(test_rows)}")
    print(f"features: {len(COMBINED_FEATURE_NAMES)}")
    print(f"injected anomalies detected: {metrics['true_positives']}/{metrics['injected_anomalies']}")
    print(f"normal false positives: {metrics['false_positives']}/{metrics['normal_samples']}")


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


def _add_storage_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-file-mb",
        type=float,
        default=0.0,
        help="rotate JSONL files at this size; 0 disables rotation",
    )
    parser.add_argument("--retention-days", type=float, help="delete rotated segments older than this")
    parser.add_argument("--no-compress-rotated", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ueba-detector", description="UEBA host anomaly detector")
    sub = parser.add_subparsers(dest="command", required=True)

    duration = sub.add_parser("duration-seconds", help=argparse.SUPPRESS)
    duration.add_argument("value")
    duration.set_defaults(func=cmd_duration_seconds)

    collect = sub.add_parser("collect", help="collect live host telemetry into JSONL")
    collect.add_argument("--output", default="data/train.jsonl")
    collect.add_argument("--interval", type=float, default=60.0)
    collect.add_argument("--duration", default="24h")
    _add_storage_options(collect)
    collect.set_defaults(func=cmd_collect)

    events = sub.add_parser("collect-events", help="collect normalized host security events into JSONL")
    events.add_argument("--output", default="data/security_events.jsonl")
    events.add_argument("--state", default="data/agent_state.json")
    events.add_argument("--interval", type=float, default=2.0)
    events.add_argument("--package-interval", type=float, default=300.0)
    events.add_argument("--heartbeat-interval", type=float, default=60.0)
    events.add_argument("--duration")
    events.add_argument("--auth-log", action="append", help="authentication log path; may be repeated")
    events.add_argument("--replay-auth-logs", action="store_true")
    events.add_argument("--emit-existing-processes", action="store_true")
    events.add_argument("--emit-existing-sessions", action="store_true")
    events.add_argument("--no-package-inventory", action="store_true")
    events.add_argument("--no-processes", action="store_true")
    events.add_argument("--no-sessions", action="store_true")
    events.add_argument("--no-auth-logs", action="store_true")
    events.add_argument("--no-packages", action="store_true")
    _add_storage_options(events)
    events.set_defaults(func=cmd_collect_events)

    collect_all = sub.add_parser("collect-all", help="collect metrics and security events together")
    collect_all.add_argument("--metrics-output", default="data/mac_metrics.jsonl")
    collect_all.add_argument("--events-output", default="data/mac_events.jsonl")
    collect_all.add_argument("--state", default="data/mac_agent_state.json")
    collect_all.add_argument("--metric-interval", type=float, default=60.0)
    collect_all.add_argument("--event-interval", dest="interval", type=float, default=2.0)
    collect_all.add_argument("--package-interval", type=float, default=300.0)
    collect_all.add_argument("--heartbeat-interval", type=float, default=60.0)
    collect_all.add_argument("--duration", default="168h")
    collect_all.add_argument("--auth-log", action="append", help="authentication log path; may be repeated")
    collect_all.add_argument("--replay-auth-logs", action="store_true")
    collect_all.add_argument("--emit-existing-processes", action="store_true")
    collect_all.add_argument("--emit-existing-sessions", action="store_true")
    collect_all.add_argument("--no-package-inventory", action="store_true")
    collect_all.add_argument("--no-processes", action="store_true")
    collect_all.add_argument("--no-sessions", action="store_true")
    collect_all.add_argument("--no-auth-logs", action="store_true")
    collect_all.add_argument("--no-packages", action="store_true")
    _add_storage_options(collect_all)
    collect_all.set_defaults(func=cmd_collect_all)

    audit = sub.add_parser(
        "audit-data",
        help="check live metric/event data quality and combined-training readiness",
    )
    audit.add_argument("--metrics", required=True)
    audit.add_argument("--events", required=True)
    audit.add_argument("--output", default="reports/training_readiness.json")
    audit.add_argument("--window-seconds", type=int, default=60)
    audit.add_argument("--minimum-windows", type=int, default=1_440)
    audit.add_argument("--recommended-windows", type=int, default=10_080)
    audit.add_argument("--max-rule-exclusion-ratio", type=float, default=0.05)
    audit.set_defaults(func=cmd_audit_data)

    dashboard = sub.add_parser(
        "dashboard",
        help="generate a self-contained local collection and training-readiness dashboard",
    )
    dashboard.add_argument("--metrics", required=True)
    dashboard.add_argument("--events", required=True)
    dashboard.add_argument("--readiness-output", default="reports/training_readiness.json")
    dashboard.add_argument("--evaluation", default="reports/evaluation.json")
    dashboard.add_argument("--output", default="reports/status_dashboard.html")
    dashboard.add_argument("--window-seconds", type=int, default=60)
    dashboard.add_argument("--minimum-windows", type=int, default=1_440)
    dashboard.add_argument("--recommended-windows", type=int, default=10_080)
    dashboard.add_argument("--max-rule-exclusion-ratio", type=float, default=0.05)
    dashboard.set_defaults(func=cmd_dashboard)

    prune = sub.add_parser("prune-data", help="delete rotated JSONL segments beyond retention")
    prune.add_argument("--path", action="append", required=True)
    prune.add_argument("--retention-days", type=float, required=True)
    prune.set_defaults(func=cmd_prune_data)

    combine = sub.add_parser("build-combined", help="join metrics and events into time-window features")
    combine.add_argument("--metrics", required=True)
    combine.add_argument("--events", required=True)
    combine.add_argument("--output", default="data/combined_features.jsonl")
    combine.add_argument("--window-seconds", type=int, default=60)
    combine.set_defaults(func=cmd_build_combined)

    train_combined = sub.add_parser("train-combined", help="build features and train a combined model")
    train_combined.add_argument("--metrics", required=True)
    train_combined.add_argument("--events", required=True)
    train_combined.add_argument("--features-output", default="data/combined_train.jsonl")
    train_combined.add_argument("--model", default="models/combined_model.json")
    train_combined.add_argument("--window-seconds", type=int, default=60)
    train_combined.add_argument("--epochs", type=int, default=220)
    train_combined.add_argument("--learning-rate", type=float, default=0.015)
    train_combined.add_argument("--threshold-quantile", type=float, default=0.995)
    train_combined.add_argument("--hidden-dim", type=int)
    train_combined.add_argument("--seed", type=int, default=42)
    train_combined.set_defaults(func=cmd_train_combined)

    score_combined = sub.add_parser("score-combined", help="score combined features with ML and rules")
    score_combined.add_argument("--model", required=True)
    score_combined.add_argument("--rules", help="calibrated rule configuration JSON")
    score_combined.add_argument("--input", required=True)
    score_combined.add_argument("--report", default="reports/combined_anomalies.jsonl")
    score_combined.add_argument("--scores-output")
    score_combined.add_argument("--summary")
    score_combined.set_defaults(func=cmd_score_combined)

    calibrate_rules = sub.add_parser(
        "calibrate-rules",
        help="derive host-specific rule thresholds from combined baseline windows",
    )
    calibrate_rules.add_argument("--input", required=True)
    calibrate_rules.add_argument("--output", default="models/combined_rules.json")
    calibrate_rules.add_argument("--quantile", type=float, default=0.995)
    calibrate_rules.set_defaults(func=cmd_calibrate_rules)

    evaluate_combined = sub.add_parser(
        "evaluate-combined",
        help="chronologically train, calibrate, and compare ML, rules, and combined detection",
    )
    evaluate_combined.add_argument("--metrics", required=True)
    evaluate_combined.add_argument("--events", required=True)
    evaluate_combined.add_argument("--features-output", default="data/evaluation_features.jsonl")
    evaluate_combined.add_argument("--model", default="models/evaluated_combined_model.json")
    evaluate_combined.add_argument("--rules-output", default="models/evaluated_rules.json")
    evaluate_combined.add_argument("--report", default="reports/evaluation.json")
    evaluate_combined.add_argument("--scores-output", default="reports/evaluation_scores.jsonl")
    evaluate_combined.add_argument("--window-seconds", type=int, default=60)
    evaluate_combined.add_argument("--epochs", type=int, default=220)
    evaluate_combined.add_argument("--learning-rate", type=float, default=0.015)
    evaluate_combined.add_argument("--threshold-quantile", type=float, default=0.995)
    evaluate_combined.add_argument("--rule-quantile", type=float, default=0.995)
    evaluate_combined.add_argument("--hidden-dim", type=int)
    evaluate_combined.add_argument("--seed", type=int, default=42)
    evaluate_combined.set_defaults(func=cmd_evaluate_combined)

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

    combined_demo = sub.add_parser(
        "demo-combined", help="test combined metric and security-event anomaly detection"
    )
    combined_demo.add_argument("--output-dir", default="examples/combined_demo")
    combined_demo.add_argument("--train-samples", type=int, default=360)
    combined_demo.add_argument("--test-samples", type=int, default=120)
    combined_demo.add_argument("--epochs", type=int, default=180)
    combined_demo.add_argument("--threshold-quantile", type=float, default=0.999)
    combined_demo.add_argument("--seed", type=int, default=7)
    combined_demo.set_defaults(func=cmd_demo_combined)

    summarize = sub.add_parser("summarize", help="convert anomaly JSONL report to text")
    summarize.add_argument("--input", required=True)
    summarize.add_argument("--output", default="reports/summary.txt")
    summarize.set_defaults(func=cmd_summarize)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
