from __future__ import annotations

import csv
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any


REVIEW_LABELS = {"unreviewed", "benign", "suspicious", "confirmed_attack"}
REVIEW_FIELDS = [
    "alert_id", "event_timestamp", "severity", "category", "ratio", "model_ratio",
    "rules", "top_features", "label", "analyst_note",
]


def alert_id(alert: dict[str, Any]) -> str:
    rules = sorted(
        str(item.get("rule_id", ""))
        for item in alert.get("detection_rules", [])
        if isinstance(item, dict)
    )
    features = [
        str(item.get("feature", ""))
        for item in alert.get("top_features", [])
        if isinstance(item, dict)
    ]
    identity = {
        "timestamp": alert.get("event_timestamp"),
        "host": alert.get("host"),
        "category": alert.get("category"),
        "rules": rules,
        "features": features,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"hwa-{digest[:16]}"


def build_review_rows(alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for alert in alerts:
        rules = [
            str(item.get("rule_id", ""))
            for item in alert.get("detection_rules", [])
            if isinstance(item, dict) and item.get("rule_id")
        ]
        features = [
            str(item.get("feature", ""))
            for item in alert.get("top_features", [])
            if isinstance(item, dict) and item.get("feature")
        ]
        rows.append(
            {
                "alert_id": alert_id(alert),
                "event_timestamp": str(alert.get("event_timestamp") or ""),
                "severity": str(alert.get("severity") or "unknown"),
                "category": str(alert.get("category") or "unknown"),
                "ratio": f"{float(alert.get('ratio', 0.0)):.6f}",
                "model_ratio": f"{float(alert.get('model_ratio', alert.get('ratio', 0.0))):.6f}",
                "rules": ";".join(rules),
                "top_features": ";".join(features),
                "label": "unreviewed",
                "analyst_note": "",
            }
        )
    return rows


def read_review_rows(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        rows = [{field: str(row.get(field) or "") for field in REVIEW_FIELDS}
                for row in csv.DictReader(stream)]
    seen: set[str] = set()
    for row in rows:
        identifier = row["alert_id"].strip()
        if not identifier:
            raise ValueError("Review row is missing alert_id")
        if identifier in seen:
            raise ValueError(f"Duplicate alert_id in review: {identifier}")
        if row["label"] not in REVIEW_LABELS:
            raise ValueError(f"Unsupported review label: {row['label']}")
        seen.add(identifier)
    return rows


def merge_review_rows(
    alerts: list[dict[str, Any]], existing_rows: list[dict[str, str]]
) -> list[dict[str, str]]:
    existing = {row["alert_id"]: row for row in existing_rows}
    rows = build_review_rows(alerts)
    for row in rows:
        previous = existing.get(row["alert_id"])
        if previous:
            row["label"] = previous["label"]
            row["analyst_note"] = previous["analyst_note"]
    return rows


def write_review_csv(path: str | Path, rows: list[dict[str, str]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=REVIEW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    os.chmod(target, 0o600)


def write_review_html(path: str | Path, rows: list[dict[str, str]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(rows, separators=(",", ":")).replace("<", "\\u003c")
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>HostWatch alert review</title>
<style>
*{box-sizing:border-box}body{font:14px system-ui;margin:0;color:#17201d;background:#f5f7f6}main{padding:24px;max-width:1600px;margin:auto}
h1{font-size:24px;margin:0}p{color:#50605a}.top{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:18px}.actions{display:flex;gap:8px;flex-wrap:wrap}
button,input,select,textarea{font:inherit}button{border:1px solid #b9c6c1;background:#fff;padding:8px 11px;cursor:pointer}button.primary{background:#176b87;color:#fff;border-color:#176b87}
.summary{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));border:1px solid #d8dfdc;background:#fff;margin-bottom:14px}.summary div{padding:12px;border-right:1px solid #e6ebe9}.summary div:last-child{border:0}.summary span{display:block;color:#60706a;font-size:12px}.summary strong{font-size:20px}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}.segments{display:flex}.segments button{margin-right:-1px}.segments button.active{background:#dce9e5;border-color:#6d9286}.search{min-width:260px;padding:8px 10px;border:1px solid #b9c6c1}
.table{overflow:auto;max-height:calc(100vh - 250px);border:1px solid #d8dfdc;background:#fff}table{border-collapse:collapse;width:100%}th,td{padding:9px 10px;border-bottom:1px solid #e6ebe9;text-align:left;white-space:nowrap;vertical-align:top}
th{position:sticky;top:0;background:#edf2f0;z-index:1}td.wrap{white-space:normal;min-width:190px;max-width:300px}select{padding:7px;border:1px solid #aebdb7;min-width:150px}textarea{padding:7px;border:1px solid #aebdb7;min-width:220px;min-height:54px;resize:vertical}.empty{padding:30px;text-align:center;color:#60706a}
@media(max-width:800px){main{padding:14px}.top,.toolbar{align-items:stretch;flex-direction:column}.summary{grid-template-columns:repeat(2,1fr)}.summary div{border-bottom:1px solid #e6ebe9}.search{min-width:0;width:100%}.table{max-height:none}}
</style></head><body><main>
<div class="top"><div><h1>HostWatch alert review</h1><p>Local analyst decisions</p></div><div class="actions"><button id="reset">Reset local changes</button><button class="primary" id="download">Download CSV</button></div></div>
<section class="summary" aria-label="Review summary"><div><span>Total</span><strong id="total">0</strong></div><div><span>Unreviewed</span><strong id="unreviewed">0</strong></div><div><span>Benign</span><strong id="benign">0</strong></div><div><span>Suspicious</span><strong id="suspicious">0</strong></div><div><span>Confirmed attack</span><strong id="confirmed_attack">0</strong></div></section>
<div class="toolbar"><div class="segments" aria-label="Label filter"><button class="active" data-filter="all">All</button><button data-filter="unreviewed">Unreviewed</button><button data-filter="benign">Benign</button><button data-filter="suspicious">Suspicious</button><button data-filter="confirmed_attack">Confirmed</button></div><input class="search" id="search" type="search" placeholder="Search alert evidence" aria-label="Search alerts"></div>
<div class="table"><table><thead><tr><th>ID</th><th>Time</th><th>Severity</th><th>Category</th><th>Ratio</th><th>Rules</th><th>Top features</th><th>Label</th><th>Analyst note</th></tr></thead><tbody id="rows"></tbody></table><div class="empty" id="empty" hidden>No alerts match this view.</div></div>
<script type="application/json" id="review-data">__REVIEW_DATA__</script>
<script>
const fields=["alert_id","event_timestamp","severity","category","ratio","model_ratio","rules","top_features","label","analyst_note"];
const labels=["unreviewed","benign","suspicious","confirmed_attack"];
const rows=JSON.parse(document.getElementById("review-data").textContent);let filter="all";
function saved(){try{return JSON.parse(localStorage.getItem("hostwatch-review-v1")||"{}")}catch{return {}}}
const local=saved();for(const row of rows){if(local[row.alert_id]){row.label=local[row.alert_id].label;row.analyst_note=local[row.alert_id].analyst_note}}
function persist(){const value={};for(const row of rows)value[row.alert_id]={label:row.label,analyst_note:row.analyst_note};try{localStorage.setItem("hostwatch-review-v1",JSON.stringify(value))}catch{}}
function textCell(value,className=""){const cell=document.createElement("td");cell.textContent=value;cell.className=className;return cell}
function summary(){const counts=Object.fromEntries(labels.map(label=>[label,0]));for(const row of rows)counts[row.label]+=1;document.getElementById("total").textContent=String(rows.length);for(const label of labels)document.getElementById(label).textContent=String(counts[label])}
function render(){const query=document.getElementById("search").value.toLowerCase();const body=document.getElementById("rows");body.replaceChildren();const visible=rows.filter(row=>(filter==="all"||row.label===filter)&&(!query||Object.values(row).join(" ").toLowerCase().includes(query)));for(const row of visible){const tr=document.createElement("tr");tr.append(textCell(row.alert_id),textCell(row.event_timestamp),textCell(row.severity),textCell(row.category),textCell(row.ratio),textCell(row.rules,"wrap"),textCell(row.top_features,"wrap"));const labelCell=document.createElement("td");const select=document.createElement("select");select.setAttribute("aria-label",`Label ${row.alert_id}`);for(const label of labels){const option=document.createElement("option");option.value=label;option.textContent=label.replaceAll("_"," ");select.append(option)}select.value=row.label;select.addEventListener("change",()=>{row.label=select.value;persist();summary();render()});labelCell.append(select);tr.append(labelCell);const noteCell=document.createElement("td");const note=document.createElement("textarea");note.setAttribute("aria-label",`Note ${row.alert_id}`);note.value=row.analyst_note;note.addEventListener("input",()=>{row.analyst_note=note.value;persist()});noteCell.append(note);tr.append(noteCell);body.append(tr)}document.getElementById("empty").hidden=visible.length!==0;summary()}
for(const button of document.querySelectorAll("[data-filter]"))button.addEventListener("click",()=>{filter=button.dataset.filter;for(const item of document.querySelectorAll("[data-filter]"))item.classList.toggle("active",item===button);render()});
document.getElementById("search").addEventListener("input",render);
document.getElementById("reset").addEventListener("click",()=>{try{localStorage.removeItem("hostwatch-review-v1")}catch{}location.reload()});
document.getElementById("download").addEventListener("click",()=>{const quote=value=>`"${String(value).replaceAll('"','""')}"`;const csv=[fields.join(","),...rows.map(row=>fields.map(field=>quote(row[field])).join(","))].join("\\r\\n")+"\\r\\n";const link=document.createElement("a");link.href=URL.createObjectURL(new Blob([csv],{type:"text/csv;charset=utf-8"}));link.download="alert_review.csv";link.click();setTimeout(()=>URL.revokeObjectURL(link.href),0)});
render();
</script></main></body></html>""".replace("__REVIEW_DATA__", payload)
    target.write_text(document, encoding="utf-8")
    os.chmod(target, 0o600)


def summarize_review_csv(path: str | Path) -> dict[str, Any]:
    rows = read_review_rows(path)
    labels = Counter(row.get("label", "unreviewed") for row in rows)
    return {
        "total": len(rows),
        "labels": {label: labels.get(label, 0) for label in sorted(REVIEW_LABELS)},
        "reviewed": len(rows) - labels.get("unreviewed", 0),
    }


def load_review_labels(path: str | Path) -> dict[str, str]:
    rows = read_review_rows(path)
    labels: dict[str, str] = {}
    for row in rows:
        identifier = str(row.get("alert_id") or "").strip()
        label = str(row.get("label") or "").strip()
        if not identifier:
            raise ValueError("Review row is missing alert_id")
        if identifier in labels:
            raise ValueError(f"Duplicate alert_id in review: {identifier}")
        if label not in REVIEW_LABELS:
            raise ValueError(f"Unsupported review label: {label}")
        labels[identifier] = label
    return labels


def evaluate_reviewed_alerts(alerts: list[dict[str, Any]], labels: dict[str, str]) -> dict[str, Any]:
    known_ids = {alert_id(alert) for alert in alerts}
    unknown_ids = sorted(set(labels) - known_ids)
    if unknown_ids:
        raise ValueError(f"Review contains {len(unknown_ids)} alert IDs not present in the anomaly file")
    matched = [(alert, labels.get(alert_id(alert), "unreviewed")) for alert in alerts]
    counts = Counter(label for _, label in matched)
    reviewed = [(alert, label) for alert, label in matched if label != "unreviewed"]
    positive = sum(label in {"suspicious", "confirmed_attack"} for _, label in reviewed)
    benign = sum(label == "benign" for _, label in reviewed)
    return {
        "alerts": len(alerts),
        "matched_reviews": sum(alert_id(alert) in labels for alert in alerts),
        "reviewed": len(reviewed),
        "unreviewed": len(alerts) - len(reviewed),
        "labels": {label: counts.get(label, 0) for label in sorted(REVIEW_LABELS)},
        "alert_precision": positive / len(reviewed) if reviewed else None,
        "reviewed_true_alerts": positive,
        "reviewed_false_alerts": benign,
        "recall": None,
        "recall_note": "Alert review alone cannot reveal attacks the detector missed.",
    }


def select_reviewed_baseline(
    samples: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    labels: dict[str, str],
    *,
    maximum_unreviewed: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    evaluation = evaluate_reviewed_alerts(alerts, labels)
    if int(evaluation["unreviewed"]) > maximum_unreviewed:
        raise ValueError(
            f"Review gate failed: {evaluation['unreviewed']} alert(s) remain unreviewed; "
            f"maximum allowed is {maximum_unreviewed}"
        )
    excluded_windows = {
        (str(alert.get("host") or "unknown"), str(alert.get("event_timestamp") or ""))
        for alert in alerts
        if labels.get(alert_id(alert)) in {"suspicious", "confirmed_attack"}
    }
    selected = [
        sample for sample in samples
        if (str(sample.get("host") or "unknown"), str(sample.get("timestamp") or ""))
        not in excluded_windows
    ]
    if not selected:
        raise ValueError("No baseline windows remain after applying reviewed labels")
    return selected, {
        "input_windows": len(samples),
        "selected_windows": len(selected),
        "excluded_reviewed_alert_windows": len(samples) - len(selected),
        "review": evaluation,
    }
