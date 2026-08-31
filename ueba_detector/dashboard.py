from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import read_jsonl_dataset


def _downsample(rows: list[dict[str, Any]], maximum: int = 480) -> list[dict[str, Any]]:
    if len(rows) <= maximum:
        return rows
    step = max(1, len(rows) // maximum)
    sampled = rows[::step]
    if sampled[-1] is not rows[-1]:
        sampled.append(rows[-1])
    return sampled[-maximum:]


def _safe_number(value: object) -> float:
    try:
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def build_dashboard_data(
    readiness: dict[str, Any],
    metric_rows: list[dict[str, Any]],
    evaluation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ordered = sorted(metric_rows, key=lambda row: str(row.get("timestamp") or ""))
    sampled = _downsample(ordered)
    latest = ordered[-1] if ordered else {}
    trends = [
        {
            "timestamp": row.get("timestamp"),
            "cpu": _safe_number(row.get("cpu_percent")),
            "memory": _safe_number(row.get("memory_percent")),
            "processes": _safe_number(row.get("process_count")),
            "network_kbps": (
                _safe_number(row.get("net_bytes_sent_per_sec"))
                + _safe_number(row.get("net_bytes_recv_per_sec"))
            )
            / 1024.0,
            "disk_mbps": (
                _safe_number(row.get("disk_read_bytes_per_sec"))
                + _safe_number(row.get("disk_write_bytes_per_sec"))
            )
            / (1024.0 * 1024.0),
        }
        for row in sampled
    ]
    return {
        "generated_at": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "readiness": readiness,
        "latest": {
            "timestamp": latest.get("timestamp"),
            "cpu": _safe_number(latest.get("cpu_percent")),
            "memory": _safe_number(latest.get("memory_percent")),
            "processes": int(_safe_number(latest.get("process_count"))),
            "network_kbps": (
                _safe_number(latest.get("net_bytes_sent_per_sec"))
                + _safe_number(latest.get("net_bytes_recv_per_sec"))
            )
            / 1024.0,
        },
        "trends": trends,
        "evaluation": evaluation,
    }


def generate_status_dashboard(
    *,
    readiness_path: str | Path,
    metrics_path: str | Path,
    output_path: str | Path,
    evaluation_path: str | Path | None = None,
) -> dict[str, Any]:
    readiness = json.loads(Path(readiness_path).read_text(encoding="utf-8"))
    evaluation = None
    if evaluation_path and Path(evaluation_path).exists():
        evaluation = json.loads(Path(evaluation_path).read_text(encoding="utf-8"))
    data = build_dashboard_data(readiness, read_jsonl_dataset(metrics_path), evaluation)
    encoded = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    encoded = encoded.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    html = DASHBOARD_HTML.replace("__DASHBOARD_DATA__", encoded)
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html, encoding="utf-8")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return data


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Host Model Readiness</title>
<style>
:root{color-scheme:light;--ink:#17202a;--muted:#64707d;--line:#d9dee4;--surface:#fff;--page:#f4f6f8;--green:#18794e;--amber:#9a6700;--red:#b42318;--blue:#1769aa;--teal:#087f8c}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;letter-spacing:0}
header{background:#fff;border-bottom:1px solid var(--line);padding:20px 28px}header .row{max-width:1240px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap}h1{font-size:22px;margin:0;letter-spacing:0}#updated{color:var(--muted);font-size:12px;overflow-wrap:anywhere}
main{max-width:1240px;margin:auto;padding:22px 28px 40px;overflow:hidden}.status{display:flex;align-items:center;gap:10px;margin-bottom:18px;flex-wrap:wrap}.status span:last-child{min-width:0;overflow-wrap:anywhere}.badge{font-weight:700;font-size:12px;padding:5px 8px;border-radius:4px;background:#fff3cd;color:#755500;border:1px solid #ecd98b}.summary{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:18px}.metric{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:14px;min-width:0}.metric label{display:block;color:var(--muted);font-size:12px;margin-bottom:6px}.metric strong{display:block;font-size:21px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.band{background:var(--surface);border-block:1px solid var(--line);padding:16px 0;margin:0 0 18px}.progress-head{display:flex;justify-content:space-between;gap:16px;margin-bottom:8px;flex-wrap:wrap}.track{height:10px;background:#e7ebef;border-radius:3px;overflow:hidden}.fill{height:100%;background:var(--green);width:0}.warning{color:var(--amber);margin:9px 0 0;overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-bottom:18px}.panel{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:14px;min-width:0}.panel h2{font-size:14px;margin:0 0 12px}.chart{width:100%;height:210px;display:block}
.tables{display:grid;grid-template-columns:1fr 1fr;gap:14px}.table-wrap{background:#fff;border:1px solid var(--line);border-radius:6px;overflow:hidden}.table-wrap h2{font-size:14px;margin:0;padding:14px;border-bottom:1px solid var(--line)}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid #edf0f2;font-size:12px}th{color:var(--muted);font-weight:600}td:last-child,th:last-child{text-align:right}.empty{padding:14px;color:var(--muted)}#evaluation-panel{margin-top:14px;display:none}
@media(max-width:900px){.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.grid,.tables{grid-template-columns:1fr}}@media(max-width:520px){header,main{padding-left:16px;padding-right:16px}.summary{grid-template-columns:1fr}.metric strong{font-size:18px}h1{font-size:20px}}
</style>
</head>
<body>
<header><div class="row"><h1>Host Model Readiness</h1><div id="updated"></div></div></header>
<main>
  <div class="status"><span class="badge" id="state"></span><span id="state-detail"></span></div>
  <section class="summary">
    <div class="metric"><label>Training windows</label><strong id="windows"></strong></div>
    <div class="metric"><label>Coverage</label><strong id="coverage"></strong></div>
    <div class="metric"><label>CPU now</label><strong id="cpu"></strong></div>
    <div class="metric"><label>Memory now</label><strong id="memory"></strong></div>
    <div class="metric"><label>Processes now</label><strong id="processes"></strong></div>
  </section>
  <section class="band"><div class="progress-head"><strong>Seven-day baseline</strong><span id="progress-label"></span></div><div class="track"><div class="fill" id="progress"></div></div><p class="warning" id="warning"></p></section>
  <section class="grid">
    <div class="panel"><h2>CPU and memory</h2><canvas class="chart" id="resource-chart"></canvas></div>
    <div class="panel"><h2>Process count</h2><canvas class="chart" id="process-chart"></canvas></div>
    <div class="panel"><h2>Network KB/s</h2><canvas class="chart" id="network-chart"></canvas></div>
    <div class="panel"><h2>Disk MB/s</h2><canvas class="chart" id="disk-chart"></canvas></div>
  </section>
  <section class="tables">
    <div class="table-wrap"><h2>Event distribution</h2><table><thead><tr><th>Event</th><th>Rows</th></tr></thead><tbody id="events"></tbody></table></div>
    <div class="table-wrap"><h2>Largest collection gaps</h2><table><thead><tr><th>Before</th><th>Missing minutes</th></tr></thead><tbody id="gaps"></tbody></table></div>
  </section>
  <section class="table-wrap" id="evaluation-panel"><h2>Latest chronological evaluation</h2><table><thead><tr><th>Method</th><th>Anomalies</th><th>Rate</th></tr></thead><tbody id="evaluation"></tbody></table></section>
</main>
<script>
const d=__DASHBOARD_DATA__,r=d.readiness,ready=r.readiness,combined=r.combined,coverage=r.coverage;
const $=id=>document.getElementById(id),pct=v=>`${(v*100).toFixed(1)}%`,num=v=>Number(v||0).toLocaleString();
$("updated").textContent=`Updated ${new Date(d.generated_at).toLocaleString()}`;$("state").textContent=String(ready.state).replaceAll("_"," ").toUpperCase();
$("state-detail").textContent=ready.ready_for_final_training?"Final training checks passed":"Collection and calibration still in progress";
$("windows").textContent=`${num(combined.clean_windows)} / ${num(r.configuration.recommended_windows)}`;$("coverage").textContent=pct(coverage.coverage_ratio);$("cpu").textContent=`${d.latest.cpu.toFixed(1)}%`;$("memory").textContent=`${d.latest.memory.toFixed(1)}%`;$("processes").textContent=num(d.latest.processes);
$("progress").style.width=pct(ready.progress_ratio);$("progress-label").textContent=pct(ready.progress_ratio);$("warning").textContent=(ready.warnings||[])[0]||"No data-quality warnings";
const eventRows=Object.entries(r.events.event_types||{}).sort((a,b)=>b[1]-a[1]);$("events").innerHTML=eventRows.map(([k,v])=>`<tr><td>${k.replaceAll("_"," ")}</td><td>${num(v)}</td></tr>`).join("");
const gaps=(coverage.largest_gaps||[]).slice(0,6);$("gaps").innerHTML=gaps.length?gaps.map(g=>`<tr><td>${new Date(g.before).toLocaleString()}</td><td>${num(g.missing_windows)}</td></tr>`).join(""):`<tr><td colspan="2">No gaps</td></tr>`;
if(d.evaluation&&d.evaluation.methods){$("evaluation-panel").style.display="block";$("evaluation").innerHTML=Object.entries(d.evaluation.methods).map(([name,m])=>`<tr><td>${name.toUpperCase()}</td><td>${num(m.anomalies)}</td><td>${pct(m.anomaly_rate)}</td></tr>`).join("")}
function chart(id,series){const c=$(id),ctx=c.getContext("2d"),ratio=window.devicePixelRatio||1,w=c.clientWidth,h=c.clientHeight;c.width=w*ratio;c.height=h*ratio;ctx.scale(ratio,ratio);ctx.clearRect(0,0,w,h);ctx.strokeStyle="#d9dee4";ctx.lineWidth=1;for(let i=0;i<5;i++){const y=10+(h-24)*i/4;ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(w,y);ctx.stroke()}series.forEach((s,si)=>{const vals=d.trends.map(x=>Number(x[s.key]||0)),max=Math.max(1,...vals);ctx.strokeStyle=s.color;ctx.lineWidth=1.6;ctx.beginPath();vals.forEach((v,i)=>{const x=vals.length<2?0:i*(w-2)/(vals.length-1),y=h-10-v*(h-24)/max;i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.stroke()})}
chart("resource-chart",[{key:"cpu",color:"#1769aa"},{key:"memory",color:"#18794e"}]);chart("process-chart",[{key:"processes",color:"#7a4e00"}]);chart("network-chart",[{key:"network_kbps",color:"#087f8c"}]);chart("disk-chart",[{key:"disk_mbps",color:"#7a3e9d"}]);
</script>
</body>
</html>
"""
