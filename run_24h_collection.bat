@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  set PYTHON=.venv\Scripts\python.exe
) else (
  set PYTHON=python
)
"%PYTHON%" -u -m ueba_detector collect --output data\baseline_24h_tcp.jsonl --interval 60 --duration 24h
