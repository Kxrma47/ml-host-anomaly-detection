.PHONY: test demo quickstart demo-combined audit dashboard evaluate

quickstart:
	./scripts/quickstart.sh

test:
	python3 -m unittest discover -s tests -p 'test_*.py'

demo:
	python3 -m ueba_detector demo --output-dir examples/demo_run

demo-combined:
	python3 -m ueba_detector demo-combined --output-dir examples/combined_demo

audit:
	python3 -m ueba_detector audit-data --metrics data/mac_metrics.jsonl --events data/mac_events.jsonl

dashboard:
	python3 -m ueba_detector dashboard --metrics data/mac_metrics.jsonl --events data/mac_events.jsonl

evaluate:
	python3 -m ueba_detector evaluate-combined --metrics data/mac_metrics.jsonl --events data/mac_events.jsonl
