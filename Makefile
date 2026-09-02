.PHONY: test demo quickstart demo-combined audit dashboard evaluate validate stress compare standards web-test web-build web-dev

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

validate:
	python3 -m ueba_detector validate-dataset --input data/mac_metrics.jsonl --kind metrics

stress:
	python3 -m ueba_detector stress-test --windows 10000

compare:
	python3 -m ueba_detector compare-models --training-input examples/demo_run/demo_train.jsonl --input examples/demo_run/demo_test.jsonl

standards:
	python3 -m ueba_detector standards-test

web-test:
	cd web && npm test

web-build:
	cd web && npm run build

web-dev:
	cd web && npm run dev
