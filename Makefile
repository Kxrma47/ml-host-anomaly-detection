.PHONY: test demo

test:
	python3 -m unittest discover -s tests -p 'test_*.py'

demo:
	python3 -m ueba_detector demo --output-dir examples/demo_run
