.PHONY: install test clean run example

install:
	pip install -r requirements.txt

test:
	python tests/run_tests.py

clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	rm -rf api_security_output/
	rm -rf venv/

run:
	@echo "Usage: make run HAR=path/to/file.har"
	@if [ -z "$(HAR)" ]; then echo "Please specify HAR file: make run HAR=capture.har"; exit 1; fi
	python api_security_tool.py $(HAR) --export-json --export-wordlists

example:
	python tests/run_tests.py
	@echo "Example completed. Check api_security_output/ for results."

batch:
	@echo "Processing all HAR files in current directory..."
	@for har in *.har; do \
		if [ -f "$$har" ]; then \
			echo "Processing $$har..."; \
			python api_security_tool.py "$$har" --output "./results/$${har%.*}" --quiet; \
		fi; \
	done
