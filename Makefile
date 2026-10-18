.PHONY: install test demo serve diagrams lint docker

install:
	pip install -e ".[dev,service,audit]"

test:
	pytest -q

demo:
	vahini demo

serve:
	vahini serve --port 8080

diagrams:
	python docs/diagrams/diagrams.py

lint:
	ruff check src tests

docker:
	docker compose up --build
