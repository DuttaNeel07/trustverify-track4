.PHONY: setup test demo evaluate brief
setup:
	uv sync --extra dev --locked
test:
	uv run --extra dev --locked pytest -q
demo:
	uv run --locked trustverify demo --directory runtime/demo-$$(date +%s)
evaluate:
	uv run --locked trustverify evaluate --output reports/detector.json
brief:
	uv run --extra dev --locked python scripts/build_brief.py
