.PHONY: install test lint web-test web-build audit verify

install:
	uv sync
	cd landscape/web && npm ci

test:
	uv run pytest tests/unit

lint:
	uv run pre-commit run --all-files

web-test:
	cd landscape/web && npm test -- --run

web-build:
	cd landscape/web && npm run build

audit:
	cd landscape/web && npm audit --audit-level=high

verify: test lint web-test web-build audit
