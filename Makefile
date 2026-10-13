.PHONY: install test demo
install:
	./landscape/local.sh install

test:
	uv run pytest
	uv run pre-commit run --all-files
	cd landscape/web && npm test && npm run build && npm audit --audit-level=high

demo:
	./landscape/local.sh demo
