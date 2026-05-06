.PHONY: help quickstart format lint test coverage check validate-local-pcaps sanitize-check release-check source-pack

help:
	@echo "Targets:"
	@echo "  quickstart - run extraction-safe first-run validation"
	@echo "  format   - run black"
	@echo "  lint     - run pylint"
	@echo "  test     - run unittest"
	@echo "  coverage - run coverage"
	@echo "  check    - run all validation"
	@echo "  validate-local-pcaps - inspect and parse local legacy pcaps"
	@echo "  sanitize-check - validate repo before GitLab push"
	@echo "  release-check  - run Git checkout release validation gates"
	@echo "  source-pack    - create source pack at /tmp/oad-parser-source-pack.tar.gz"

quickstart:
	./scripts/quickstart_check.sh

format:
	python3 -m black oad_parser

lint:
	python3 -m pylint oad_parser

test:
	python3 -m unittest discover -s oad_parser/tests -p "test_*.py"

coverage:
	python3 -m coverage run -m unittest discover -s oad_parser/tests -p "test_*.py"
	python3 -m coverage report

check: test
	@echo "Base check complete. Run format/lint/coverage after installing dev dependencies."

validate-local-pcaps:
	./scripts/validate_local_pcaps.sh

sanitize-check:
	./scripts/validate_sanitized_release.sh

release-check:
	./scripts/validate_sanitized_release.sh
	./scripts/validate_release_readiness.sh

source-pack:
	./scripts/make_source_pack.sh /tmp/oad-parser-source-pack.tar.gz
