.PHONY: validate seal test ci install-hooks

# Validate registry.yaml (schema + semantics). Does not write the seal.
validate:
	python validator.py

# Validate and write the approved hash seal.
# Run this after editing registry.yaml, before committing.
seal: validate

# Run the full scenario harness.
test:
	python test_scenario.py

# Full CI pipeline — what the GitHub Action runs.
ci: seal test

# Install the pre-commit hook into the local git repo.
install-hooks:
	cp hooks/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed."
