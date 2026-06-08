# Contributing

## Development workflow

1. Create a feature branch.
2. Keep commits scoped and use conventional commit messages.
3. Run `make verify` before opening a pull request.
4. Update `README.md` and `CHANGELOG.md` for user-visible changes.

## Standards

- Prefer deterministic inputs and outputs.
- Preserve backwards compatibility for the CLI across patch releases.
- Add or update tests for every behavior change.
- Document new policy fields with examples.
- Keep CI semantics explicit: if a change affects exit codes, `validate`, or SARIF output, update smoke coverage and release notes.

## Release process

1. Bump the version in `pyproject.toml` and `src/agent_policy_gate/__init__.py`.
2. Update `CHANGELOG.md`.
3. Create a git tag like `v0.2.0`.
4. Publish the release notes in GitHub.
