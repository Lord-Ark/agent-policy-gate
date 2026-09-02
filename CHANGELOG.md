# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added

- CLI `--version` flag for quick package version checks in local and CI environments.
- Support `--policy -` and `--trace -` stdin inputs for pipeline-friendly validation and evaluation workflows.

### Fixed

- Normalize bracketed IPv6 network targets in rule domains and trace resources so URL-based IPv6 egress is validated and scored correctly.

## [0.2.0] - 2026-06-08

### Added

- Policy validation command with duplicate rule detection, matcher coverage warnings, and schema-level error reporting.
- SARIF report output for GitHub-native code scanning and security artifact workflows.
- CI enforcement flags for failing builds on deny, review, or configurable risk thresholds.
- CI gate flow diagram documenting validation, evaluation, report generation, and pipeline enforcement.

### Changed

- Expanded GitHub Actions smoke coverage to exercise policy validation, SARIF output, and non-zero enforcement semantics.
- Strengthened the local `make security` target to validate policies and assert CI gate behavior.

## [0.1.0] - 2026-06-07

### Added

- Initial release of Agent Policy Gate.
- Policy document model for allow, review, and deny decisions.
- Risk scoring heuristics for shell, secrets, network, and filesystem activity.
- CLI with text, JSON, and HTML report output.
- Example policy, trace, demo visuals, unit tests, and CI workflow.
