## Purpose

Defines how Security License Lens is installed and released so strangers and conference attendees can obtain a tagged talk-ready build without cloning from source.

## ADDED Requirements

### Requirement: PyPI-installable package
The project MUST be publishable to PyPI as `licenselens` such that `pipx install licenselens` (or `pip install licenselens`) installs the `licenselens` console entrypoint.

#### Scenario: Entry point present
- **WHEN** the package is installed from the talk-ready distribution
- **THEN** running `licenselens version` prints the product name and version

### Requirement: Container escape hatch
A container image MUST be available that runs a dry-run or live scan and can write reports to a mounted output directory, documented as the alternate install path.

#### Scenario: Docker dry-run
- **WHEN** a user runs the documented container command with an output mount
- **THEN** an HTML report appears in the mounted directory without a local Python env

### Requirement: Tagged talk-ready release
By the talk-ready gate, a GitHub Release (or equivalent) MUST exist for the frozen version with release notes covering packs, known limitations, and the hallway-line thesis.

#### Scenario: Version alignment
- **WHEN** users install the talk-ready tag
- **THEN** `licenselens version` matches the release tag semantic version

### Requirement: No telemetry by default
Distributed builds MUST NOT enable outbound product telemetry by default. Scan data MUST remain on the operator machine unless the operator exports it.

#### Scenario: Default scan network use
- **WHEN** a user runs a live scan
- **THEN** network calls are only to Microsoft/Azure endpoints required for auth and collection (plus any user-configured proxies), not to a License Lens analytics service
