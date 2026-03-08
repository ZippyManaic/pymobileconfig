# pymobileconfig Project Context

`pymobileconfig` is a Python library (3.10+) designed to generate Apple `.mobileconfig` configuration profiles programmatically. It provides a clean, dataclass-based API to construct profiles containing various payload types, primarily for use in development testing and MDM (Mobile Device Management) scenarios.

## Core Technologies
- **Python 3.10+**: Utilises modern features like `dataclasses`, `__future__.annotations`, and `type` hints.
- **Build System**: [Hatchling](https://hatch.pypa.io/) is used as the build backend (`pyproject.toml`).
- **Standard Library**: Extensively uses `plistlib` for XML plist generation and `uuid` for identifier management.
- **Testing**: [pytest](https://docs.pytest.org/) for unit and integration testing.
- **Type Checking**: [Pyright](https://github.com/microsoft/pyright) configured in `strict` mode (`pyrightconfig.json`).

## Project Architecture
The project is structured under `src/pymobileconfig/`:

- **`profile.py`**: Contains the `Profile` class, which acts as the top-level container for a `.mobileconfig`. It manages profile-level metadata (organisation, identifier, UUID) and a list of payloads.
- **`payloads/`**: A directory containing individual payload implementations, all inheriting from `BasePayload` in `base.py`.
  - **`base.py`**: Defines the `BasePayload` abstract base class with common fields like `display_name` and `_uuid`, and the `to_dict` method.
  - **`managed_app.py`**: Implements `ManagedAppConfig` (`com.apple.configuration.managed`) for delivering app-specific settings.
  - **`pkcs12.py`**: Implements `PKCS12` (`com.apple.security.pkcs12`) for certificate/key bundle delivery.
  - **`scep.py`**: Implements `SCEP` (`com.apple.security.scep`) for over-the-air certificate enrolment.
  - **`trusted_cert.py`**: Implements `TrustedCertificate` (`com.apple.security.root` or `com.apple.security.pkcs1`) for CA certificate installation.

## Development & Testing

### Installation
To set up the development environment:
```bash
pip install -e ".[dev]"
```

### Running Tests
Tests are located in the `tests/` directory and use `pytest`:
```bash
pytest
```
Coverage can be checked if `pytest-cov` is installed (included in `dev` extras).

### Type Checking
The project uses strict type checking with Pyright:
```bash
pyright
```

## Engineering Standards & Conventions
- **SPDX Headers**: All source files should start with `# SPDX-License-Identifier: MIT`.
- **Typing**: Use `from __future__ import annotations` and provide comprehensive type hints for all parameters and return values.
- **Dataclasses**: Use `@dataclass` for domain models (Profile and Payloads) to maintain a clean, declarative API.
- **Immutability (Internal)**: Internal fields like `_uuid` and `_payloads` are managed via `field(init=False, repr=False)` to prevent accidental mutation while keeping the public API simple.
- **Fluent API**: The `Profile.add()` method returns `self` to allow for a fluent, chainable API (e.g., `Profile(...).add(...).add(...)`).
- **Input Handling**: Path-related arguments should support both `str` and `pathlib.Path`. Certificate data should support `bytes` and `Path`.

## Known Constraints
- **Plist Compatibility**: Ensure all data added to profiles (especially in `ManagedAppConfig`) is compatible with `plistlib` supported types (`str`, `int`, `float`, `bool`, `list`, `dict`, `bytes`, `datetime`).
- **Security**: Be mindful that `ManagedAppConfig` values are readable in plaintext by the target application; do not store sensitive secrets there.
