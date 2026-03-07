# pymobileconfig

Generate Apple mobileconfig configuration profiles from Python.

## Installation

```bash
pip install pymobileconfig
```

## Quick Start

```python
from pathlib import Path
from pymobileconfig import Profile, TrustedCertificate, SCEP, ManagedAppConfig

profile = (
    Profile(display_name="MDM Device Certificates", organisation="Acme Corp")
    .add(TrustedCertificate(
        display_name="Acme Root CA",
        certificate=Path("root_ca.crt"),   # PEM path, PEM bytes, or DER bytes
    ))
    .add(SCEP(
        display_name="Backend Certificate",
        url="https://ca.acme.com:9000/scep/scep",
        challenge="your-scep-challenge",
        subject=[("CN", "MY-DEVICE-001"), ("OU", "backend"), ("O", "Acme Corp")],
        keychain_access_groups=["$(AppIdentifierPrefix)com.acme.deviceclient"],
    ))
    .add(ManagedAppConfig(
        display_name="App Configuration",
        config={"api_base_url": "https://api.acme.com:8443"},
    ))
)

profile.write("device-enrollment.mobileconfig")
```

## Payloads

### `TrustedCertificate`

Installs a trusted root or intermediate CA certificate.

| Parameter | Type | Description |
|---|---|---|
| `display_name` | `str` | Label shown in Settings |
| `certificate` | `bytes \| Path` | PEM or DER bytes, or path to a PEM file |

### `SCEP`

SCEP certificate enrolment — used for Intune-managed device certificates.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `display_name` | `str` | — | Label shown in Settings |
| `url` | `str` | — | SCEP endpoint URL |
| `challenge` | `str` | — | SCEP challenge password |
| `subject` | `list` | — | X.509 subject as `[("CN", "..."), ("OU", "...")]` |
| `name` | `str` | `"scep"` | SCEP CA identifier |
| `key_type` | `str` | `"RSA"` | Key algorithm |
| `key_size` | `int` | `2048` | Key size in bits |
| `key_usage` | `int` | `5` | Key usage bitmask (1=signing, 4=encipherment) |
| `retries` | `int` | `3` | Enrolment retry count |
| `retry_delay` | `int` | `10` | Seconds between retries |
| `keychain_access_groups` | `list[str]` | `[]` | Keychain access groups for the enrolled cert |

### `PKCS12`

Installs a PKCS#12 certificate and private key bundle into the device keychain.

Appropriate for delivering shared server certificates where the same key is
intentionally distributed to multiple devices (e.g. a USB-C device server cert
shared across a fleet). For per-device identity certificates, use `SCEP` instead
— the private key never leaves the device's Secure Enclave.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `display_name` | `str` | — | Label shown in Settings |
| `pkcs12` | `bytes \| Path` | — | Raw `.p12` / `.pfx` bytes, or path to file |
| `password` | `str` | `""` | Passphrase for the PKCS#12 bundle |

### `ManagedAppConfig`

Delivers key-value configuration to an app via
`UserDefaults(suiteName: "com.apple.configuration.managed")`.

Supports standard plist types: `str`, `int`, `float`, `bool`, `list`, `dict`, `bytes`.

> **Do not store secrets here** — values are readable in plaintext by the app.

| Parameter | Type | Description |
|---|---|---|
| `display_name` | `str` | Payload label |
| `config` | `dict` | Key-value pairs to deliver to the app |

### `Profile`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `display_name` | `str` | — | Profile name shown in Settings |
| `organisation` | `str` | — | Organisation name |
| `description` | `str` | `""` | Optional description |
| `identifier` | `str` | auto | Reverse-DNS identifier (auto-generated if omitted) |
| `removal_disallowed` | `bool` | `False` | Prevent user removal |

#### Methods

- `profile.add(payload)` — add a payload, returns `self` for chaining
- `profile.dumps()` — serialise to XML plist `bytes`
- `profile.write(path)` — write mobileconfig to a file

## Production Deployment via Intune

For production, standard payload types (trusted cert, SCEP) are configured
directly in Intune without needing a mobileconfig file:

- **Trusted certificate**: Devices → Configuration → iOS/iPadOS → Trusted certificate
- **SCEP profile**: Devices → Configuration → iOS/iPadOS → SCEP certificate
- **App configuration**: Apps → App configuration policies → Managed devices

`pymobileconfig` is most useful for development testing (serving a profile
over HTTP for manual install) and for non-standard payload types that Intune
has no built-in UI for.

## Reading Managed App Config in Swift

```swift
let defaults = UserDefaults(suiteName: "com.apple.configuration.managed")
let apiURL = defaults?.string(forKey: "api_base_url") ?? "https://fallback.example.com"
```

## Development

```bash
git clone https://github.com/ZippyManaic/pymobileconfig
cd pymobileconfig
pip install -e ".[dev]"
pytest
```

## Licence

MIT
