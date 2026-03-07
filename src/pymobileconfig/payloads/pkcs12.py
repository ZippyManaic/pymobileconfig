# SPDX-License-Identifier: MIT
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from .base import BasePayload


@dataclass
class PKCS12(BasePayload):
    """
    PKCS#12 identity certificate payload

    Installs a certificate and private key bundle into the device keychain.
    The private key is embedded in the profile in encrypted form, protected
    by the supplied password.

    Appropriate for delivering shared server certificates where the same key
    is intentionally distributed to multiple devices (e.g. a device
    server cert shared across a fleet). Do not use for per-device identity
    certificates — use SCEP for those, so the private key never leaves the
    device's Secure Enclave
    """

    PAYLOAD_TYPE: ClassVar[str] = "com.apple.security.pkcs12"

    pkcs12: bytes | Path  # raw .p12 / .pfx bytes, or path to file
    password: str = ""

    def to_dict(self, profile_identifier: str) -> dict[str, Any]:
        d = super().to_dict(profile_identifier)
        data = (
            self.pkcs12
            if isinstance(self.pkcs12, bytes)
            else Path(self.pkcs12).read_bytes()
        )
        d["PayloadContent"] = data
        if self.password:
            d["Password"] = self.password
        return d
