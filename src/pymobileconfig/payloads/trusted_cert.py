# SPDX-License-Identifier: MIT
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from .base import BasePayload


def _load_certificate(source: bytes | Path) -> bytes:
    """
    Accept PEM or DER bytes, or a path to a PEM/DER file.
    Returns DER bytes
    """
    if isinstance(source, Path):
        source = source.read_bytes()
    # Check if it looks like PEM
    if b"-----BEGIN" in source:
        return _pem_to_der(source)
    return source


def _pem_to_der(pem: bytes) -> bytes:
    """
    Extract the first certificate from a PEM file and return its DER bytes.
    """
    # Find everything between the first set of BEGIN/END delimiters
    match = re.search(
        b"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
        pem,
        re.DOTALL,
    )
    if not match:
        raise ValueError("No valid certificate found in PEM data")

    # Remove any whitespace/newlines and decode
    b64_data = match.group(1).replace(b"\n", b"").replace(b"\r", b"").strip()
    return base64.b64decode(b64_data)


@dataclass(kw_only=True)
class TrustedCertificate(BasePayload):
    """
    Installs a trusted root or intermediate CA certificate
    """

    PAYLOAD_TYPE: ClassVar[str] = "com.apple.security.root"

    certificate: bytes | Path  # PEM (path or bytes) or DER bytes
    payload_type: str = "com.apple.security.root"

    def to_dict(self, profile_identifier: str) -> dict[str, Any]:
        d = super().to_dict(profile_identifier)
        # Override the PayloadType if provided in the constructor
        d["PayloadType"] = self.payload_type
        d["PayloadCertificateData"] = _load_certificate(self.certificate)
        return d
