# SPDX-License-Identifier: MIT
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from .base import BasePayload


def _load_certificate(source: bytes | Path) -> bytes:
    """Accept PEM or DER bytes, or a path to a PEM file. Returns DER bytes."""
    if isinstance(source, Path):
        source = source.read_bytes()
    if source.lstrip().startswith(b"-----"):
        return _pem_to_der(source)
    return source


def _pem_to_der(pem: bytes) -> bytes:
    lines = pem.decode().splitlines()
    b64 = "".join(ln for ln in lines if not ln.startswith("-----"))
    return base64.b64decode(b64)


@dataclass
class TrustedCertificate(BasePayload):
    """Installs a trusted root or intermediate CA certificate."""

    PAYLOAD_TYPE: ClassVar[str] = "com.apple.security.root"

    certificate: bytes | Path  # PEM (path or bytes) or DER bytes

    def to_dict(self, profile_identifier: str) -> dict:
        d = super().to_dict(profile_identifier)
        d["PayloadCertificateData"] = _load_certificate(self.certificate)
        return d
