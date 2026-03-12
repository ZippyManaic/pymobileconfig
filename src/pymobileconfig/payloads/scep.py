# SPDX-License-Identifier: MIT
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, TypeAlias, cast


def ca_fingerprint_from_cert(cert_path: str | Path) -> bytes:
    """
    Return the SHA-1 fingerprint of a PEM certificate as raw bytes.

    This is the value iOS uses to verify the SCEP server's identity when
    ``CAFingerprint`` is present in the SCEP payload.  It must match the
    SHA-1 of the DER-encoded certificate returned by the SCEP
    ``GetCACert`` operation (typically the intermediate CA).

    Requires ``openssl`` on PATH.
    """
    der = subprocess.check_output(
        ["openssl", "x509", "-in", str(cert_path), "-outform", "DER"]
    )
    return hashlib.sha1(der).digest()

from .base import BasePayload

# Subject may be supplied as simple pairs or the Apple mobileconfig native format.
#
# Apple's SCEP profile spec requires triple nesting — each RDN is wrapped in its
# own array so that multi-valued RDNs are representable:
#   [ [["CN","device-001"]], [["OU","backend"]], [["O","Acme"]] ]
#
# Callers may pass the simpler pair formats; _normalise_subject converts them:
#
# Tuple pairs (recommended input):
#   [("CN", "device-001"), ("OU", "backend"), ("O", "Acme")]
#
# List pairs:
#   [["CN", "device-001"], ["OU", "backend"], ["O", "Acme"]]

SubjectPairs: TypeAlias = list[tuple[str, str]]
SubjectFlat: TypeAlias = list[list[str]]
SubjectNested: TypeAlias = list[list[list[str]]]


def _normalise_subject(subject: SubjectPairs | SubjectFlat | SubjectNested) -> SubjectNested:
    if not subject:
        return []
    first = subject[0]
    # Already in nested format: [[["CN", "val"]], ...]
    if isinstance(first, list) and first and isinstance(first[0], list):
        return cast(SubjectNested, subject)
    # Tuple pairs or list pairs: [("CN","val"), ...] or [["CN","val"], ...]
    return [[[str(k), str(v)]] for k, v in subject]  # type: ignore[misc]


@dataclass(kw_only=True)
class SCEP(BasePayload):
    """
    SCEP certificate enrolment payload
    """

    PAYLOAD_TYPE: ClassVar[str] = "com.apple.security.scep"

    url: str
    challenge: str
    subject: SubjectPairs | SubjectFlat
    name: str = "scep"
    key_type: str = "RSA"
    key_size: int = 2048
    key_usage: int = 5  # 5 = Digital Signature (1) + Key Encipherment (4); 0 = omit
    retries: int = 3
    retry_delay: int = 10
    key_is_extractable: bool = False
    subject_alt_name: dict[str, Any] = field(default_factory=dict[str, Any])
    ca_fingerprint: bytes = b""
    keychain_access_groups: list[str] = field(default_factory=list[str])

    def to_dict(self, profile_identifier: str) -> dict[str, Any]:
        d = super().to_dict(profile_identifier)
        content: dict[str, Any] = {
            "URL": self.url,
            "Name": self.name,
            "Challenge": self.challenge,
            "Subject": _normalise_subject(self.subject),
            "KeyType": self.key_type,
            "Keysize": self.key_size,
            "Retries": self.retries,
            "RetryDelay": self.retry_delay,
            "KeyIsExtractable": self.key_is_extractable,
        }
        if self.key_usage:
            content["KeyUsage"] = self.key_usage
        if self.subject_alt_name:
            content["SubjectAltName"] = self.subject_alt_name
        if self.ca_fingerprint:
            content["CAFingerprint"] = self.ca_fingerprint
        if self.keychain_access_groups:
            content["KeychainAccessGroups"] = self.keychain_access_groups
        d["PayloadContent"] = content
        return d
