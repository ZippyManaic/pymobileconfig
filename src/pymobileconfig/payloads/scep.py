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

# Subject may be supplied as simple pairs or the nested mobileconfig format.
#
# Simple (recommended):
#   [("CN", "device-001"), ("OU", "backend"), ("O", "Acme")]
#
# Nested (mobileconfig native format):
#   [[["CN", "device-001"]], [["OU", "backend"]], [["O", "Acme"]]]

SubjectPairs: TypeAlias = list[tuple[str, str]]
SubjectNested: TypeAlias = list[list[list[str]]]


def _normalise_subject(subject: SubjectPairs | SubjectNested) -> SubjectNested:
    if not subject:
        return []
    # If it's a list of tuples, or a list of lists where the first item isn't a list
    if isinstance(subject[0], tuple):
        return [[[k, v]] for k, v in cast(SubjectPairs, subject)]
    if isinstance(subject[0], list) and (not subject[0] or not isinstance(subject[0][0], list)):
        # Handle cases where it might be a flat list of lists [[k, v], [k, v]]
        return [[item] for item in cast(Any, subject)]
    return cast(SubjectNested, subject)


@dataclass(kw_only=True)
class SCEP(BasePayload):
    """
    SCEP certificate enrolment payload
    """

    PAYLOAD_TYPE: ClassVar[str] = "com.apple.security.scep"

    url: str
    challenge: str
    subject: SubjectPairs | SubjectNested
    name: str = "scep"
    key_type: str = "RSA"
    key_size: int = 2048
    # 5 = Digital Signature (1) + Key Encipherment (4)
    key_usage: int = 5
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
            "KeyUsage": self.key_usage,
            "Retries": self.retries,
            "RetryDelay": self.retry_delay,
            "KeyIsExtractable": self.key_is_extractable,
        }
        if self.subject_alt_name:
            content["SubjectAltName"] = self.subject_alt_name
        if self.ca_fingerprint:
            content["CAFingerprint"] = self.ca_fingerprint
        if self.keychain_access_groups:
            content["KeychainAccessGroups"] = self.keychain_access_groups
        d.update(content)
        return d
