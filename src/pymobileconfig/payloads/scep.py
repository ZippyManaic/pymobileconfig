# SPDX-License-Identifier: MIT
from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from .base import BasePayload

# Subject may be supplied as simple pairs or the nested mobileconfig format.
#
# Simple (recommended):
#   [("CN", "device-001"), ("OU", "backend"), ("O", "Acme")]
#
# Nested (mobileconfig native format):
#   [[["CN", "device-001"]], [["OU", "backend"]], [["O", "Acme"]]]

SubjectPairs = list[tuple[str, str]]
SubjectNested = list[list[list[str]]]


def _normalise_subject(subject: SubjectPairs | SubjectNested) -> SubjectNested:
    if not subject:
        return []
    if isinstance(subject[0], (list, tuple)) and isinstance(subject[0][0], list):
        return subject  # type: ignore[return-value]
    return [[[k, v]] for k, v in subject]  # type: ignore[misc]


@dataclass
class SCEP(BasePayload):
    """SCEP certificate enrolment payload."""

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
    keychain_access_groups: list[str] = field(default_factory=list)

    def to_dict(self, profile_identifier: str) -> dict:
        d = super().to_dict(profile_identifier)
        content: dict = {
            "URL": self.url,
            "Name": self.name,
            "Challenge": self.challenge,
            "Subject": _normalise_subject(self.subject),
            "KeyType": self.key_type,
            "KeySize": self.key_size,
            "KeyUsage": self.key_usage,
            "Retries": self.retries,
            "RetryDelay": self.retry_delay,
        }
        if self.keychain_access_groups:
            content["KeychainAccessGroups"] = self.keychain_access_groups
        d["PayloadContent"] = content
        return d
