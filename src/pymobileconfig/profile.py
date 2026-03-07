# SPDX-License-Identifier: MIT
from __future__ import annotations

import plistlib
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .payloads.base import BasePayload


@dataclass
class Profile:
    """
    An Apple mobileconfig configuration profile
    """

    display_name: str
    organisation: str
    description: str = ""
    identifier: str = ""
    removal_disallowed: bool = False

    _uuid: str = field(
        default_factory=lambda: str(uuid.uuid4()).upper(),
        repr=False,
        init=False,
    )
    _payloads: list[BasePayload] = field(
        default_factory=list[BasePayload],
        repr=False,
        init=False,
    )

    def __post_init__(self) -> None:
        if not self.identifier:
            slug = self.organisation.lower().replace(" ", "")
            self.identifier = f"com.{slug}.profile.{self._uuid}"

    def add(self, payload: BasePayload) -> Profile:
        """
        Add a payload to the profile. Returns self for chaining
        """
        self._payloads.append(payload)
        return self

    def to_dict(self) -> dict[str, Any]:
        """
        Return the profile as a Python dict (plist-compatible)
        """
        return {
            "PayloadDisplayName": self.display_name,
            "PayloadDescription": self.description,
            "PayloadIdentifier": self.identifier,
            "PayloadOrganization": self.organisation,
            "PayloadRemovalDisallowed": self.removal_disallowed,
            "PayloadType": "Configuration",
            "PayloadUUID": self._uuid,
            "PayloadVersion": 1,
            "PayloadContent": [p.to_dict(self.identifier) for p in self._payloads],
        }

    def dumps(self) -> bytes:
        """
        Serialise to XML plist bytes
        """
        return plistlib.dumps(self.to_dict(), fmt=plistlib.FMT_XML)

    def write(self, path: Path | str) -> None:
        """
        Write the mobileconfig to a file
        """
        with open(path, "wb") as f:
            plistlib.dump(self.to_dict(), f, fmt=plistlib.FMT_XML)
