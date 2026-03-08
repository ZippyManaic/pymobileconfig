# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass(kw_only=True)
class BasePayload:
    """
    Base class for all mobileconfig payload types
    """

    PAYLOAD_TYPE: ClassVar[str]

    display_name: str
    uuid: str = field(default_factory=lambda: str(uuid.uuid4()).upper())

    def to_dict(self, profile_identifier: str) -> dict[str, Any]:
        return {
            "PayloadDisplayName": self.display_name,
            "PayloadIdentifier": f"{profile_identifier}.{self.PAYLOAD_TYPE}.{self.uuid}",
            "PayloadType": self.PAYLOAD_TYPE,
            "PayloadUUID": self.uuid,
            "PayloadVersion": 1,
        }
