# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, ClassVar


@dataclass
class BasePayload:
    """
    Base class for all mobileconfig payload types
    """

    PAYLOAD_TYPE: ClassVar[str]

    display_name: str

    _uuid: str = field(
        default_factory=lambda: str(uuid.uuid4()).upper(),
        repr=False,
        init=False,
    )

    def to_dict(self, profile_identifier: str) -> dict[str, Any]:
        return {
            "PayloadDisplayName": self.display_name,
            "PayloadIdentifier": f"{profile_identifier}.{self.PAYLOAD_TYPE}.{self._uuid}",
            "PayloadType": self.PAYLOAD_TYPE,
            "PayloadUUID": self._uuid,
            "PayloadVersion": 1,
        }
