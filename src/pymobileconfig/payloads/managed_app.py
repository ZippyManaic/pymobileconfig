# SPDX-License-Identifier: MIT
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from .base import BasePayload


@dataclass(kw_only=True)
class ManagedAppConfig(BasePayload):
    """
    Managed app configuration payload

    Delivers key-value configuration to an iOS/macOS app via
    UserDefaults(suiteName: "com.apple.configuration.managed").

    Supports standard plist types: str, int, float, bool, list, dict, bytes.

    Do not store secrets here — values are readable in plaintext by the app
    """

    PAYLOAD_TYPE: ClassVar[str] = "com.apple.configuration.managed"

    config: dict[str, Any]

    def to_dict(self, profile_identifier: str) -> dict[str, Any]:
        d = super().to_dict(profile_identifier)
        d.update(self.config)
        return d
