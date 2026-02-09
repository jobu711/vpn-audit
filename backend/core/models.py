from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal


@dataclass
class AuditResult:
    """Result of a single VPN audit check."""

    status: Literal["pass", "fail", "warning"]
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
