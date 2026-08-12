from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class GenerationInfo:
    """Describes the AI system that produced an image, for the C2PA manifest."""

    generator_name: str
    generator_version: str
    prompt: str | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
