"""Input contracts for the presentation API."""

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="allow")

    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    permission: str | None = None
    requested_permission: str | None = None
    timestamp: str | None = None
    target_agent: str | None = None
    delegatee: str | None = None

    def as_injected_action(self) -> dict[str, Any]:
        """Mark user input as synthetic so Module 6 applies live Module 1 checks."""
        data = self.model_dump(exclude_none=True)
        data.pop("record_id", None)
        data.pop("trace_result", None)
        data["record_id"] = f"synthetic:api:{uuid4()}"
        data.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        return data


class GovernanceStreamRequest(BaseModel):
    scenario: str | None = None
    action: ActionInput | None = None
