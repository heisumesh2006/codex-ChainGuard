"""Input contracts for the presentation API."""

from datetime import datetime, timezone
import json
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator
from backend.core.blockchain.evidence import aware_timestamp


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="allow")

    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    permission: str | None = None
    requested_permission: str | None = None
    timestamp: str | None = None
    target_agent: str | None = None
    delegatee: str | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_is_aware(cls, value):
        if value is None:
            return value
        return aware_timestamp(value).isoformat().replace("+00:00", "Z")

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
    authentication: dict[str, Any] | None = None


class AuditVerifyInput(BaseModel):
    """Optional off-chain record copy for forensic/tamper verification."""

    record_override: dict[str, Any] | None = None

    @field_validator("record_override")
    @classmethod
    def finite_record(cls, value):
        if value is not None:
            json.dumps(value, allow_nan=False)
        return value
