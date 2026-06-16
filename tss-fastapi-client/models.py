from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class KeygenRequest(BaseModel):
    party_id: str = Field(..., description="This party's identifier")
    peers: List[str] = Field(..., description="List of all party IDs including self")
    threshold: int = Field(..., ge=1, description="Threshold for signing (t)")


class KeygenResponse(BaseModel):
    status: str
    party: str
    detail: Optional[str] = None


class SignRequest(BaseModel):
    party_id: str = Field(..., description="This party's identifier")
    message: str = Field(
        ..., description="Hex-encoded message digest (32 bytes for secp256k1)"
    )


class SignResponse(BaseModel):
    R: str
    S: str
    Signature: str
    Recovery: str
    detail: Optional[str] = None
