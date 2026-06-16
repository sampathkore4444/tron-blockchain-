import httpx
from typing import Dict, Any, Optional

from models import KeygenRequest, SignRequest, KeygenResponse, SignResponse


class TSSClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.AsyncClient(
            timeout=120.0,  # generous timeout since TSS can take time
            follow_redirects=True,
        )

    async def close(self):
        await self.client.aclose()

    async def keygen(self, req: KeygenRequest) -> KeygenResponse:
        try:
            response = await self.client.post(
                f"{self.base_url}/keygen",
                json=req.model_dump(mode="json"),
            )
            response.raise_for_status()
            data = response.json()
            return KeygenResponse(**data)
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except:
                detail = str(e)
            raise ValueError(f"Keygen failed ({e.response.status_code}): {detail}")
        except Exception as e:
            raise ValueError(f"Keygen request error: {str(e)}")

    async def sign(self, req: SignRequest) -> SignResponse:
        try:
            response = await self.client.post(
                f"{self.base_url}/sign",
                json=req.model_dump(mode="json"),
            )
            response.raise_for_status()
            data = response.json()
            return SignResponse(**data)
        except httpx.HTTPStatusError as e:
            try:
                detail = e.response.json().get("detail", str(e))
            except:
                detail = str(e)
            raise ValueError(f"Sign failed ({e.response.status_code}): {detail}")
        except Exception as e:
            raise ValueError(f"Sign request error: {str(e)}")
