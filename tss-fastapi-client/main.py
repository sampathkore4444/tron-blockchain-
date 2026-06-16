from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager

from models import KeygenRequest, SignRequest, KeygenResponse, SignResponse
from client import TSSClient

app = FastAPI(
    title="TSS MPC Wrapper (Python → Go)",
    description="FastAPI proxy/client for Go TSS server on localhost:8080",
    version="0.1.0",
)

# Global client (managed via lifespan)
tss_client: TSSClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    global tss_client
    tss_client = TSSClient(base_url="http://localhost:8080")
    yield
    await tss_client.close()


app.router.lifespan_context = lifespan


@app.post("/keygen", response_model=KeygenResponse)
async def perform_keygen(request: KeygenRequest):
    """
    Trigger threshold key generation.

    For real multi-party usage you need to call this endpoint
    on EVERY participating machine with the SAME peers list.
    """
    try:
        result = await tss_client.keygen(request)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/sign", response_model=SignResponse)
async def perform_sign(request: SignRequest):
    """
    Generate threshold ECDSA signature for the given message hash.

    Message should be a hex string of the 32-byte hash (keccak256 / sha256).
    """
    try:
        result = await tss_client.sign(request)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health")
async def health_check():
    return {"status": "ok", "tss_backend": "http://localhost:8080"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, reload=True)
