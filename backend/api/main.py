from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router as api_router
from backend.api.websocket import router as ws_router

app = FastAPI(title="VPN Audit Tool", version="0.1.0")

app.include_router(api_router)
app.include_router(ws_router)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


# Static file mount MUST be last so API/WS routes take priority.
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
