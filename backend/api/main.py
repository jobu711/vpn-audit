from fastapi import FastAPI

app = FastAPI(title="VPN Audit Tool", version="0.1.0")


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}
