"""Q-ARMOR — Production Entry Point (detected by Railway/Render)."""

from backend.app import app  # noqa: F401 — re-export for uvicorn auto-detection

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
