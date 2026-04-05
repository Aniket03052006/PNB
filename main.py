"""Q-ARMOR — Production Entry Point (detected by Railway/Render)."""

import gc
gc.set_threshold(400, 10, 10)  # More aggressive GC to reclaim scan intermediates

from backend.app import app  # noqa: F401 — re-export for uvicorn auto-detection

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
