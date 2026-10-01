"""FastAPI Server Entry Point for Project Apocalypse."""

from apocalypse.server import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("apocalypse.server:app", host="0.0.0.0", port=8000, reload=True)
