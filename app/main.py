from fastapi import FastAPI

from app.api.auth import router as auth_router


app = FastAPI(
    title="Dustbin API",
    version="1.0.0",
)


app.include_router(
    auth_router
)


@app.get("/")
async def root():

    return {
        "message": "Dustbin API is running"
    }