"""API for neptune"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .crud import api_router as crud_router
from .scan import api_router as scan_router

neptune_api = FastAPI(
    title="Neptune API",
    version="0.6.0",
    description="Containers SBOM & vulnerability management",
    redoc_url=None,
    docs_url="/api",
    openapi_url="/api/openapi.json"
)

neptune_api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

neptune_api.include_router(scan_router)
neptune_api.include_router(crud_router)

neptune_api.mount(
    path="/",
    app=StaticFiles(directory="/app/dist", html=True),
    name="ui")
