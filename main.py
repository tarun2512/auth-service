import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scripts.services.traveller_auth_service import traveller_login_router
from scripts.db_connections.psql.datamodels.models import User, TravellerProfile
from scripts.utils.postgres_util import (
    create_table,
)
from scripts.utils.security_utils.decorators import CookieAuthentication

secure_access = os.environ.get("SECURE_ACCESS", default=False)

auth = CookieAuthentication()
app = FastAPI(
    title="Travel Auth Service",
    version="7.09",
    description="Auth-Service Microservice",
    docs_url=os.environ.get("SW_DOCS_URL"),
    redoc_url="/redoc",
    root_path="/auth-service",
    openapi_url=os.environ.get("SW_OPENAPI_URL"),
)


@app.get("/api/auth-service/healthcheck")
async def ping():
    return {"status": 200}


if secure_access in [True, "true", "True"]:
    app.include_router(traveller_login_router, dependencies=[Depends(auth)])
else:
    app.include_router(traveller_login_router)

if os.environ.get("ENABLE_CORS") in (True, "true", "True") and os.environ.get("CORS_URLS"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_URLS").split(","),
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "PUT"],
        allow_headers=["*"],
    )