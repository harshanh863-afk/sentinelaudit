"""SentinelAudit API — Production entry point."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.findings import router as findings_router
from app.api.v1.projects import router as projects_router
from app.api.v1.public import router as public_router
from app.api.v1.reports import router as reports_router
from app.api.v1.scans import router as scans_router
from app.api.v1.targets import router as targets_router
from app.core.config import settings
from app.core.environment import env_config
from app.core.logging import setup_logging
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.db.session import SessionLocal, engine

setup_logging("DEBUG" if settings.debug else "INFO")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    from app.services.rule_engine.rule_seeder import seed_rules
    from app.services.rule_engine.rule_validator import RuleValidator

    # Validate rules during startup
    try:
        validator = RuleValidator()
        validator.validate_all()
        logger.info("LIFESPAN: all rules validated successfully")
    except Exception as exc:
        logger.warning("LIFESPAN: rule validation warning: %s", exc)

    db = SessionLocal()
    try:
        seeded = seed_rules(db)
        if seeded:
            logger.info("LIFESPAN: seeded %d rules on startup", seeded)
    except Exception as exc:
        logger.warning("LIFESPAN: rule seeding skipped: %s", exc)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

# ── Security Headers ──────────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)

# ── CORS ──────────────────────────────────────────────────────────
if env_config.is_production:
    allowed_origins = [env_config.FRONTEND_URL]
    allow_creds = True
else:
    allowed_origins = ["*"]
    allow_creds = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=allow_creds,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request size limit middleware ─────────────────────────────────
@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    if request.method == "POST":
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 1024 * 100:  # 100KB
            return JSONResponse(
                status_code=413,
                content={"detail": "Request too large"},
            )
    response = await call_next(request)
    return response


# ── Routers ───────────────────────────────────────────────────────
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
app.include_router(projects_router, prefix="/api/v1")
app.include_router(public_router, prefix="/api")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(targets_router, prefix="/api/v1")

# Enterprise routers (lazy-loaded)
try:
    from app.api.v1.exports import router as exports_router
    app.include_router(exports_router, prefix="/api/v1")
    logger.info("MAIN: export endpoints registered")
except Exception as exc:
    logger.warning("MAIN: export endpoints skipped: %s", exc)


# ── Health endpoints ──────────────────────────────────────────────
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health/database")
def health_database():
    try:
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        return {"status": "healthy", "service": "database"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database unavailable: {str(e)}")


@app.get("/health/worker")
def health_worker():
    try:
        from app.workers.celery_app import celery_app
        stats = celery_app.control.inspect().stats()
        if stats:
            return {
                "status": "healthy",
                "service": "worker",
                "workers": list(stats.keys()),
            }
        return {"status": "degraded", "service": "worker", "detail": "No active workers"}
    except Exception as e:
        return {"status": "degraded", "service": "worker", "detail": str(e)}
