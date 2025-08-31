from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.jinja import TemplateEngine
from src.app.lifespan import ServerResources


BASE_DIR = Path(__file__).parent.parent.resolve()
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
DEBUG: bool = True

@asynccontextmanager
async def lifespan(app: FastAPI):

    template_engine = TemplateEngine.create(
        templates_dir=TEMPLATES_DIR,
    )
    resources = ServerResources(
        template_engine=template_engine,
    )

    try:
        yield resources()
    finally:
        pass


def create_app() -> FastAPI:

    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        lifespan=lifespan,
        title="Reconoscope - OSINT Web Application",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        debug=DEBUG,
    )

    app.mount(
        "/static",
        StaticFiles(directory=STATIC_DIR),
        name="static"
    )


    return app