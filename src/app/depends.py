
import typing

from fastapi import Depends, Request
from fastapi.templating import Jinja2Templates

from app.lifespan import ServerResources

async def get_server_resources(request: Request) -> ServerResources:
    return typing.cast(ServerResources, request.state.resources)


ResourcesDep = typing.Annotated[ServerResources, Depends(get_server_resources)]

async def get_jinja(resources: ResourcesDep) -> Jinja2Templates:
    return resources.template_engine.jinja


JinjaDep = typing.Annotated[Jinja2Templates, Depends(get_jinja)]

