

from dataclasses import dataclass
from pathlib import Path
from typing import Self
from jinja2 import Environment, FileSystemLoader
from fastapi.templating import Jinja2Templates

@dataclass
class TemplateEngine:
    templates_dir: Path
    _backend: Jinja2Templates

    @classmethod
    def create(
        cls,
        *,
        templates_dir: Path,
        jinja_globals: dict | None = None,
    ) -> Self:
        environment = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=True,
            auto_reload=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        environment.filters.update({
            'currency': lambda value: f"${value:,.2f}",
            'datetime': lambda value: value.strftime("%Y-%m-%d %H:%M:%S"),
            'truncate': lambda value, length=100: (value[:length] + '...') if len(value) > length else value,
        })

        if jinja_globals:
            environment.globals.update(jinja_globals)

        backend = Jinja2Templates(
            directory=str(templates_dir),
            env=environment,
        )

        return cls(
            templates_dir=templates_dir,
            _backend=backend,
        )

    @property
    def jinja(self) -> Jinja2Templates:
        return self._backend