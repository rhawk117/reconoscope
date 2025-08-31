



from dataclasses import dataclass
from app.jinja import TemplateEngine



@dataclass(slots=True)
class ServerResources:
    template_engine: TemplateEngine

    def __call__(self) -> dict:

        return {
            "template_engine": self.template_engine,
        }

