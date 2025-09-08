

from pathlib import Path
import sys

from rich.console import Console
import dataclasses as dc

def load_url_account_list(file_path: str, account: str) -> list[str]:
    txt_file = Path(file_path)
    if not txt_file.is_file() or not txt_file.exists():
        raise FileNotFoundError(f"URL list file not found: {file_path}")

    url_lines = txt_file.read_text().splitlines()

    urls: list[str] = []
    for line in url_lines:
        line = line.strip()
        if "{account}" not in line:
            print(f"Skipping line without '{{account}}' placeholder: {line}")
            continue

        line = line.format(account=account)
        urls.append(line)

    return urls


@dc.dataclass(slots=True)
class AutoRunModule:
    _console: Console = dc.field(default_factory=Console, init=False)
    module_name: str
    usage: str
    description: str

    @property
    def header(self) -> str:
        line = '-' * 60
        return (
            f'[bold blue]{line}[/]\n'
            '[italic green]Reconoscope - OSINT Reconnaissance Tool[/]\n'
            f'[bold blue]{line}[/]\n'
            f'[bold]Usage:[/]\n{self.usage}\n'
            f'[bold blue]{self.module_name} AutoRun[/]\n'
            f'[italic]{self.description}[/]\n'
        )

    def get_input(self, prompt: str) -> str:
        if len(sys.argv) > 1:
            return sys.argv[1]

        return self._console.input(
            f'[green](?)[/][italic]{prompt}[/] '
            '[bold green]>[/] '
        )


