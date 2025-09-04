


import asyncio
from pathlib import Path
import sys
from rich.console import Console
import httpx
import argparse
import dataclasses
from loguru import logger

from cli import http_utils
from cli.internals import (
    ArgumentModel,
    cli_arg,
    get_argparse_arguments,
    Renderable
)


LOGURU_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)

logger.add(
    sys.stdout,
    format=LOGURU_FORMAT,
    level="INFO",
    colorize=True,
    backtrace=True,
    diagnose=True,
    enqueue=True,
)


@dataclasses.dataclass
class StandardArgs(ArgumentModel):
    domain: str | None = cli_arg(
        "--domain",
        help="Domain name to enumerate subdomains and perform DNS lookup",
    )

    ip: str | None = cli_arg(
        "--ip",
        help="IP address to fetch geolocation and ASN info",
    )

    phone: str | None = cli_arg(
        "--phone",
        help="Phone number to validate and get info about",
    )

    url_list: str | None = cli_arg(
        "--url-list",
        help="File containing list of URLs to check for account existence",
    )

    username: str | None = cli_arg(
        "--username",
        help="Username to check for account existence on common platforms",
    )




class _HttpRoutines:
    def __init__(self, client: httpx.AsyncClient):
        self.tasks = []
        self.client: httpx.AsyncClient = client

    def collect(self, options: StandardArgs) -> None:
        if options.domain:
            from cli import domains
            self.tasks.append(
                domains.lookup_domain_name(options.domain, client=self.client)
            )
            self.tasks.append(
                domains.enumerate_subdomains(options.domain, client=self.client)
            )

        if options.ip:
            from cli import ips
            self.tasks.append(ips.get_ip_info(options.ip, client=self.client))

    async def gather(self):
        if not self.tasks:
            return
        for fut in await asyncio.gather(*self.tasks, return_exceptions=True):
            if isinstance(fut, Exception):
                logger.error(f"Error during lookup: {fut}")
            elif isinstance(fut, Renderable):
                yield fut
            else:
                logger.warning(f"Unknown result type: {type(fut)} - {fut}")
        self.tasks.clear()

    @classmethod
    async def stream(cls, args: StandardArgs, client: httpx.AsyncClient):
            routines = cls(client=client)
            routines.collect(args)
            async for result in routines.gather():
                yield result


def read_url_list(file_path: str, profile: str) -> list[str]:
    txt_file = Path(file_path)
    if not txt_file.is_file() or not txt_file.exists():
        raise FileNotFoundError(f"URL list file not found: {file_path}")

    url_lines = txt_file.read_text().splitlines()

    urls: list[str] = []
    for line in url_lines:
        if not (stripped := line.strip()):
            continue
        urls.append(stripped.format(profile=profile))


async def run() -> None:
    parser = argparse.ArgumentParser(
        description="Reconoscope - OSINT Command Line Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    args = get_argparse_arguments(parser, StandardArgs)

    console = Console()
    console.print(f"""
[bold blue]Reconoscope - OSINT Command Line Tool[/bold blue]

[green]Arguments[/green]:
{args.show()}

[italic]Starting lookups...[/italic]
    """)

    client_config = http_utils.HTTPClientConfig()

    async with client_config.makeclient() as client:
        async for result in _HttpRoutines.stream(args, client):
            console.print(result.console_output())

    if args.phone:
        from cli import phone_num
        phone_result = phone_num.get_phone_info(args.phone)
        console.print(phone_result.console_output())

    if args.url_list and args.username:
        urls = read_url_list(args.url_list, profile=args.username)
        blaster = http_utils.RequestBlaster(concurrency=20)
        results = await blaster(
            urls=urls,
            client_config=client_config,
        )