


import asyncio
import sys
from rich.console import Console
import httpx
import argparse
import dataclasses
from cli import http_utils
from loguru import logger

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





class _HttpRoutines:
    def __init__(self, client: httpx.AsyncClient):
        self.tasks = []
        self.client = client

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

    @classmethod
    async def stream(cls, args: StandardArgs):
        async with http_utils.makeclient(10) as client:
            routines = cls(client=client)
            routines.collect(args)
            async for result in routines.gather():
                yield result



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

    async for result in _HttpRoutines.stream(args):
        console.print(result.console_output())

    if args.phone:
        from cli import phone_num
        phone_result = phone_num.get_phone_info(args.phone)
        console.print(phone_result.console_output())
