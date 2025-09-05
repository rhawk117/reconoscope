


import argparse
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import sys
from typing import TypeVar
from rich.console import Console
from loguru import logger
from cli.internals import ArgparseModel, cli_arg, CLIGroup
from core import httpclient
from modules.models import Renderable


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

@dataclass
class EmailArgs(ArgparseModel):
    email: str = cli_arg(
        "--email",
        required=False,
        help="Email address to analyze headers and search for breaches",
    )
    headers: str | None = cli_arg(
        "--headers",
        required=False,
        help="Path to a file containing raw email headers to analyze",
    )

@dataclass
class DomainArgs(ArgparseModel):
    name: str = cli_arg(
        "--name",
        required=True,
        help="Domain name to enumerate subdomains and perform DNS lookup",
    )
    is_blocked: bool = cli_arg(
        "--is-blocked",
        default=False,
        action="store_true",
        help="Check if the domain is listed in known DNS blocklists",
    )

@dataclass
class IPArgs(ArgparseModel):
    ip: str = cli_arg(
        "--ip",
        required=True,
        help="IP address to fetch geolocation and ASN info",
    )
    reverse_dns: bool = cli_arg(
        "--reverse-dns",
        default=False,
        action="store_true",
        help="Perform reverse DNS lookup on the IP address",
    )

@dataclass
class HttpProbeArgs(ArgparseModel):
    account: str = cli_arg(
        "--account",
        required=True,
        help="Account username to check for existence on common platforms",
    )

    concurrency: int = cli_arg(
        "--concurrency",
        default=100,
        type=int,
        help="Number of concurrent requests to make",
    )

    shards: int = cli_arg(
        "--shards",
        default=5,
        type=int,
        help="Number of shards to split the URL list into for processing",
    )


@dataclass
class MiscArgs(ArgparseModel):
    phone_number: str = cli_arg(
        "--phone-number",
        required=False,
        help="Phone number to gather information about, e.g. +14155552671",
    )
    website: str = cli_arg(
        "--website",
        required=False,
        help="Website URL to fetch metadata from, e.g. https://example.com",
    )


A = TypeVar("A", bound=ArgparseModel)


class DomainGroup(CLIGroup[DomainArgs]):
    model = DomainArgs

    @asynccontextmanager
    async def _client(self):
        async with httpclient.makeclient() as client:
            yield client

    async def routine(self, args: DomainArgs) -> None:
        from modules.domain import (
            AsyncDomainLookup,
            CertshSubdomainEnumerator,
            DnsBlocklistSearch,
        )

        if args.is_blocked:
            async with self._client() as client:
                result = await DnsBlocklistSearch.run(client, args.name)
            self.console.print(result.render())
            return

        async with self._client() as client:
            futures = (
                AsyncDomainLookup.run(args.name),
                CertshSubdomainEnumerator.run(client, args.name),
            )
            for coro in await asyncio.gather(*futures):
                self.console.print(coro.render())


class IPGroup(CLIGroup[IPArgs]):
    model = IPArgs

    @asynccontextmanager
    async def _client(self):
        async with httpclient.makeclient() as client:
            yield client

    async def routine(self, args: IPArgs) -> None:
        from modules.ips import IPInfoCollector
        from modules.domain import ReverseDnsLookup

        async with self._client() as client:
            futures: list = [IPInfoCollector.run(client, args.ip)]
            if args.reverse_dns:
                futures.append(ReverseDnsLookup.run(args.ip))

            results: list[Renderable] = await asyncio.gather(*futures)
            for coro in results:
                self.console.print(coro.render())


class EmailGroup(CLIGroup[EmailArgs]):
    model = EmailArgs

    async def run_header(self, header_text: str) -> Renderable:
        from modules.email import EmailHeaderAnalyzer

        async with httpclient.makeclient() as client:
            return await EmailHeaderAnalyzer.run(
                raw_header=header_text,
                client=client,
            )

    async def routine(self, args: EmailArgs) -> None:
        console = Console()

        if args.headers:
            result = await self.run_header(args.headers)
        else:
            from modules.domain import EmailDomainSearch

            result = await EmailDomainSearch.run(args.email)

        console.print(result.render())


class ProbeGroup(CLIGroup[HttpProbeArgs]):
    model = HttpProbeArgs
    default_url_list = "data/account_search_list.txt"

    def render_result(self, result: dict) -> None:
        status = "[green]Success[/green]" if result["success"] else "[red]Failed[/red]"
        self.console.print(f"""
        -------------------------------------
        [bold]URL:[/bold]{result["url"]}
        [bold]Status:[/bold] {status}
        [bold]HTTP Status:[/bold] {result["status"]}
        [bold]Final URL:[/bold] {result["final_url"]}
        [bold]Message:[/bold] {result["message"]}
        ----------------------------------------
        """)

    async def routine(self, args: HttpProbeArgs) -> None:
        from modules.http_probe import MultiprocessAccountProbe
        from core.utils import load_url_account_list

        urls = load_url_account_list(
            self.default_url_list,
            account=args.account,
        )

        probe = MultiprocessAccountProbe(concurrency=args.concurrency)
        results = probe.run(
            urls=urls,
            shards=args.shards,
        )

        for result in results:
            self.render_result(dict(result))


class MiscGroup(CLIGroup[MiscArgs]):
    model = MiscArgs

    @asynccontextmanager
    async def _client(self):
        async with httpclient.makeclient() as client:
            yield client

    async def routine(self, args: MiscArgs) -> None:
        from modules.general import get_phone_info, WebpageMetadata

        if args.phone_number:
            result = get_phone_info(args.phone_number)
            self.console.print(result.render())
            return

        elif args.website:
            async with self._client() as client:
                result = await WebpageMetadata.collect(client, args.website)
            self.console.print(result.render())

        else:
            self.console.print(
                "[red]Error: --phone-number or --website is required[/red]"
            )


def create_app() -> argparse.ArgumentParser:
    app_schema = {
        "domain": {
            "class": DomainGroup,
            "help": "Domain related tools (DNS lookup, subdomain enumeration, blocklist check)",
        },
        "ip": {
            "class": IPGroup,
            "help": "IP related tools (geolocation, ASN info, reverse DNS)",
        },
        "email": {
            "class": EmailGroup,
            "help": "Email related tools (header analysis, breach search)",
        },
        "probe": {
            "class": ProbeGroup,
            "help": "Account existence probing on various platforms",
        },
        "misc": {
            "class": MiscGroup,
            "help": "Miscellaneous tools (phone info, webpage metadata)",
        },
    }

    parser = argparse.ArgumentParser(
        description="OSINT Toolkit CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    subparsers = parser.add_subparsers(
        title="subcommands",
        description="valid subcommands",
        help="additional help",
        dest="command",
    )

    for app_name, config in app_schema.items():
        app_class: type[CLIGroup] = config["class"]

        subparser = subparsers.add_parser(
            app_name,
            help=config["help"],
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        group: CLIGroup = app_class(subparser)
        subparser.set_defaults(func=group)

    return parser


def run() -> None:
    parser = create_app()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return

    args.func(args)