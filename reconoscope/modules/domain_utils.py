
import dataclasses as dc
from typing import Final

import httpx
from rich.console import Console

from reconoscope.core.httpx import httpxretry, make_httpx_client


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip('.')


@dc.dataclass(slots=True)
class SubdomainResult:
    domain: str
    total: int
    subdomains: list[str]


class CersthSubdomainSearch:
    CERTSH_URL: Final[str] = 'https://crt.sh/'

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client: httpx.AsyncClient = client

    @httpxretry()
    async def query(self, domain: str) -> list[dict]:
        """
        Queries the Cersth API for subdomains.

        Parameters
        ----------
        domain : str

        Returns
        -------
        dict
        """

        response = await self.client.get(
            self.CERTSH_URL, params={'q': f'%.{domain}', 'output': 'json'}
        )
        response.raise_for_status()
        return response.json()


    def walk_response(self, result: list[dict], domain: str):
        """
        Iterates over the query result from crt.sh and yields subdomains.

        Parameters
        ----------
        result : list[dict]
        """
        for entry in result or []:
            if 'name_value' in entry and (name_value := entry['name_value']):
                yield from self._iter_name_value(name_value, domain)
            elif 'common_name' in entry and (common_name := entry['common_name']):
                hostname = normalize_hostname(common_name)
                if hostname and hostname != domain:
                    yield hostname

    def _iter_name_value(self, name_value: str, domain: str):
        """
        Iterates over the name_value field from crt.sh results.

        Parameters
        ----------
        name_value : str

        Yields
        ------
        _str_
        """
        for line in str(name_value).splitlines():
            hostname = normalize_hostname(line)
            if hostname and hostname != domain:
                yield hostname

    async def fetch_subdomains(self, domain: str) -> SubdomainResult:
        """
        Fetches subdomains for a given domain.

        Parameters
        ----------
        domain : str

        Returns
        -------
        SubdomainResult
        """
        raw_result = await self.query(domain)
        subdomains = set()
        for subdomain in self.walk_response(raw_result, domain):
            subdomains.add(subdomain)

        return SubdomainResult(
            domain=domain,
            total=len(subdomains),
            subdomains=sorted(subdomains),
        )


async def fetch_certsh_subdomains(domain: str) -> SubdomainResult:
    """
    Fetches subdomains from crt.sh for a given domain.

    Parameters
    ----------
    domain : str

    Returns
    -------
    set[str]
    """
    async with make_httpx_client() as client:
        searcher = CersthSubdomainSearch(client)
        return await searcher.fetch_subdomains(domain)


def render_subdomain_results(result: SubdomainResult) -> str:
    console = Console(record=True)
    console.print(f'[bold]Domain:[/] [green]{result.domain}[/]')
    console.print(f'[bold]Total Subdomains Found:[/] [green]{result.total}[/]')
    if result.subdomains:
        console.print('[bold]Subdomains:[/]')
        for subdomain in result.subdomains:
            console.print(f'  -> [green]{subdomain}[/]')

    return console.export_text()


def auto_run_certsh() -> None:
    import asyncio
    import sys

    console = Console()

    if len(sys.argv) < 2:
        domain = console.input('[bold yellow]Enter a domain to look up subdomains:[/] ')
    else:
        domain = sys.argv[1]

    async def main() -> None:
        result = await fetch_certsh_subdomains(domain=domain)
        console.print(render_subdomain_results(result))

    asyncio.run(main())


if __name__ == '__main__':
    auto_run_certsh()