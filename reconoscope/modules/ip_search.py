

import asyncio
import dataclasses as dc
import sys
from typing import Final

import httpx
from rich.console import Console

from reconoscope.core.httpx import httpxretry, make_httpx_client


@dc.dataclass(slots=True)
class IpRecord:
    """
    The parsed ip information record.
    """
    ip: str | None = None
    city: str | None = None
    country: str | None = None
    postal: str | None = None
    org: str | None = None
    location: str | None = None
    timezone: str | None = None
    extras: dict = dc.field(default_factory=dict)

    @property
    def maps_link(self) -> str | None:
        if not self.location:
            return None
        return f"https://maps.google.com/?q={self.location}"


class IpIsBogonError(ValueError): ...

class IPSearchEngine:
    IP_INFO_URL: Final[str] = "https://ipinfo.io/{ip}/json"

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client: httpx.AsyncClient = client

    @httpxretry()
    async def fetch_ip_info(self, ip: str) -> dict:
        '''
        Fetches raw JSON IP information from ipinfo.io.

        Parameters
        ----------
        ip : str

        Returns
        -------
        dict
        '''
        url = self.IP_INFO_URL.format(ip=ip)
        response = await self.client.get(url)
        response.raise_for_status()
        return response.json()

    async def search(self, ip: str) -> IpRecord:
        """
        Look up information about an IP address.

        Parameters
        ----------
        ip : str

        Returns
        -------
        IpRecord

        Raises
        ------
        IpIsBogonError
        """
        ip_response = await self.fetch_ip_info(ip)

        if ip_response.get("bogon"):
            raise IpIsBogonError(f"IP {ip} is a bogon address")

        record_kwargs = {}
        for fields in dc.fields(IpRecord):
            # remove all till we have only extras left
            if record_field := ip_response.pop(fields.name, None):
                record_kwargs[fields.name] = record_field

        return IpRecord(
            **record_kwargs,
            extras=ip_response,
        )

    async def search_ips(self, ips: list[str]) -> list[IpRecord]:
        tasks = [self.search(ip) for ip in ips]
        return await asyncio.gather(*tasks)


async def lookup_ip(
    ip: str,
    client: httpx.AsyncClient,
) -> IpRecord:
    '''
    Look up information about an IP address.

    Parameters
    ----------
    client : httpx.AsyncClient
        _An HTTPX AsyncClient instance_
    ip : str
        _The IP address to look up_

    Returns
    -------
    IpRecord

    Raises
    ------
    ValueError
        _If the IP address is a bogon address_
    '''
    searcher = IPSearchEngine(client=client)
    return await searcher.search(ip)

async def lookup_all_ips(
    client: httpx.AsyncClient,
    ips: list[str],
) -> list[IpRecord]:
    '''
    Look up information about multiple IP addresses.

    Parameters
    ----------
    client : httpx.AsyncClient
        _An HTTPX AsyncClient instance_
    ips : list[str]
        _A list of IP addresses to look up_

    Returns
    -------
    list[IpRecord]

    Raises
    ------
    ValueError
        _If any of the IP addresses is a bogon address_
    '''
    searcher = IPSearchEngine(client=client)
    return await searcher.search_ips(ips)


def render_ip_record(record: IpRecord) -> str:
    result_dict = dc.asdict(record)
    result_lines = []
    for k, v in result_dict.items():
        result_lines.append(f'[green]{k.capitalize()}:[/] [green]{v or "n/a"}[/]')
        if k == 'extras':
            for ek, ev in record.extras.items():
                result_lines.append(f'  [magenta]{ek}:[/][green] {ev or "n/a"}[/]')

    if maps_link := record.maps_link:
        result_lines.append(
            f'[green]Google Maps Link:[/] [green underline]{maps_link}[/]'
        )

    return '\n'.join(result_lines)

def auto_run() -> None:
    console = Console()

    if len(sys.argv) < 2:
        ip = console.input("[bold yellow]Enter an IP address to look up:[/] ")
    else:
        ip = sys.argv[1]

    async def main() -> None:
        async with make_httpx_client() as client:
            try:
                result = await lookup_ip(client=client, ip=ip)
                console.print(render_ip_record(result))
            except ValueError as ve:
                console.print(f"[bold red]Error:[/] {ve}")
            except httpx.HTTPError as he:
                console.print(f"[bold red]HTTP Error:[/] {he}")

    asyncio.run(main())

if __name__ == "__main__":
    auto_run()