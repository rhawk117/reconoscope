


import asyncio
import dataclasses
from typing import Final
import httpx
from reconoscope.core.retries import httpx_retries
import dataclasses as dc

@dc.dataclass(slots=True)
class IpRecord:
    """
    The results from an IP address lookup.
    """

    ip: str | None = None
    city: str | None = None
    country: str | None = None
    postal: str | None = None
    org: str | None = None
    location: str | None = None
    timezone: str | None = None
    extras: dict = dataclasses.field(default_factory=dict)

    @property
    def maps_link(self) -> str | None:
        if not self.location:
            return None
        return f"https://maps.google.com/?q={self.location}"


class IPAddressSearch:
    IP_INFO_URL: Final[str] = "https://ipinfo.io/{ip}/json"

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client: httpx.AsyncClient = client

    @httpx_retries
    async def fetch(self, ip: str) -> dict:
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
        '''
        Look up information about an IP address.

        Parameters
        ----------
        ip : str

        Returns
        -------
        IpRecord

        Raises
        ------
        ValueError
            _If the IP address is a bogon address_
        '''
        ip_response = await self.fetch(ip)

        if ip_response.get("bogon"):
            raise ValueError(f"IP {ip} is a bogon address")
        extras = {
            k: v for k, v in ip_response.items()
            if k not in dataclasses.fields(IpRecord)
        }

        return IpRecord(
            ip=ip_response.get("ip"),
            city=ip_response.get("city"),
            country=ip_response.get("country"),
            postal=ip_response.get("postal"),
            org=ip_response.get("org"),
            location=ip_response.get("loc"),
            timezone=ip_response.get("timezone"),
            extras=extras,
        )

    async def search_ips(self, ips: list[str]) -> list[IpRecord]:
        tasks = [self.search(ip) for ip in ips]
        return await asyncio.gather(*tasks)


async def lookup_ip(
    client: httpx.AsyncClient,
    ip: str,
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
    searcher = IPAddressSearch(client=client)
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
    searcher = IPAddressSearch(client=client)
    return await searcher.search_ips(ips)