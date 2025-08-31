
import httpx
import dataclasses
from cli.models import IpInfo
from cli import http_utils

IP_INFO_URL = "https://ipinfo.io"



async def get_ip_info(ip: str, client: httpx.AsyncClient) -> IpInfo:
    '''
    Parameters
    ----------
    ip : str
    client : httpx.AsyncClient

    Returns
    -------
    IpInfo

    Raises
    ------
    RuntimeError
        _response failed_
    ValueError
        _bogon in response_
    '''
    url = f"{IP_INFO_URL}/{ip}/json"
    response = await http_utils.try_get_json(
        client=client,
        url=url,
        attempts=3,
    )
    if "error" in response:
        raise RuntimeError(
            f"Error fetching IP info: {response['error']}, details: {response['details']}"
        )

    if response.get("bogon"):
        raise ValueError(f"IP {ip} is a bogon address")

    extras = {k: v for k, v in response.items() if k not in dataclasses.fields(IpInfo)}
    return IpInfo(
        ip=response.get("ip"),
        city=response.get("city"),
        country=response.get("country"),
        postal=response.get("postal"),
        org=response.get("org"),
        location=response.get("loc"),
        timezone=response.get("timezone"),
        extras=extras,
    )
