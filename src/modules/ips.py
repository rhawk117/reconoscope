


import dataclasses
from typing import Final
import httpx
from core.retries import async_retries
from modules.models import IpRecord


class IPInfoCollector:
    IP_INFO_URL: Final[str] = "https://ipinfo.io/{ip}/json"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @async_retries(attempts=3, delay=0.5, jitter=0.1, backoff="expo")
    async def fetchone(self, ip: str) -> dict:
        url = self.IP_INFO_URL.format(ip=ip)
        response = await self.client.get(url)
        response.raise_for_status()
        return response.json()

    async def __call__(self, ip: str) -> IpRecord:
        ip_response = await self.fetchone(ip)

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
