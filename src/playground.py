import abc
import argparse
import asyncio
from contextlib import asynccontextmanager
import pprint
import sys
import dns
import dns.asyncresolver
from dns.rdata import Rdata
import dns.resolver
from loguru import logger
from rich.console import Console
from pydantic import BaseModel, Field
from rich.traceback import install as install_rich_traceback
import httpx
import phonenumbers
from phonenumbers import carrier, geocoder

install_rich_traceback(show_locals=True)

IP_INFO_URL = "https://ipinfo.io"
CRT_SH_URL = "https://crt.sh/"

LOGURU_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)
logger.remove()
logger.add(
    sys.stdout,
    format=LOGURU_LOG_FORMAT,
    level="DEBUG",
    enqueue=True,
    backtrace=True,
)


class Renderable(abc.ABC):
    @abc.abstractmethod
    def console_output(self) -> str:
        pass


class IpInfo(BaseModel, Renderable):
    ip: str | None = None
    city: str | None = None
    country: str | None = None
    postal: str | None = None
    org: str | None = None
    location: str | None = None
    timezone: str | None = None
    extras: dict = Field(default_factory=dict)

    @property
    def maps_link(self) -> str | None:
        if not self.location:
            return None
        return f"https://maps.google.com/?q={self.location}"

    def console_output(self) -> str:
        return (
            "IP Information:\n"
            f"[bold]IP:[/bold] {self.ip}\n"
            f"[bold]City:[/bold] {self.city}\n"
            f"[bold]Country:[/bold] {self.country}\n"
            f"[bold]Postal Code:[/bold] {self.postal}\n"
            f"[bold]Organization:[/bold] {self.org}\n"
            f"[bold]Location:[/bold] {self.location}\n"
            f"[bold]Timezone:[/bold] {self.timezone}\n"
            f"[bold]Google Maps:[/bold] {self.maps_link}\n"
            f"extras\n{pprint.pformat(self.extras, indent=4)}"
        )


class SubdomainResult(BaseModel, Renderable):
    domain: str
    total: int
    subdomains: list[str]

    def console_output(self) -> str:
        return (
            f"Subdomain Enumeration for {self.domain}:\n"
            f"Total Subdomains Found: {self.total}\n"
            "Subdomains:\n" + "\n".join(f" - {sub}" for sub in self.subdomains)
        )


class DNSRecord(BaseModel, Renderable):
    A: list[str] = Field(default_factory=list)
    CNAME: list[str] = Field(default_factory=list)
    MX: list[str] = Field(default_factory=list)
    NS: list[str] = Field(default_factory=list)

    def console_output(self) -> str:
        output = "DNS Records:\n"
        for rtype in ("A", "CNAME", "MX", "NS"):
            records = getattr(self, rtype)
            if records:
                output += f" {rtype} Records:\n"
                for record in records:
                    output += f"  - {record}\n"
        return output


class DnsLookupResult(BaseModel, Renderable):
    domain: str
    records: DNSRecord
    warnings: list[str] = Field(default_factory=list)

    def console_output(self) -> str:
        output = f"DNS Lookup for {self.domain}:\n"
        output += self.records.console_output()
        if self.warnings:
            output += "Warnings:\n"
            for warning in self.warnings:
                output += f" - {warning}\n"
        return output


class PhoneRecord(BaseModel, Renderable):
    phone_number: str
    e164: str | None = None
    country: str | None = None
    region: str | None = None
    operator: str | None = None
    is_valid: bool

    def console_output(self) -> str:
        return (
            f"Phone Number Information for {self.phone_number}:\n"
            f"[bold]E.164 Format:[/bold] {self.e164}\n"
            f"[bold]Country:[/bold] {self.country}\n"
            f"[bold]Region:[/bold] {self.region}\n"
            f"[bold]Operator:[/bold] {self.operator}\n"
            f"[bold]Is Valid:[/bold] {'Yes' if self.is_valid else 'No'}\n"
        )


class HttpUtils:
    @staticmethod
    def make_http_client(headers: dict) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=10.0, headers=headers)

    @staticmethod
    def get_default_headers() -> dict:
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"
        }

    @staticmethod
    async def get_json(
        *,
        client: httpx.AsyncClient,
        url: str,
        params: dict | None = None,
    ) -> dict:
        response = await client.get(url, params=params)
        response.raise_for_status()
        return response.json()

    @staticmethod
    async def try_get_json(
        *,
        client: httpx.AsyncClient,
        url: str,
        params: dict | None = None,
        attempts: int = 3,
    ) -> dict:
        response = None
        while attempts > 0 and response is None:
            try:
                response = await HttpUtils.get_json(
                    client=client,
                    url=url,
                    params=params,
                )
            except (
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.WriteError,
                httpx.RemoteProtocolError,
            ) as exc:
                logger.error(
                    f"Error fetching URL {url}: {exc}. Attempts left: {attempts}"
                )
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                try:
                    error_detail = exc.response.json()
                except Exception:
                    return {"error": f"HTTP {status_code}", "details": str(exc)}
                return {"error": f"HTTP {status_code}", "details": error_detail}

            attempts -= 1
            await asyncio.sleep(0.25 * attempts)

        if response is None:
            raise RuntimeError(f"Failed to fetch URL {url} after retries")

        return response


async def get_ip_info(ip: str, client: httpx.AsyncClient) -> IpInfo:
    url = f"{IP_INFO_URL}/{ip}/json"
    response = await HttpUtils.try_get_json(
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

    extras = {k: v for k, v in response.items() if k not in IpInfo.__fields__}
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


class DNSLookup:
    resolver = dns.asyncresolver.Resolver()
    RECORD_TYPES = (
        "A",
        "CNAME",
        "MX",
        "NS",
    )

    def __init__(self, client: httpx.AsyncClient, domain_name: str):
        self.client = client
        self.domain_name = domain_name
        self.records: dict = {rtype: [] for rtype in self.RECORD_TYPES}
        self.warnings: list[str] = []

    @asynccontextmanager
    async def wrap_query(self, rtype: str):
        try:
            yield
        except dns.resolver.NoAnswer:
            self.warnings.append(f"No answer for {rtype} record")
        except dns.resolver.NXDOMAIN:
            self.warnings.append(f"Domain does not exist for {rtype} record")
        except dns.resolver.Timeout:
            self.warnings.append(f"Timeout while querying {rtype} record")
        except dns.resolver.NoNameservers:
            self.warnings.append(f"No nameservers available for {rtype} record")
        except Exception as exc:
            self.warnings.append(f"Error querying {rtype} record: {exc}")

    def _add_mx_record(self, rdata: Rdata) -> None:
        preference = getattr(rdata, "preference", None)
        exchange = getattr(rdata, "exchange", None)
        if exchange or preference:
            record = f"{preference} {exchange}"
            self.records["MX"].append(record)

    async def __call__(self, rtype: str) -> None:
        async with self.wrap_query(rtype):
            answer = await self.resolver.resolve(self.domain_name, rtype)
            for rdata in answer:
                if rtype == "MX":
                    self._add_mx_record(rdata)
                else:
                    self.records[rtype].append(rdata.to_text())

    @classmethod
    async def dns_lookup(
        cls, domain: str, client: httpx.AsyncClient
    ) -> DnsLookupResult:
        enumerator = cls(client, domain)

        await asyncio.gather(*(enumerator(rtype) for rtype in cls.RECORD_TYPES))

        return DnsLookupResult(
            domain=domain,
            records=DNSRecord(**enumerator.records),
            warnings=enumerator.warnings,
        )


def get_phone_info(phone_number: str) -> PhoneRecord:
    try:
        phone_obj = phonenumbers.parse(phone_number)
    except phonenumbers.NumberParseException as exc:
        raise ValueError(f"Error parsing phone number {phone_number}: {exc}")

    if is_valid := phonenumbers.is_valid_number(phone_obj):
        kwargs = {
            "e164": phonenumbers.format_number(
                phone_obj, phonenumbers.PhoneNumberFormat.E164
            ),
            "country": geocoder.country_name_for_number(phone_obj, "en"),
            "region": geocoder.description_for_number(phone_obj, "en"),
            "operator": carrier.name_for_number(phone_obj, "en"),
        }
    else:
        kwargs = {
            "e164": None,
            "country": None,
            "region": None,
            "operator": None,
        }

    return PhoneRecord(phone_number=phone_number, is_valid=is_valid, **kwargs)


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def _validate_and_add(name: str, found: set[str], target: str) -> None:
    if (normalized := normalize_hostname(name)) and normalized != target:
        found.add(normalized)


async def enumerate_subdomains(
    domain: str, client: httpx.AsyncClient
) -> SubdomainResult:
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    response = await HttpUtils.try_get_json(
        client=client,
        url=CRT_SH_URL,
        params=params,
        attempts=3,
    )
    if "error" in response:
        raise RuntimeError(
            f"Error fetching subdomains: {response['error']}, details: {response['details']}"
        )

    found: set[str] = set()
    for entry in response or []:
        if "name_value" in entry and (name_value := entry["name_value"]):
            for line in str(name_value).splitlines():
                _validate_and_add(line, found, domain)
        elif "common_name" in entry and (common_name := entry["common_name"]):
            _validate_and_add(common_name, found, domain)

    return SubdomainResult(domain=domain, total=len(found), subdomains=sorted(found))


def get_arguments() -> argparse.Namespace:
    app = argparse.ArgumentParser(
        description="Reconoscope - OSINT Command Line Tool",
    )

    app.add_argument(
        "--version",
        action="version",
        version="Reconoscope 0.1.0",
    )

    app.add_argument(
        "--domain",
        type=str,
        help="Domain name to enumerate subdomains and perform DNS lookup",
    )

    app.add_argument(
        "--ip",
        type=str,
        help="IP address to fetch geolocation and ASN info",
    )

    app.add_argument(
        "--phone",
        type=str,
        help="Phone number to validate and get info about",
    )

    args = app.parse_args()
    if not (args.domain or args.ip or args.phone):
        app.error("At least one of --domain, --ip, or --phone must be provided")

    return args


@asynccontextmanager
async def app_context():
    headers = HttpUtils.get_default_headers()

    try:
        async with HttpUtils.make_http_client(headers) as client:
            yield client
    except Exception as exc:
        logger.error(f"Error in application context: {exc}")
        raise


async def main(
    *,
    domain: str | None = None,
    ip: str | None = None,
    phone: str | None = None,
) -> None:
    console = Console()
    cmd_string = ""
    async with app_context() as client:
        tasks = []
        if domain:
            cmd_string += f"Addressing domain: {domain}\n"
            tasks.append(enumerate_subdomains(domain, client))
            tasks.append(DNSLookup.dns_lookup(domain, client))
        if ip:
            cmd_string += f"Addressing IP: {ip}\n"
            tasks.append(get_ip_info(ip, client))

        console.status(f"Running tasks...\n{cmd_string}")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                console.print(f"[red]Error:[/red] {result}")
            elif isinstance(result, Renderable):
                console.print(result.console_output())
                console.print("\n" + "-" * 40 + "\n")
            else:
                console.print(
                    f"[yellow]Warning:[/yellow] Unhandled result type: {type(result)}"
                )

    if phone:
        try:
            phone_result = get_phone_info(phone)
            console.print(phone_result.console_output())
        except ValueError as exc:
            console.print(f"[red]Error:[/red] {exc}")


if __name__ == "__main__":
    args = get_arguments()
    asyncio.run(
        main(
            domain=args.domain,
            ip=args.ip,
            phone=args.phone,
        )
    )
