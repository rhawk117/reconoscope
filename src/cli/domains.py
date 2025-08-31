
import asyncio
from contextlib import asynccontextmanager
from dns.rdata import Rdata
import httpx
import dns.asyncresolver
import dns.resolver
from cli.models import DnsLookupResult, SubdomainResult, DNSRecord
from cli import http_utils

CRT_SH_URL = "https://crt.sh/"

def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def _validate_and_add(name: str, found: set[str], target: str) -> None:
    if (normalized := normalize_hostname(name)) and normalized != target:
        found.add(normalized)


class _AiodnsLookup:
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


async def lookup_domain_name(
    domain: str, client: httpx.AsyncClient
) -> DnsLookupResult:

    lookup = _AiodnsLookup(
        client=client,
        domain_name=domain,
    )

    await asyncio.gather(
        *(lookup(rtype) for rtype in _AiodnsLookup.RECORD_TYPES)
    )

    return DnsLookupResult(
        domain=domain,
        records=DNSRecord(**lookup.records),
        warnings=lookup.warnings,
    )

async def enumerate_subdomains(
    domain: str, client: httpx.AsyncClient
) -> SubdomainResult:
    params = {
        "q": f"%.{domain}",
        "output": "json",
    }
    response = await http_utils.try_get_json(
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

