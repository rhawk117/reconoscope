



import asyncio
from contextlib import asynccontextmanager
from typing import Final

from dns import reversename
import dns.asyncresolver
from dns.rdata import Rdata
import dns.resolver
import email_validator
import httpx
from cli.domains import EmailDomainRecord
from core.retries import async_retries
from modules.models import DNSRecord, DnsBlocklistResult, DomainRecord, ReverseDnsResult, SubdomainResult


class AsyncDomainLookup:
    resolver = dns.asyncresolver.Resolver()
    RECORD_TYPES = (
        "A",
        "CNAME",
        "MX",
        "NS",
    )

    def __init__(self, domain_name: str):
        self.domain_name: str = domain_name
        self.records: dict[str, list] = {rtype: [] for rtype in self.RECORD_TYPES}
        self.warnings: list[str] = []

    @asynccontextmanager
    async def collect_warnings(self, rtype: str):
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

    def add_mx_record(self, rdata: Rdata) -> None:
        preference = getattr(rdata, "preference", None)
        exchange = getattr(rdata, "exchange", None)
        if exchange or preference:
            record = f"{preference} {exchange}"
            self.records["MX"].append(record)

    async def __call__(self, rtype: str) -> None:
        async with self.collect_warnings(rtype):
            answer = await self.resolver.resolve(self.domain_name, rtype)
            for rdata in answer:
                if rtype == "MX":
                    self.add_mx_record(rdata)
                else:
                    self.records[rtype].append(rdata.to_text())

    @classmethod
    async def lookup(cls, domain_name: str) -> DomainRecord:
        lookup = cls(domain_name=domain_name)
        await asyncio.gather(
            *(lookup(rtype) for rtype in cls.RECORD_TYPES)
        )
        return DomainRecord(
            domain=domain_name,
            records=DNSRecord(**lookup.records),
            warnings=lookup.warnings,
        )

    def reset(self) -> None:
        self.records = {rtype: [] for rtype in self.RECORD_TYPES}
        self.warnings.clear()



def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


class CertshSubdomainEnumerator:
    CERTSH_URL: Final[str] = "https://crt.sh/"

    def __init__(self, domain: str, client: httpx.AsyncClient) -> None:
        self.domain = domain
        self.client = client

    @async_retries(attempts=3, delay=0.5, jitter=0.1, backoff="expo")
    async def query(self) -> list[dict]:
        response = await self.client.get(
            url=self.CERTSH_URL,
            params={
                "q": f"%.{self.domain}",
                "output": "json",
            },
        )
        response.raise_for_status()
        return response.json()

    def _iter_name_value(self, name_value: str):
        for line in str(name_value).splitlines():
            hostname = normalize_hostname(line)
            if hostname and hostname != self.domain:
                yield hostname

    def iter_query_result(self, result: list[dict]):
        for entry in result or []:
            if "name_value" in entry and (name_value := entry["name_value"]):
                yield from self._iter_name_value(name_value)
            elif "common_name" in entry and (common_name := entry["common_name"]):
                hostname = normalize_hostname(common_name)
                if hostname and hostname != self.domain:
                    yield hostname

    async def __call__(self) -> SubdomainResult:
        subdomain_dict = await self.query()
        found: set[str] = set()
        for hostname in self.iter_query_result(subdomain_dict):
            found.add(hostname)

        return SubdomainResult(
            domain=self.domain,
            total=len(found),
            subdomains=sorted(found),
        )

class EmailDomainSearch:
    dns_resolver = dns.asyncresolver.Resolver()

    def get_email_domain(self, email: str) -> str | None:
        try:
            v = email_validator.validate_email(email)
            return v.domain
        except email_validator.EmailNotValidError:
            return None

    def __init__(self, email: str) -> None:
        '''
        Creates an instance to check the domain part of the email for
        MX records.

        Parameters
        ----------
        email : str

        Raises
        ------
        ValueError
            _An invalid email address provided_
        '''
        self.email = email
        if not (domain := self.get_email_domain(email)):
            raise ValueError(f"Invalid email address: {email}")

        self.domain = domain

    async def iter_mx_records(self):
        '''
        asynchronously iterates over the MX records for the email domain.
        '''
        try:
            answer = await self.dns_resolver.resolve(self.domain, "MX")
            for rdata in answer:
                exchange = getattr(rdata, "exchange", None)
                if exchange:
                    yield exchange
        except Exception:
            return

    async def __call__(self) -> EmailDomainRecord:
        '''
        Checks the domain part of the email for MX records and returns
        an EmailDomainRecord instance with the results.

        Returns
        -------
        EmailDomainRecord
        '''
        mx_records = []
        async for mx_exchange in self.iter_mx_records():
            mx_records.append(str(mx_exchange))

        if not mx_records:
            authenticity_msg = (
                "No MX records found, domain may not accept emails or does not exist"
            )
        else:
            authenticity_msg = (
                f"Found {len(mx_records)} MX records, domain likely accepts emails"
            )

        return EmailDomainRecord(
            email=self.email,
            domain=self.domain,
            mx_records=mx_records,
            authenticity=authenticity_msg,
        )

class ReverseDnsLookup:
    resolver = dns.asyncresolver.Resolver()

    def __init__(self, ip_address: str):
        self.ip_address = ip_address

    async def get_ptr_record(self) -> str:
        rev_name = reversename.from_address(self.ip_address)
        answer = await self.resolver.resolve(rev_name, "PTR")
        if not (ptr_record := str(answer[0]).rstrip(".")):
            return "No PTR record found"
        return ptr_record

    async def __call__(self) -> ReverseDnsResult | None:
        try:
            ptr_record = await self.get_ptr_record()
        except Exception:
            return None

        return ReverseDnsResult(
            ip_address=self.ip_address,
            ptr_record=ptr_record,
        )


class DnsBlocklistSearch:
    BLOCKLIST_DOMAINS = (
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
    )
    resolver = dns.asyncresolver.Resolver()

    def __init__(self, ip_address: str, client: httpx.AsyncClient):
        self.ip_address = ip_address
        self.client = client
        self.answers: dict[str, list[str]] = {}

    async def check_blocklist(
        self,
        blocklist_domain: str,
        reversed_ip: str,
    ) -> None:

        self.answers.setdefault(blocklist_domain, [])

        query = f"{reversed_ip}.{blocklist_domain}"
        try:
            answer = await self.resolver.resolve(query, "A")
            for a in answer:
                self.answers[blocklist_domain].append(str(a))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
        ):
            self.answers[blocklist_domain].append("Not listed")
        except Exception as exc:
            return self.answers[blocklist_domain].append(f"Error: {exc}")



    async def __call__(self) -> DnsBlocklistResult:
        reversed_ip = ".".join(reversed(self.ip_address.split(".")))
        tasks = [
            asyncio.create_task(self.check_blocklist(domain, reversed_ip))
            for domain in self.BLOCKLIST_DOMAINS
        ]
        await asyncio.gather(*tasks)
        return DnsBlocklistResult(
            ip_address=self.ip_address,
            responses=self.answers,
            reverse_ip=reversed_ip,
        )