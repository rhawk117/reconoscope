import asyncio
from contextlib import asynccontextmanager
from dataclasses import fields
from email.parser import Parser
import re
from typing import Final, NamedTuple, TypedDict
from dns import reversename
from dns.rdata import Rdata
import httpx
import dns.asyncresolver
import dns.resolver
from cli.ips import IpInfo
from cli.models import (
    DnsLookupResult,
    EmailAuthentication,
    EmailDomainAuth,
    EmailDomainRecord,
    EmailHeaderRecord,
    RecievedIPs,
    ReverseDnsResult,
    SubdomainResult,
    DNSRecord,
)
from cli.utils.httpx_retry import httpx_retry
import email_validator


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


class AsyncDNSAudit:
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

    def add_mx_record(self, rdata: Rdata) -> None:
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
                    self.add_mx_record(rdata)
                else:
                    self.records[rtype].append(rdata.to_text())

    @classmethod
    async def lookup(cls, domain_name: str) -> DnsLookupResult:
        lookup = cls(domain_name=domain_name)
        await asyncio.gather(*(lookup(rtype) for rtype in cls.RECORD_TYPES))
        return DnsLookupResult(
            domain=domain_name,
            records=DNSRecord(**lookup.records),
            warnings=lookup.warnings,
        )


class IPInfoCollector:
    IP_INFO_URL: Final[str] = "https://ipinfo.io/{ip}/json"

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    @httpx_retry(attempts=3, delay=0.5, jitter=0.1, backoff="expo")
    async def fetchone(self, ip: str) -> dict:
        url = self.IP_INFO_URL.format(ip=ip)
        response = await self.client.get(url)
        response.raise_for_status()
        return response.json()

    async def __call__(self, ip: str) -> IpInfo:
        ip_response = await self.fetchone(ip)

        if ip_response.get("bogon"):
            raise ValueError(f"IP {ip} is a bogon address")
        extras = {k: v for k, v in ip_response.items() if k not in fields(IpInfo)}
        return IpInfo(
            ip=ip_response.get("ip"),
            city=ip_response.get("city"),
            country=ip_response.get("country"),
            postal=ip_response.get("postal"),
            org=ip_response.get("org"),
            location=ip_response.get("loc"),
            timezone=ip_response.get("timezone"),
            extras=extras,
        )


class CertshSubdomainEnumerator:
    CERTSH_URL: Final[str] = "https://crt.sh/"

    def __init__(self, domain: str, client: httpx.AsyncClient) -> None:
        self.domain = domain
        self.client = client

    @httpx_retry(attempts=3, delay=0.5, jitter=0.1, backoff="expo")
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

    def __init__(self, email: str):
        self.email = email

        if not (domain := self.get_email_domain(email)):
            raise ValueError(f"Invalid email address: {email}")

        self.domain = domain

    async def iter_mx_records(self):
        try:
            answer = await self.dns_resolver.resolve(self.domain, "MX")
            for rdata in answer:
                exchange = getattr(rdata, "exchange", None)
                if exchange:
                    yield exchange
        except Exception:
            return

    async def __call__(self) -> EmailDomainRecord:
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





class EmailAuthParser:
    '''
    Parses email authentication results from headers with
    Authentication-Results field, uses pre-compiled regex
    patterns.
    '''
    def __init__(self) -> None:
        self.spf_match_re = re.compile(
            r"(?i)spf=(pass|fail|softfail|neutral|none|temperror|permerror)"
        )
        self.spf_domain_match_re = re.compile(r"envelope-from=([^;\s]+)")
        self.dkim_match_re = re.compile(
            r"(?i)dkim=(pass|fail|none|policy|neutral|temperror|permerror)"
        )
        self.dkim_domain_match_re = re.compile(r"d=([^;\s]+)")
        self.dmarc_match_re = re.compile(
            r"(?i)dmarc=(pass|fail|none|policy|neutral|temperror|permerror)"
        )

    def scan_text(self, pattern: re.Pattern, text: str | None) -> str | None:
        if not text:
            return None
        if match := pattern.search(text, re.IGNORECASE):
            return match.group(1)
        return None

    def __call__(self, auth_results: list[str], from_: str) -> EmailAuthentication:
        if "@" in from_:
            domain_token = from_.split("@", 1)[-1]
            from_domain = domain_token.strip(">").strip().lower()

        spf = EmailDomainAuth()
        dkim = EmailDomainAuth()
        dmarc = None

        for line in auth_results or []:
            if not line:
                continue

            if spf_result := self.scan_text(self.spf_match_re, line):
                spf.result = spf_result

            if spf_domain := self.scan_text(self.spf_domain_match_re, line):
                spf.domain = spf_domain

            if dkim_result := self.scan_text(self.dkim_match_re, line):
                dkim.result = dkim_result

            if dkim_domain := self.scan_text(self.dkim_domain_match_re, line):
                dkim.domain = dkim_domain

            if dmarc_result := self.scan_text(self.dmarc_match_re, line):
                dmarc = dmarc_result

        if from_domain:
            spf.aligned = spf.domain is not None and spf.domain.lower() == from_domain
            dkim.aligned = (
                dkim.domain is not None and dkim.domain.lower() == from_domain
            )

        return EmailAuthentication(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
        )

    def dispose(self) -> None:
        del self.spf_match_re
        del self.spf_domain_match_re
        del self.dkim_match_re
        del self.dkim_domain_match_re
        del self.dmarc_match_re

class EmailHeaderAnalyzer:
    IP_ADDRESS_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def __init__(self, *, client: httpx.AsyncClient, raw_header: str) -> None:
        self.email_message = Parser().parsestr(raw_header)
        self.ip_lookup = IPInfoCollector(client=client)

    def get_reciever_ips(self) -> list[str]:
        received_headers = self.email_message.get_all("Received", [])
        ips: set[str] = set()
        for header in received_headers:
            found_ips = self.IP_ADDRESS_RE.findall(header)
            ips.update(found_ips)
        return list(ips)

    async def add_reciever_ips(self, record: EmailHeaderRecord) -> RecievedIPs:
        reciever_ips = self.get_reciever_ips()
        record.reciever_ips.ip_list = list(reciever_ips)
        tasks = [
            asyncio.create_task(self.ip_lookup(ip)) for ip in reciever_ips
        ]
        for fut in await asyncio.gather(*tasks, return_exceptions=True):
            record.reciever_ips.add_result(fut)

        return record.reciever_ips


    async def __call__(self) -> EmailHeaderRecord:
        record = EmailHeaderRecord(
            from_=self.email_message.get("From"),
            to_=self.email_message.get("To"),
            subject=self.email_message.get("Subject"),
            date=self.email_message.get("Date"),
        )
        auth_results = self.email_message.get_all("Authentication-Results", [])
        from_ = self.email_message.get("From", "")
        parser = EmailAuthParser()
        email_auth = parser(
            auth_results=auth_results,
            from_=from_
        )
        parser.dispose()
        record.auth_results = email_auth
        await self.add_reciever_ips(record)

        return record
