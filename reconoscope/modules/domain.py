



import asyncio
from contextlib import asynccontextmanager
from typing import Final

from dns import reversename
import dns.asyncresolver
from dns.rdata import Rdata
import dns.resolver
import email_validator
import httpx
from reconoscope.core.retries import async_retries
from reconoscope.modules.models import (
    DNSRecord,
    DnsBlocklistResult,
    DomainRecord,
    ReverseDnsResult,
    SubdomainResult,
    EmailDomainRecord,
)


class AsyncDomainLookup:
    """
    Asynchronously looks up DNS records for a given domain.
    """
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
        """
        Adds an MX record to the records dictionary.

        Parameters
        ----------
        rdata : Rdata
            _The record to process_
        """
        preference = getattr(rdata, "preference", None)
        exchange = getattr(rdata, "exchange", None)
        if exchange or preference:
            record = f"{preference} {exchange}"
            self.records["MX"].append(record)

    async def __call__(self, rtype: str) -> None:
        """
        Looks up a specific DNS record type and stores the results.

        Parameters
        ----------
        rtype : str
            _The rtype to call with_
        """
        async with self.collect_warnings(rtype):
            answer = await self.resolver.resolve(self.domain_name, rtype)
            for rdata in answer:
                if rtype == "MX":
                    self.add_mx_record(rdata)
                else:
                    self.records[rtype].append(rdata.to_text())

    @classmethod
    async def run(cls, domain_name: str) -> DomainRecord:
        """
        Runs the DNS lookup for the specified domain name.

        Parameters
        ----------
        domain_name : str

        Returns
        -------
        DomainRecord
        """
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
        """
        Resets the internal state of the instance.
        """
        self.records = {rtype: [] for rtype in self.RECORD_TYPES}
        self.warnings.clear()



def normalize_hostname(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


class CertshSubdomainEnumerator:
    """
    Enumerates subdomains using the crt.sh
    """
    CERTSH_URL: Final[str] = "https://crt.sh/"

    def __init__(self, domain: str, client: httpx.AsyncClient) -> None:
        self.domain: str = domain
        self.client: httpx.AsyncClient = client

    @async_retries(attempts=3, delay=0.5, jitter=0.1, backoff="expo")
    async def query(self) -> list[dict]:
        """
        Queries crt.sh for subdomains of the specified domain.

        Returns
        -------
        list[dict]
        """
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
            if hostname and hostname != self.domain:
                yield hostname

    def iter_query_result(self, result: list[dict]):
        """
        Iterates over the query result from crt.sh and yields subdomains.

        Parameters
        ----------
        result : list[dict]
        """
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

    @classmethod
    async def run(cls, client: httpx.AsyncClient, domain: str) -> SubdomainResult:
        """
        Runs the subdomain enumeration for the specified domain.

        Parameters
        ----------
        client : httpx.AsyncClient
        domain : str

        Returns
        -------
        SubdomainResult
        """
        enumerator = cls(domain=domain, client=client)
        return await enumerator()

class EmailDomainSearch:
    """
    Searches for MX records of the domain part of an email address.
    """
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

    @classmethod
    async def run(cls, email: str) -> 'EmailDomainRecord':
        '''
        Runs the email domain search for the specified email address.

        Parameters
        ----------
        email : str

        Returns
        -------
        EmailDomainRecord
        '''
        searcher = cls(email=email)
        return await searcher()

class ReverseDnsLookup:
    '''
    Performs a reverse DNS lookup for a given IP address.
    '''
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

    @classmethod
    async def run(cls, ip_address: str) -> ReverseDnsResult | None:
        reverse_dns_lookup = cls(ip_address=ip_address)
        return await reverse_dns_lookup()



class DnsBlocklistSearch:
    BLOCKLIST_DOMAINS = (
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
        "b.barracudacentral.org",
    )
    resolver = dns.asyncresolver.Resolver()

    def __init__(self, ip_address: str, client: httpx.AsyncClient):
        self.ip_address: str = ip_address
        self.client: httpx.AsyncClient = client
        self.answers: dict[str, list[str]] = {}

    async def check_blocklist(
        self,
        blocklist_domain: str,
        reversed_ip: str,
    ) -> None:
        '''
        Checks if the reversed IP is listed in the given blocklist domain.

        Parameters
        ----------
        blocklist_domain : str
        reversed_ip : str
        '''
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
        '''
        Queries the blocklist domains to check if the IP address
        is listed.

        Returns
        -------
        DnsBlocklistResult
        '''
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

    @classmethod
    async def run(cls, client: httpx.AsyncClient, ip_address: str) -> DnsBlocklistResult:
        '''
        Runs the DNS blocklist search for the specified IP address.

        Parameters
        ----------
        client : httpx.AsyncClient
        ip_address : str

        Returns
        -------
        DnsBlocklistResult
        '''
        searcher = cls(ip_address=ip_address, client=client)
        return await searcher()