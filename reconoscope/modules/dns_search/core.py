from __future__ import annotations

import asyncio
import contextlib
import dataclasses as dc
import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import dns.reversename
import email_validator
from reconoscope.modules.dns_search.records import DomainRecords, MXRecord, PTRRecord
from reconoscope.modules.dns_search import parser

@dc.dataclass(slots=True)
class DnsSearchResult:
    domain: str
    records: DomainRecords
    warnings: list[str] = dc.field(default_factory=list)
    rtypes_queried: list[str] = dc.field(default_factory=list)

@dc.dataclass(slots=True)
class EmailDnsResult:
    email: str
    domain: str
    records: list[MXRecord] = dc.field(default_factory=list)
    warnings: list[str] = dc.field(default_factory=list)
    is_authentic: bool = False

@dc.dataclass(slots=True)
class DnsSearchOptions:
    '''
    Options for DNS lookups.
    '''
    filename: str = "/etc/resolv.conf"
    configure: bool = True
    lifetime: float = 5.0
    search: bool | None = None
    source_port: int = 0
    tcp: bool = False


class _EngineUtils:
    @staticmethod
    def get_email_domain(email: str) -> str:
        try:
            v = email_validator.validate_email(email)
            return v.domain
        except email_validator.EmailNotValidError as e:
            raise ValueError(f"Invalid email address: {email}") from e

    @staticmethod
    def reverse_name(ip_address: str) -> str:
        try:
            rev_name = dns.reversename.from_address(ip_address)
            return str(rev_name).rstrip(".")
        except Exception as e:
            raise ValueError(f"Invalid IP address: {ip_address}") from e




class DnsSearchEngine:
    '''
    A class for performing async DNS lookups with
    error handling and result parsing.
    '''
    RECORD_TYPES: tuple[dns.rdatatype.RdataType, ...] = (
        dns.rdatatype.A,
        dns.rdatatype.AAAA,
        dns.rdatatype.MX,
        dns.rdatatype.NS,
        dns.rdatatype.CNAME,
        dns.rdatatype.SOA,
        dns.rdatatype.TXT,
        dns.rdatatype.PTR,
    )


    def __init__(
        self,
        domain_name: str,
        *,
        options: DnsSearchOptions | None = None,
    ) -> None:
        options = options or DnsSearchOptions()

        self._resolver = dns.asyncresolver.Resolver(
            configure=options.configure,
            filename=options.filename,
        )
        self.options = options
        self.domain_name: str = domain_name
        self.warnings: list[str] = []
        self.rtypes_queried: list[str] = []
        self.records = DomainRecords()

    @contextlib.asynccontextmanager
    async def _catch_errors(self, rtype: dns.rdatatype.RdataType):
        '''
        Wraps the `_fetch` method to catch and log DNS errors as the occur

        Parameters
        ----------
        rtype : dns.rdatatype.RdataType
        '''
        self.rtypes_queried.append(dns.rdatatype.to_text(rtype))
        try:
            yield
        except dns.resolver.NoNameservers:
            self.warnings.append(f"No nameservers available for {self.domain_name}")
        except dns.resolver.NXDOMAIN:
            self.warnings.append(f"Domain {self.domain_name} does not exist")
        except dns.resolver.NoAnswer:
            self.warnings.append(f"No answer for {dns.rdatatype.to_text(rtype)} record")
        except dns.resolver.Timeout:
            self.warnings.append(f"Timeout while querying {dns.rdatatype.to_text(rtype)} record")
        except Exception as e:
            self.warnings.append(f"Error querying {dns.rdatatype.to_text(rtype)} record: {e}")


    async def _fetch(self, rtype: dns.rdatatype.RdataType) -> None:
        '''
        Looksup and stores a specific DNS record type.

        Parameters
        ----------
        rtype : dns.rdatatype.RdataType
        '''
        async with self._catch_errors(rtype):
            response = await self._resolver.resolve(
                self.domain_name,
                rtype,
                lifetime=self.options.lifetime,
                search=self.options.search,
                source_port=self.options.source_port,
                tcp=self.options.tcp,
            )
            for rdata in response:
                resolved_record = parser.parse_rdata(rdata)
                parser.collect_record(
                    bag=self.records,
                    rtype=response.rdtype,
                    record=resolved_record,
                )

    async def lookup(self, rtype: dns.rdatatype.RdataType) -> None:
        '''
        Looks up a specific DNS record type.

        Parameters
        ----------
        rtype : dns.rdatatype.RdataType
        '''
        if rtype not in self.RECORD_TYPES:
            raise ValueError(f"Unsupported record type: {dns.rdatatype.to_text(rtype)}")
        await self._fetch(rtype)

    def create_lookup_tasks(
        self,
        rtypes: tuple[dns.rdatatype.RdataType, ...]
    ) -> list[asyncio.Task[None]]:
        '''
        Creates async tasks for looking up multiple DNS record types.

        Parameters
        ----------
        rtypes : tuple[dns.rdatatype.RdataType, ...]
            _The record types to look up._

        Returns
        -------
        list[asyncio.Task[None]]
            _A list of asyncio tasks for the lookups._
        '''
        tasks = [asyncio.create_task(self.lookup(rtype)) for rtype in rtypes]
        return tasks

    async def lookup_records(
        self,
        *,
        rtypes: tuple[dns.rdatatype.RdataType, ...] | None = None
    ) -> DnsSearchResult:
        '''
        Looks up multiple DNS record types.

        Parameters
        ----------
        rtypes : tuple[dns.rdatatype.RdataType, ...] | None
            _The record types to look up. If None, all supported types will be looked up._

        Returns
        -------
        DnsSearchResult
        '''
        rtypes = rtypes or self.RECORD_TYPES
        tasks = (self.lookup(rtype) for rtype in rtypes)
        await asyncio.gather(*tasks)

        results = DnsSearchResult(
            domain=self.domain_name,
            records=self.records,
            warnings=self.warnings,
            rtypes_queried=self.rtypes_queried,
        )
        return results

    def get_results(self) -> DnsSearchResult:
        '''
        Returns the current lookup results.

        Returns
        -------
        DnsSearchResult
        '''
        return DnsSearchResult(
            domain=self.domain_name,
            records=self.records,
            warnings=self.warnings,
            rtypes_queried=self.rtypes_queried,
        )

    def reset(self) -> None:
        '''
        Resets the internal state for a new lookup.
        '''
        self.warnings.clear()
        self.rtypes_queried.clear()
        self.records = DomainRecords()

    @classmethod
    def from_ip_address(cls, ip_address: str, *, options: DnsSearchOptions | None = None) -> DnsSearchEngine:
        domain_name = _EngineUtils.reverse_name(ip_address)
        return cls(domain_name, options=options)

    async def resolve(
        self,
        name: str,
        rtype: dns.rdatatype.RdataType,
        *,
        catch_errors: bool = True
    ) -> dns.resolver.Answer:
        '''
        Resolves a specific DNS record type for a given name.

        Parameters
        ----------
        name : str
            _The domain name to look up._
        rtype : dns.rdatatype.RdataType
            _The record type to look up._

        Returns
        -------
        list[str]
            _A list of resolved records as strings._
        '''
        if catch_errors:
            async with self._catch_errors(rtype):
                response = await self._resolver.resolve(
                    name,
                    rtype,
                    lifetime=self.options.lifetime,
                    search=self.options.search,
                    source_port=self.options.source_port,
                    tcp=self.options.tcp,
                )
        else:
            response = await self._resolver.resolve(
                name,
                rtype,
                lifetime=self.options.lifetime,
                search=self.options.search,
                source_port=self.options.source_port,
                tcp=self.options.tcp,
            )
        return response

    async def _check_forward_coro(
        self,
        ip_address: str,
        record_type: dns.rdatatype.RdataType,
        hostname: str
    ) -> bool:
        try:
            response = await self.resolve(hostname, record_type, catch_errors=True)
            if any(getattr(rdata, "address", None) == ip_address for rdata in response):
                return True
        except Exception:
            return False
        return False

    @classmethod
    async def fcrdns_okay(
        cls,
        ip_address: str,
        *,
        options: DnsSearchOptions | None = None
    ) -> bool:
        '''
        Performs a Forward-Confirmed Reverse DNS (FCrDNS) check.

        Parameters
        ----------
        ip_address : str
            _The IP address to check._
        options : DnsSearchOptions | None
            _Options for the DNS lookup._

        Returns
        -------
        bool
            _True if the FCrDNS check passes, False otherwise._
        '''
        engine = cls.from_ip_address(ip_address, options=options)
        await engine.lookup(dns.rdatatype.PTR)



        if not engine.records.PTR:
            return False


        for host in engine.records.PTR:
            coros = (
                engine._check_forward_coro(ip_address, dns.rdatatype.A, host.target),
                engine._check_forward_coro(ip_address, dns.rdatatype.AAAA, host.target),
            )
            results = await asyncio.gather(*coros)
            if any(results):
                return True
        return False










class EmailDomainLookup:

    @staticmethod
    def _get_email_domain(email: str) -> str:
        try:
            v = email_validator.validate_email(email)
            return v.domain
        except email_validator.EmailNotValidError as e:
            raise ValueError(f"Invalid email address: {email}") from e

    def __init__(self, email_address: str, *, options: DnsSearchOptions | None = None) -> None:
        self.email_address = email_address
        self.domain_name = EmailDomainLookup._get_email_domain(email_address)
        self.dns_engine = DnsSearchEngine(
            self.domain_name,
            options=options
        )

    async def get_mx_records(self) -> list[MXRecord]:
        await self.dns_engine.lookup(dns.rdatatype.MX)
        results = self.dns_engine.get_results()
        mx_records = results.records.MX
        self.dns_engine.reset()
        return mx_records

    async def search(self) -> EmailDnsResult:
        mx_records = await self.get_mx_records()
        is_authentic = bool(mx_records)
        return EmailDnsResult(
            email=self.email_address,
            domain=self.domain_name,
            records=mx_records,
            warnings=self.dns_engine.warnings,
            is_authentic=is_authentic,
        )



async def collect_dns_records(
    domain_name: str,
    *,
    options: DnsSearchOptions | None = None,
    rtypes: tuple[dns.rdatatype.RdataType, ...] | None = None
) -> DnsSearchResult:
    '''
    Fetches DNS records for a given domain.

    Parameters
    ----------
    domain_name : str
        _The domain name to look up._
    options : DnsSearchOptions | None
        _Options for the DNS lookup._
    rtypes : tuple[dns.rdatatype.RdataType, ...] | None
        _The record types to look up. If None, all supported types will be looked up._

    Returns
    -------
    DnsSearchResult
    '''
    resolver = DnsSearchEngine(domain_name, options=options)
    return await resolver.lookup_records(rtypes=rtypes)

async def get_email_records(
    email_address: str,
    *,
    options: DnsSearchOptions | None = None,
) -> EmailDnsResult:
    '''
    Fetches MX records for a given email address.

    Parameters
    ----------
    email_address : str
        _The email address to look up._
    options : DnsSearchOptions | None
        _Options for the DNS lookup._

    Returns
    -------
    EmailDnsResult
    '''
    lookup = EmailDomainLookup(email_address, options=options)
    return await lookup.search()

async def reverse_dns_lookup(
    ip_address: str,
    *,
    options: DnsSearchOptions | None = None
) -> list[PTRRecord]:
    '''
    Performs a reverse DNS lookup for a given IP address.

    Parameters
    ----------
    ip_address : str
        _The IP address to look up._
    options : DnsSearchOptions | None
        _Options for the DNS lookup._

    Returns
    -------
    DnsSearchResult
    '''
    engine = DnsSearchEngine.from_ip_address(ip_address, options=options)
    await engine.lookup(dns.rdatatype.PTR)
    return engine.records.PTR