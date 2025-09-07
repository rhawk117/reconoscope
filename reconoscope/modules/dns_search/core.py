from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import contextlib
import dataclasses as dc
from typing import Coroutine, Self, cast
import warnings
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
class DnsConfig:
    '''
    Options for DNS lookups.
    '''
    filename: str = "/etc/resolv.conf"
    configure: bool = True
    lifetime: float = 5.0
    search: bool | None = None
    source_port: int = 0
    tcp: bool = False


def create_aiodns_resolver(options: DnsConfig | None = None) -> dns.asyncresolver.Resolver:
    options = options or DnsConfig()
    resolver = dns.asyncresolver.Resolver(
        configure=options.configure,
        filename=options.filename,
    )
    return resolver

def get_email_domain(email: str) -> str:
    try:
        v = email_validator.validate_email(email)
        return v.domain
    except email_validator.EmailNotValidError as e:
        raise ValueError(f"Invalid email address: {email}") from e


def get_reverse_ip_name(ip_address: str) -> str:
    try:
        rev_name = dns.reversename.from_address(ip_address)
        return str(rev_name).rstrip(".")
    except Exception as e:
        raise ValueError(f"Invalid IP address: {ip_address}") from e

@dc.dataclass(slots=True, kw_only=True)
class _DnsQueryWorker:
    domain_name: str
    resolver: dns.asyncresolver.Resolver

    async def resolve_rtype(
        self,
        rtype: dns.rdatatype.RdataType,
        config: DnsConfig,
    ) -> dns.resolver.Answer:
        return await self.resolver.resolve(
            self.domain_name,
            rtype,
            lifetime=config.lifetime,
            search=config.search,
            source_port=config.source_port,
            tcp=config.tcp,
        )

    async def stream_resolution(
        self,
        rtype: dns.rdatatype.RdataType,
        config: DnsConfig,
    ) -> AsyncIterator[object]:
        response = await self.resolve_rtype(rtype, config)
        for rdata in response:
            yield parser.parse_rdata(rdata)

@dc.dataclass(slots=True)
class DnsQuery:
    '''
    A class for performing DNS queries for multiple records
    for a specific domain.
    '''
    resolver: dns.asyncresolver.Resolver
    options: DnsConfig
    domain_name: str
    warnings: list[str] = dc.field(default_factory=list)
    rtypes_queried: list[str] = dc.field(default_factory=list)
    _records: DomainRecords = dc.field(default_factory=DomainRecords)

    @classmethod
    def create(
        cls,
        *,
        domain_name: str,
        config: DnsConfig | None = None,
        resolver: dns.asyncresolver.Resolver | None = None,
    ) -> Self:
        config = config or DnsConfig()
        if not resolver:
            resolver = create_aiodns_resolver(config)

        return cls(
            resolver=resolver,
            options=config,
            domain_name=domain_name,
        )

    @contextlib.asynccontextmanager
    async def _catch_errors(self, rtype: dns.rdatatype.RdataType):
        '''
        Wraps the `_fetch` method to catch and log DNS errors as they occur.

        Parameters
        ----------
        domain_name : str
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


    async def _searchone(self, rtype: dns.rdatatype.RdataType) -> None:
        async with self._catch_errors(rtype):
            worker = _DnsQueryWorker(
                domain_name=self.domain_name,
                resolver=self.resolver,
            )
            async for record in worker.stream_resolution(rtype, self.options):
                parser.collect_record(
                    bag=self._records,
                    rtype=rtype,
                    record=record,
                )

    async def run_query(self, rtypes: tuple[dns.rdatatype.RdataType, ...]) -> DnsSearchResult:
        await asyncio.gather(*(self._searchone(rtype) for rtype in rtypes))
        return DnsSearchResult(
            domain=self.domain_name,
            records=self._records,
            warnings=self.warnings,
            rtypes_queried=self.rtypes_queried,
        )

    def reset(self) -> None:
        '''
        Resets the internal state for a new lookup.
        '''
        self.warnings.clear()
        self.rtypes_queried.clear()
        self._records = DomainRecords()

class ConcurrentDnsQuery:
    '''
    A class for orchestrating multiple concurrent DNS lookups
    at a given time for multiple domains.
    '''
    RECORD_TYPES: tuple[dns.rdatatype.RdataType, ...] = (
        dns.rdatatype.A,
        dns.rdatatype.AAAA,
        dns.rdatatype.MX,
        dns.rdatatype.NS,
        dns.rdatatype.CNAME,
        dns.rdatatype.SOA,
        dns.rdatatype.TXT,
    )

    def __init__(
        self,
        *,
        options: DnsConfig | None = None,
    ) -> None:
        self._lock = asyncio.Lock()
        options = options or DnsConfig()

        self._resolver = dns.asyncresolver.Resolver(
            configure=options.configure,
            filename=options.filename,
        )
        self.options = options

    @property
    def supported_rtypes(self) -> str:
        return ", ".join(dns.rdatatype.to_text(r) for r in self.RECORD_TYPES)

    def _check_rtypes(self, rtypes: tuple[dns.rdatatype.RdataType, ...]) -> tuple[dns.rdatatype.RdataType, ...]:
        unsupported_types = [
            r for r in rtypes if r not in self.RECORD_TYPES
        ]
        if unsupported_types:
            warnings.warn(
                f"Unsupported record types requested: `{unsupported_types}`, support types are: {self.supported_rtypes}",
                UserWarning
            )
            return tuple(r for r in rtypes if r in self.RECORD_TYPES)
        return rtypes


    async def query(
        self,
        *,
        domains: list[str],
        rtypes: tuple[dns.rdatatype.RdataType, ...] | None = None,
    ) -> dict[str, DnsSearchResult]:
        '''
        Performs DNS lookups for multiple domains concurrently.

        Parameters
        ----------
        domains : list[str]
            _A list of domain names to look up._
        rtypes : tuple[dns.rdatatype.RdataType, ...] | None
            _The record types to look up. If None, all supported types will be looked up._
        '''
        if rtypes is not None:
            rtypes = self._check_rtypes(rtypes)
        else:
            rtypes = self.RECORD_TYPES

        coros: list[Coroutine[None, None, DnsSearchResult]] = []
        for domain in domains:
            query = DnsQuery.create(
                domain_name=domain,
                config=self.options,
                resolver=self._resolver,
            )
            coros.append(query.run_query(rtypes))
        coro_result = await asyncio.gather(*coros)
        return {
            result.domain: result
            for result in coro_result
        }


async def fetch_dns_records(
    *,
    domain_name: str,
    options: DnsConfig | None = None,
    rtypes: tuple[dns.rdatatype.RdataType, ...] | None = None,
) -> DnsSearchResult:
    '''
    Fetches DNS records for a given domain.

    Parameters
    ----------
    domain_name : str
        _The domain name to look up._
    options : DnsConfig | None
        _Options for the DNS lookup._

    Returns
    -------
    DnsSearchResult
    '''
    resolver = DnsQuery.create(
        domain_name=domain_name,
        resolver=create_aiodns_resolver(options)
    )
    return await resolver.run_query(
        rtypes=rtypes or ConcurrentDnsQuery.RECORD_TYPES
    )

async def concurrent_dns_lookup(
    *,
    domain_names: list[str],
    options: DnsConfig | None = None,
) -> dict[str, DnsSearchResult]:
    '''
    Performs DNS lookups for multiple domains concurrently.

    Parameters
    ----------
    domain_names : list[str]
        _A list of domain names to look up._
    options : DnsConfig | None
        _Options for the DNS lookup._

    Returns
    -------
    dict[str, DnsSearchResult]
    '''
    engine = ConcurrentDnsQuery(options=options)
    return await engine.query(domains=domain_names)

async def reversename_lookup(
    *,
    ip_address: str,
    options: DnsConfig | None = None,
) -> list[PTRRecord]:

    options = options or DnsConfig()
    worker = _DnsQueryWorker(
        domain_name=get_reverse_ip_name(ip_address),
        resolver=create_aiodns_resolver(options)
    )
    ptr_records: list[PTRRecord] = []

    async for ptr_record in worker.stream_resolution(
        dns.rdatatype.PTR,
        options
    ):
        if isinstance(ptr_record, PTRRecord):
            ptr_records.append(ptr_record)

    return ptr_records


async def email_dns_lookup(
    email_address: str,
    *,
    options: DnsConfig | None = None,
) -> EmailDnsResult:
    '''
    Looks up the MX records for the domain of the given email address.

    Parameters
    ----------
    email_address : str
        _The email address to look up._
    options : DnsConfig | None
        _Options for the DNS lookup._

    Returns
    -------
    list[MXRecord]

    Raises
    ------
    ValueError
        _If the email address is invalid or if no MX records are found._
    '''
    domain = get_email_domain(email_address)
    options = options or DnsConfig()
    worker = _DnsQueryWorker(
        domain_name=domain,
        resolver=create_aiodns_resolver(options)
    )
    mx_records: list[MXRecord] = []

    async for mx_record in worker.stream_resolution(
        dns.rdatatype.MX,
        options
    ):
            mx_records.append(cast(MXRecord, mx_record))

    is_authentic = bool(mx_records)

    return EmailDnsResult(
        email=email_address,
        domain=domain,
        records=mx_records,
        is_authentic=is_authentic,
    )

def create_dns_query(
    *,
    domain_name: str,
    config: DnsConfig | None = None,
) -> DnsQuery:
    '''
    Creates a DnsQuery instance for the given domain.

    Parameters
    ----------
    domain_name : str
        _The domain name to look up._
    config : DnsConfig | None
        _Options for the DNS lookup._

    Returns
    -------
    DnsQuery
    '''
    return DnsQuery.create(
        domain_name=domain_name,
        config=config,
    )