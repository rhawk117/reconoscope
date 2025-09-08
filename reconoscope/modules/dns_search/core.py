from __future__ import annotations

import asyncio
import contextlib
import dataclasses as dc
import sys
import warnings
from collections.abc import AsyncIterator
from typing import Coroutine, Self, cast

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import dns.reversename
import email_validator
from rich.console import Console

from reconoscope.modules.dns_search import parser
from reconoscope.modules.dns_search.records import DomainRecords, MXRecord, PTRRecord


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
            yield parser.parse_rdata(rdata, response)

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


def render_record(record: object | dict) -> str:
    message = ''
    if dc.is_dataclass(record):
        items = dc.asdict(record).items()
    else:
        items = record.items()  # type: ignore
    for key, value in items:  # type: ignore
        if key == 'ttl':
            continue
        message += f'[bold]{key}[/bold]: [italic green]{value}[/italic green]\n'
    return message


def stringify_results(result: DnsSearchResult) -> str:
    message = (
        f'[bold underline]DNS Lookup Results for {result.domain}[/bold underline]\n'
        f'[bold]Queried Record Types:[/bold] {", ".join(result.rtypes_queried)}\n'
        f'[bold]Warnings:[/bold] {", ".join(result.warnings) if result.warnings else "None"}\n'
    )
    for rtype, records in dc.asdict(result.records).items():
        if records:
            message += f'\n[bold underline]{rtype} Records:[/bold underline]\n'
            for record in records:
                message += render_record(record)
        else:
            message += f'\n[bold underline]{rtype} Records:[/bold underline] None\n'

    return message


def result_table(results: dict[str, DnsSearchResult]) -> None:
    from rich.table import Table

    console = Console()
    table = Table(title='DNS Lookup Results')
    table.add_column('Domain', style='cyan', no_wrap=True)
    table.add_column('Record Type', style='magenta')
    table.add_column('Records', style='green')
    table.add_column('Warnings', style='red')

    for domain, result in results.items():
        record_summaries = []
        for rtype, records in dc.asdict(result.records).items():
            if records:
                record_summaries.append(f'{rtype}: {len(records)}')
        record_summary = (
            '\n'.join(record_summaries) if record_summaries else 'No records found'
        )
        warnings_summary = '\n'.join(result.warnings) if result.warnings else 'None'
        table.add_row(
            domain, ', '.join(result.rtypes_queried), record_summary, warnings_summary
        )

    console.print(table)


def auto_run_dns() -> None:
    console = Console()

    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = console.input('Enter a domain name to look up: ')

    results = asyncio.run(fetch_dns_records(domain_name=domain, options=DnsConfig()))
    console.print(stringify_results(results))

    console.print('\n[bold underline]Summary Table[/bold underline]\n')
    result_table({results.domain: results})


def auto_run_email() -> None:
    console = Console()

    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        email = console.input('Enter an email address to look up: ')

    result = asyncio.run(email_dns_lookup(email_address=email, options=DnsConfig()))

    console.print(
        f'[bold underline]Email DNS Lookup Results for {result.email}[/bold underline]'
    )
    console.print(f'[bold]Domain:[/bold] {result.domain}')
    console.print(
        f'[bold]Is Authentic:[/bold] {"Yes" if result.is_authentic else "No"}'
    )
    if result.warnings:
        console.print(f'[bold]Warnings:[/bold] {", ".join(result.warnings)}')
    if result.records:
        console.print('[bold underline]MX Records:[/bold underline]')
        for record in result.records:
            console.print(render_record(record))
    else:
        console.print('[bold underline]MX Records:[/bold underline] None')


def auto_reversename() -> None:
    console = Console()

    if len(sys.argv) > 1:
        ip_address = sys.argv[1]
    else:
        ip_address = console.input('Enter an IP address to look up: ')

    try:
        ptr_records = asyncio.run(
            reversename_lookup(ip_address=ip_address, options=DnsConfig())
        )
        console.print(
            f'[bold underline]Reverse DNS Lookup Results for {ip_address}[/bold underline]'
        )
        if ptr_records:
            for record in ptr_records:
                console.print(render_record(record))
        else:
            console.print('No PTR records found.')
    except ValueError as e:
        console.print(f'[red]Error:[/red] {e}')


if __name__ == '__main__':
    auto_run_dns()