from __future__ import annotations
import dataclasses as dc






@dc.dataclass(slots=True)
class ARecord:
    '''
    An "IPv4 Address" DNS record.
    '''
    address: str
    ttl: int | None = None
    text: str | None = None  # For TXT records


class AAAARecord(ARecord):
    '''
    An "IPv6 Address" DNS record.
    '''




@dc.dataclass(slots=True)
class MXRecord:
    '''
    A "Mail Exchange" DNS record.
    '''
    preference: int
    exchange: str
    ttl: int | None = None


@dc.dataclass(slots=True)
class SOARecord:
    '''
    A "Start of Authority" DNS record.
    '''
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    ttl: int | None = None


@dc.dataclass(slots=True)
class DNSRecordSet:
    '''
    A collection of DNS records for a domain.
    '''
    A: list[ARecord] = dc.field(default_factory=list)
    AAAA: list[AAAARecord] = dc.field(default_factory=list)
    CNAME: list[str] = dc.field(default_factory=list)
    MX: list[MXRecord] = dc.field(default_factory=list)
    NS: list[str] = dc.field(default_factory=list)
    TXT: list[str] = dc.field(default_factory=list)
    SOA: list[SOARecord] = dc.field(default_factory=list)
    CAA: list[str] = dc.field(default_factory=list)
    SRV: list[str] = dc.field(default_factory=list)


@dc.dataclass(slots=True)
class DomainLookupRecord:
    '''
    A DNS record for a domain.
    '''
    domain: str
    records: DNSRecordSet
    warnings: list[str] = dc.field(default_factory=list)
