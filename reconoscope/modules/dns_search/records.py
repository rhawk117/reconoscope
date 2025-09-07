import dataclasses as dc


@dc.dataclass(slots=True)
class MXRecord:
    preference: int
    exchange: str
    ttl: int | None

@dc.dataclass(slots=True)
class PTRRecord:
    target: str
    ttl: int | None


@dc.dataclass(slots=True)
class SOARecord:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int
    ttl: int | None


@dc.dataclass(slots=True)
class ARecord:
    address: str
    ttl: int | None


@dc.dataclass(slots=True)
class AAAARecord:
    address: str
    ttl: int | None


@dc.dataclass(slots=True)
class NSRecord:
    target: str
    ttl: int | None


@dc.dataclass(slots=True)
class CNAMERecord:
    target: str
    ttl: int | None


@dc.dataclass(slots=True)
class TXTRecord:
    text: str
    ttl: int | None


@dc.dataclass(slots=True)
class DomainRecords:
    A: list[ARecord] = dc.field(default_factory=list)
    AAAA: list[AAAARecord] = dc.field(default_factory=list)
    MX: list[MXRecord] = dc.field(default_factory=list)
    NS: list[NSRecord] = dc.field(default_factory=list)
    CNAME: list[CNAMERecord] = dc.field(default_factory=list)
    SOA: list[SOARecord] = dc.field(default_factory=list)
    TXT: list[TXTRecord] = dc.field(default_factory=list)
    PTR: list[PTRRecord] = dc.field(default_factory=list)

