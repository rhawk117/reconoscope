
from __future__ import annotations
from typing import cast
import functools
from typing import Any

import dns.rdata
import dns.rdatatype
from dns.rdtypes.IN.A import A as R_A
from dns.rdtypes.IN.AAAA import AAAA as R_AAAA
from dns.rdtypes.ANY.MX import MX as R_MX
from dns.rdtypes.ANY.NS import NS as R_NS
from dns.rdtypes.ANY.CNAME import CNAME as R_CNAME
from dns.rdtypes.ANY.SOA import SOA as R_SOA
from dns.rdtypes.ANY.TXT import TXT as R_TXT
from dns.rdtypes.ANY.PTR import PTR as R_PTR

import dns.resolver
from reconoscope.modules.dns_search.records import (
    ARecord,
    AAAARecord,
    CNAMERecord,
    MXRecord,
    NSRecord,
    SOARecord,
    TXTRecord,
    DomainRecords,
    PTRRecord,
)

def _name(n: Any) -> str:
    return "" if n is None else str(n).rstrip(".")


def _txt_join(r: R_TXT) -> str:
    if getattr(r, "strings", None):
        parts = [
            s.decode(errors="ignore") if isinstance(s, (bytes, bytearray)) else str(s)
            for s in r.strings
        ]
        return "".join(parts)
    return r.to_text().strip('"')


def _ttl(ans: dns.resolver.Answer) -> int | None:
    return getattr(ans, "ttl", None)

@functools.singledispatch
def parse_rdata(r: dns.rdata.Rdata, ans: dns.resolver.Answer) -> object:
    '''
    A parser for the rdata of a DNS record, using singledispatch to handle
    different types for record

    Parameters
    ----------
    r : Any
        _description_
    ans : dns.resolver.Answer
        _description_

    Returns
    -------
    object
        _The resolved record object_
    '''
    return r.to_text() if hasattr(r, "to_text") else str(r)


@parse_rdata.register
def _(r: R_A, ans: dns.resolver.Answer) -> ARecord:
    return ARecord(address=r.address, ttl=_ttl(ans))


@parse_rdata.register
def _(r: R_AAAA, ans: dns.resolver.Answer) -> AAAARecord:
    return AAAARecord(address=r.address, ttl=_ttl(ans))


@parse_rdata.register
def _(r: R_MX, ans: dns.resolver.Answer) -> MXRecord:
    return MXRecord(
        preference=int(r.preference), exchange=_name(r.exchange), ttl=_ttl(ans)
    )


@parse_rdata.register
def _(r: R_NS, ans: dns.resolver.Answer) -> NSRecord:
    return NSRecord(target=_name(r.target), ttl=_ttl(ans))


@parse_rdata.register
def _(r: R_CNAME, ans: dns.resolver.Answer) -> CNAMERecord:
    return CNAMERecord(target=_name(r.target), ttl=_ttl(ans))


@parse_rdata.register
def _(r: R_SOA, ans: dns.resolver.Answer) -> SOARecord:
    return SOARecord(
        mname=_name(r.mname),
        rname=_name(r.rname),
        serial=int(r.serial),
        refresh=int(r.refresh),
        retry=int(r.retry),
        expire=int(r.expire),
        minimum=int(r.minimum),
        ttl=_ttl(ans),
    )


@parse_rdata.register
def _(r: R_TXT, ans: dns.resolver.Answer) -> TXTRecord:
    return TXTRecord(text=_txt_join(r), ttl=_ttl(ans))

@parse_rdata.register
def _(r: R_PTR, ans: dns.resolver.Answer) -> PTRRecord:
    return PTRRecord(target=_name(r.target), ttl=_ttl(ans))


def collect_record(bag: DomainRecords, rtype: dns.rdatatype.RdataType, record: Any) -> None:
    match rtype:
        case dns.rdatatype.A:
            bag.A.append(cast(ARecord, record))
        case dns.rdatatype.AAAA:
            bag.AAAA.append(cast(AAAARecord, record))
        case dns.rdatatype.MX:
            bag.MX.append(cast(MXRecord, record))
        case dns.rdatatype.NS:
            bag.NS.append(cast(NSRecord, record))
        case dns.rdatatype.CNAME:
            bag.CNAME.append(cast(CNAMERecord, record))
        case dns.rdatatype.SOA:
            bag.SOA.append(cast(SOARecord, record))
        case dns.rdatatype.TXT:
            bag.TXT.append(cast(TXTRecord, record))
        case dns.rdatatype.PTR:
            bag.PTR.append(cast(PTRRecord, record))
        case _:
            pass

