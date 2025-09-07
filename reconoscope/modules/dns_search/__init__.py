from .core import (
    DnsConfig,
    DnsSearchResult,
    EmailDnsResult,
    MXRecord,
    DnsQuery,
    ConcurrentDnsQuery,
    fetch_dns_records,
    concurrent_dns_lookup,
    reversename_lookup,
    email_dns_lookup
)

__all__ = [
    "DnsConfig",
    "DnsSearchResult",
    "EmailDnsResult",
    "MXRecord",
    "DnsQuery",
    "ConcurrentDnsQuery",
    "fetch_dns_records",
    "concurrent_dns_lookup",
    "reversename_lookup",
    "email_dns_lookup",
]