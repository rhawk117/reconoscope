from __future__ import annotations

import abc
import pprint
import dataclasses

class Renderable(abc.ABC):
    @abc.abstractmethod
    def render(self) -> str:
        pass

    def __str__(self) -> str:
        return self.render()

@dataclasses.dataclass
class IpRecord(Renderable):
    '''
    The results from an IP address lookup.
    '''
    ip: str | None = None
    city: str | None = None
    country: str | None = None
    postal: str | None = None
    org: str | None = None
    location: str | None = None
    timezone: str | None = None
    extras: dict = dataclasses.field(default_factory=dict)

    @property
    def maps_link(self) -> str | None:
        if not self.location:
            return None
        return f"https://maps.google.com/?q={self.location}"

    def render(self) -> str:
        return (
            "IP Information:\n"
            f"[bold]IP:[/bold] {self.ip}\n"
            f"[bold]City:[/bold] {self.city}\n"
            f"[bold]Country:[/bold] {self.country}\n"
            f"[bold]Postal Code:[/bold] {self.postal}\n"
            f"[bold]Organization:[/bold] {self.org}\n"
            f"[bold]Location:[/bold] {self.location}\n"
            f"[bold]Timezone:[/bold] {self.timezone}\n"
            f"[bold]Google Maps:[/bold] {self.maps_link}\n"
            f"extras\n{pprint.pformat(self.extras, indent=4)}"
        )


@dataclasses.dataclass
class SubdomainResult(Renderable):
    domain: str
    total: int
    subdomains: list[str]

    def render(self) -> str:
        return (
            f"Subdomain Enumeration for {self.domain}:\n"
            f"Total Subdomains Found: {self.total}\n"
            "Subdomains:\n" + "\n".join(f" - {sub}" for sub in self.subdomains)
        )


@dataclasses.dataclass
class DNSRecord(Renderable):
    '''
    The records returned from a DNS lookup.
    '''
    A: list[str] = dataclasses.field(default_factory=list)
    CNAME: list[str] = dataclasses.field(default_factory=list)
    MX: list[str] = dataclasses.field(default_factory=list)
    NS: list[str] = dataclasses.field(default_factory=list)

    def render(self) -> str:
        output = "DNS Records:\n"
        for rtype in ("A", "CNAME", "MX", "NS"):
            records = getattr(self, rtype)
            if records:
                output += f" {rtype} Records:\n"
                for record in records:
                    output += f"  - {record}\n"
        return output


@dataclasses.dataclass
class DomainRecord(Renderable):
    domain: str
    records: DNSRecord
    warnings: list[str] = dataclasses.field(default_factory=list)

    def render(self) -> str:
        output = f"DNS Lookup for {self.domain}:\n"
        output += self.records.render()
        if self.warnings:
            output += "Warnings:\n"
            for warning in self.warnings:
                output += f" - {warning}\n"
        return output


@dataclasses.dataclass
class PhoneRecord(Renderable):
    '''
    Represents the result of a phone number lookup.
    '''
    phone_number: str
    is_valid: bool
    e164: str | None = None
    country: str | None = None
    region: str | None = None
    operator: str | None = None

    def render(self) -> str:
        return (
            f"Phone Number Information for {self.phone_number}:\n"
            f"[bold]E.164 Format:[/bold] {self.e164}\n"
            f"[bold]Country:[/bold] {self.country}\n"
            f"[bold]Region:[/bold] {self.region}\n"
            f"[bold]Operator:[/bold] {self.operator}\n"
            f"[bold]Is Valid:[/bold] {'Yes' if self.is_valid else 'No'}\n"
        )

@dataclasses.dataclass
class EmailDomainRecord(Renderable):
    '''
    Represents the result of an email domain lookup.
    '''
    email: str
    domain: str
    authenticity: str
    mx_records: list[str] = dataclasses.field(default_factory=list)

    def render(self) -> str:
        return (
            f"Email Domain Information for {self.email}:\n"
            f"[bold]Domain:[/bold] {self.domain}\n"
            f"[bold]Authenticity:[/bold] {self.authenticity}\n"
            f"[bold]MX Records:[/bold]\n" + "\n".join(f" - {mx}" for mx in self.mx_records)
        )

@dataclasses.dataclass
class ReverseDnsResult(Renderable):
    '''
    Represents the result of a reverse DNS lookup.
    '''
    ip_address: str
    ptr_record: str

    def render(self) -> str:
        return (
            f"Reverse DNS Lookup for {self.ip_address}:\n"
            f"[bold]PTR Record:[/bold] {self.ptr_record}\n"
        )


@dataclasses.dataclass
class EmailDomainAuth:
    '''
    Represents the authentication result of an email domain (SPF or DKIM).
    '''
    result: str | None = None
    domain: str | None = None
    aligned: bool | None = None

    def render(self) -> str:
        msg = ''
        if self.result is not None:
            msg += f"[bold]Result:[/bold] {self.result}\n"
        if self.domain is not None:
            msg += f"[bold]Domain:[/bold] {self.domain}\n"
        if self.aligned is not None:
            msg += f"[bold]Aligned:[/bold] {'Yes' if self.aligned else 'No'}\n"
        return msg
@dataclasses.dataclass
class EmailAuthentication(Renderable):
    spf: EmailDomainAuth = dataclasses.field(default_factory=EmailDomainAuth)
    dkim: EmailDomainAuth = dataclasses.field(default_factory=EmailDomainAuth)
    dmarc: str | None = None

    def render(self) -> str:
        return (
            "Email Authentication Results:\n"
            "[bold]SPF:[/bold]\n" + self.spf.render() +
            "[bold]DKIM:[/bold]\n" + self.dkim.render() +
            f"[bold]DMARC:[/bold] {self.dmarc}\n"
        )


@dataclasses.dataclass
class RecievedIPs(Renderable):
    '''
    Represents the collection of IPs that recieved an email. From the
    `Received` headers.
    '''
    ip_report: list[IpRecord] = dataclasses.field(default_factory=list)
    errors: list[str] = dataclasses.field(default_factory=list)
    ip_list: list[str] = dataclasses.field(default_factory=list)

    def add_result(self, future_result: IpRecord | Exception | BaseException) -> None:
        if isinstance(future_result, Exception):
            self.errors.append(str(future_result))
        else:
            self.ip_report.append(future_result) # type: ignore

    def render(self) -> str:
        output = "Recieved IPs Information:\n"
        if self.ip_report:
            output += "[green]IP Details:[/green]\n"
            for ip_info in self.ip_report:
                output += ip_info.render() + "\n"
        if self.errors:
            output += "[red]Errors[/red]:\n"
            for error in self.errors:
                output += f" - {error}\n"
        return output

@dataclasses.dataclass
class EmailHeaderRecord(Renderable):
    from_: str | None = None
    to_: str | None = None
    subject: str | None = None
    date: str | None = None

    auth_results: EmailAuthentication | None = None
    reciever_ips: RecievedIPs = dataclasses.field(
        default_factory=RecievedIPs
    )

    def render(self) -> str:
        output = "Email Headers:\n"
        if self.from_:
            output += f"[bold]From:[/bold] {self.from_}\n"
        if self.to_:
            output += f"[bold]To:[/bold] {self.to_}\n"
        if self.subject:
            output += f"[bold]Subject:[/bold] {self.subject}\n"
        if self.date:
            output += f"[bold]Date:[/bold] {self.date}\n"
        if self.auth_results:
            output += self.auth_results.render()
        output += self.reciever_ips.render()
        return output


@dataclasses.dataclass
class DnsBlocklistResult(Renderable):
    ip_address: str
    reverse_ip: str
    responses: dict[str, list[str]] = dataclasses.field(default_factory=dict)

    def render(self) -> str:
        output = f"DNS Blocklist Results for {self.ip_address}:\n"
        if not self.responses:
            output += " - No listings found.\n"
            return output

        for bl, entries in self.responses.items():
            output += f"[bold]{bl}:[/bold]\n"
            for entry in entries:
                output += f" - {entry}\n"

        return output


@dataclasses.dataclass
class CDNScriptInfo(Renderable):
    src: str
    host: str
    path: str
    filename: str
    async_: bool
    defer: bool
    integrity: str | None = None
    crossorigin: str | None = None

    def render(self) -> str:
        output = f"CDN Script:\n - [bold]Source:[/bold] {self.src}\n"
        output += f" - [bold]Host:[/bold] {self.host}\n"
        output += f" - [bold]Path:[/bold] {self.path}\n"
        output += f" - [bold]Filename:[/bold] {self.filename}\n"
        output += f" - [bold]Async:[/bold] {'Yes' if self.async_ else 'No'}\n"
        output += f" - [bold]Defer:[/bold] {'Yes' if self.defer else 'No'}\n"
        if self.integrity:
            output += f" - [bold]Integrity:[/bold] {self.integrity}\n"
        if self.crossorigin:
            output += f" - [bold]Crossorigin:[/bold] {self.crossorigin}\n"
        return output


@dataclasses.dataclass
class WebsiteRecord(Renderable):
    url: str
    title: str | None = None
    description: str | None = None
    keywords: list[str] = dataclasses.field(default_factory=list)
    robots: str | None = None
    author: str | None = None
    client_javascript: list[str] = dataclasses.field(default_factory=list)

    def render(self) -> str:
        output = f"Webpage Metadata for {self.url}:\n"
        if self.title:
            output += f"[bold]Title:[/bold] {self.title}\n"
        if self.description:
            output += f"[bold]Description:[/bold] {self.description}\n"
        if self.keywords:
            output += f"[bold]Keywords:[/bold] {', '.join(self.keywords)}\n"
        if self.author:
            output += f"[bold]Author:[/bold] {self.author}\n"
        if self.robots:
            output += f"[bold]Robots:[/bold] {self.robots}\n"
        if self.client_javascript:
            output += "[bold]Client-side JavaScript Files:[/bold]\n"
            for js in self.client_javascript:
                output += f" - {js}\n"


        return output