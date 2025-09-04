from __future__ import annotations

import pprint
import dataclasses
from cli.internals import Renderable



@dataclasses.dataclass
class IpInfo(Renderable):
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

    def console_output(self) -> str:
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

    def console_output(self) -> str:
        return (
            f"Subdomain Enumeration for {self.domain}:\n"
            f"Total Subdomains Found: {self.total}\n"
            "Subdomains:\n" + "\n".join(f" - {sub}" for sub in self.subdomains)
        )


@dataclasses.dataclass
class DNSRecord(Renderable):
    A: list[str] = dataclasses.field(default_factory=list)
    CNAME: list[str] = dataclasses.field(default_factory=list)
    MX: list[str] = dataclasses.field(default_factory=list)
    NS: list[str] = dataclasses.field(default_factory=list)

    def console_output(self) -> str:
        output = "DNS Records:\n"
        for rtype in ("A", "CNAME", "MX", "NS"):
            records = getattr(self, rtype)
            if records:
                output += f" {rtype} Records:\n"
                for record in records:
                    output += f"  - {record}\n"
        return output


@dataclasses.dataclass
class DnsLookupResult(Renderable):
    domain: str
    records: DNSRecord
    warnings: list[str] = dataclasses.field(default_factory=list)

    def console_output(self) -> str:
        output = f"DNS Lookup for {self.domain}:\n"
        output += self.records.console_output()
        if self.warnings:
            output += "Warnings:\n"
            for warning in self.warnings:
                output += f" - {warning}\n"
        return output


@dataclasses.dataclass
class PhoneRecord(Renderable):
    phone_number: str
    is_valid: bool
    e164: str | None = None
    country: str | None = None
    region: str | None = None
    operator: str | None = None

    def console_output(self) -> str:
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
    email: str
    domain: str
    authenticity: str
    mx_records: list[str] = dataclasses.field(default_factory=list)

    def console_output(self) -> str:
        return (
            f"Email Domain Information for {self.email}:\n"
            f"[bold]Domain:[/bold] {self.domain}\n"
            f"[bold]Authenticity:[/bold] {self.authenticity}\n"
            f"[bold]MX Records:[/bold]\n" + "\n".join(f" - {mx}" for mx in self.mx_records)
        )

@dataclasses.dataclass
class ReverseDnsResult(Renderable):
    ip_address: str
    ptr_record: str

    def console_output(self) -> str:
        return (
            f"Reverse DNS Lookup for {self.ip_address}:\n"
            f"[bold]PTR Record:[/bold] {self.ptr_record}\n"
        )


@dataclasses.dataclass
class EmailDomainAuth:
    result: str | None = None
    domain: str | None = None
    aligned: bool | None = None

    def console_output(self) -> str:
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

    def console_output(self) -> str:
        return (
            "Email Authentication Results:\n"
            "[bold]SPF:[/bold]\n" + self.spf.console_output() +
            "[bold]DKIM:[/bold]\n" + self.dkim.console_output() +
            f"[bold]DMARC:[/bold] {self.dmarc}\n"
        )


@dataclasses.dataclass
class RecievedIPs(Renderable):
    ip_report: list[IpInfo] = dataclasses.field(default_factory=list)
    errors: list[str] = dataclasses.field(default_factory=list)
    ip_list: list[str] = dataclasses.field(default_factory=list)

    def add_result(self, future_result: IpInfo | Exception | BaseException) -> None:
        if isinstance(future_result, Exception):
            self.errors.append(str(future_result))
        else:
            self.ip_report.append(future_result) # type: ignore

    def console_output(self) -> str:
        output = "Recieved IPs Information:\n"
        if self.ip_report:
            output += "[green]IP Details:[/green]\n"
            for ip_info in self.ip_report:
                output += ip_info.console_output() + "\n"
        if self.errors:
            output += "[red]Errors[/red]:\n"
            for error in self.errors:
                output += f" - {error}\n"
        return output

@dataclasses.dataclass
class EmailHeaderRecord:
    from_: str | None = None
    to_: str | None = None
    subject: str | None = None
    date: str | None = None

    auth_results: EmailAuthentication | None = None
    reciever_ips: RecievedIPs = dataclasses.field(
        default_factory=RecievedIPs
    )

    def console_output(self) -> str:
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
            output += self.auth_results.console_output()
        output += self.reciever_ips.console_output()
        return output