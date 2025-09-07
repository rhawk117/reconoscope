import asyncio
import email.parser
import re

import httpx

from reconoscope.modules.models import EmailAuthentication, EmailDomainAuth, EmailHeaderRecord, RecievedIPs
from reconoscope.modules.ip_search import IPInfoCollector

class EmailAuthParser:
    """
    Parses email authentication results from headers with
    Authentication-Results field, uses pre-compiled regex
    patterns.
    """

    spf_match_re = re.compile(
        r"(?i)spf=(pass|fail|softfail|neutral|none|temperror|permerror)"
    )
    spf_domain_match_re: re.Pattern =  re.compile(r"envelope-from=([^;\s]+)")
    dkim_match_re = re.compile(
        r"(?i)dkim=(pass|fail|none|policy|neutral|temperror|permerror)"
    )
    dkim_domain_match_re = re.compile(r"d=([^;\s]+)")
    dmarc_match_re = re.compile(
        r"(?i)dmarc=(pass|fail|none|policy|neutral|temperror|permerror)"
    )

    def scan_text(self, pattern: re.Pattern, text: str | None) -> str | None:
        if not text:
            return None
        if match := pattern.search(text, re.IGNORECASE):
            return match.group(1)
        return None

    def __call__(self, auth_results: list[str], from_: str) -> EmailAuthentication:
        if "@" in from_:
            domain_token = from_.split("@", 1)[-1]
            from_domain = domain_token.strip(">").strip().lower()

        spf = EmailDomainAuth()
        dkim = EmailDomainAuth()
        dmarc = None

        for line in auth_results or []:
            if not line:
                continue

            if spf_result := self.scan_text(self.spf_match_re, line):
                spf.result = spf_result

            if spf_domain := self.scan_text(self.spf_domain_match_re, line):
                spf.domain = spf_domain

            if dkim_result := self.scan_text(self.dkim_match_re, line):
                dkim.result = dkim_result

            if dkim_domain := self.scan_text(self.dkim_domain_match_re, line):
                dkim.domain = dkim_domain

            if dmarc_result := self.scan_text(self.dmarc_match_re, line):
                dmarc = dmarc_result

        if from_domain:
            spf.aligned = spf.domain is not None and spf.domain.lower() == from_domain
            dkim.aligned = (
                dkim.domain is not None and dkim.domain.lower() == from_domain
            )

        return EmailAuthentication(
            spf=spf,
            dkim=dkim,
            dmarc=dmarc,
        )



class EmailHeaderAnalyzer:
    IP_ADDRESS_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def __init__(self, *, client: httpx.AsyncClient, raw_header: str) -> None:
        self.email_message = email.parser.Parser().parsestr(raw_header)
        self.ip_lookup = IPInfoCollector(client=client)

    def get_reciever_ips(self) -> list[str]:
        received_headers = self.email_message.get_all("Received", [])
        ips: set[str] = set()
        for header in received_headers:
            found_ips = self.IP_ADDRESS_RE.findall(header)
            ips.update(found_ips)
        return list(ips)

    async def add_reciever_ips(self, record: EmailHeaderRecord) -> RecievedIPs:
        reciever_ips = self.get_reciever_ips()
        record.reciever_ips.ip_list = list(reciever_ips)
        tasks = [asyncio.create_task(self.ip_lookup(ip)) for ip in reciever_ips]
        for fut in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(fut, Exception):
                record.reciever_ips.errors.append(str(fut))
            else:
                record.reciever_ips.ip_report.append(fut) # type: ignore


        return record.reciever_ips

    async def __call__(self) -> EmailHeaderRecord:
        record = EmailHeaderRecord(
            from_=self.email_message.get("From"),
            to_=self.email_message.get("To"),
            subject=self.email_message.get("Subject"),
            date=self.email_message.get("Date"),
        )

        auth_results = self.email_message.get_all("Authentication-Results", [])
        from_ = self.email_message.get("From", "")
        parser = EmailAuthParser()
        email_auth = parser(auth_results=auth_results, from_=from_)
        record.auth_results = email_auth
        await self.add_reciever_ips(record)

        return record

    @classmethod
    async def run(cls, raw_header: str, client: httpx.AsyncClient) -> EmailHeaderRecord:
        analyzer = cls(
            client=client,
            raw_header=raw_header
        )
        return await analyzer()

