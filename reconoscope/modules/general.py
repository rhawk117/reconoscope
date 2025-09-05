import socket
import ssl
import httpx
import phonenumbers
from phonenumbers import geocoder
from phonenumbers import carrier

from reconoscope.core.retries import async_retries
from reconoscope.modules.models import PhoneRecord, WebsiteRecord
import bs4

def get_phone_info(phone_number: str) -> PhoneRecord:
    try:
        phone_obj = phonenumbers.parse(phone_number)
    except phonenumbers.NumberParseException as exc:
        raise ValueError(f"Error parsing phone number {phone_number}: {exc}")

    if is_valid := phonenumbers.is_valid_number(phone_obj):
        kwargs = {
            "e164": phonenumbers.format_number(
                phone_obj, phonenumbers.PhoneNumberFormat.E164
            ),
            "country": geocoder.country_name_for_number(phone_obj, "en"),
            "region": geocoder.description_for_number(phone_obj, "en"),
            "operator": carrier.name_for_number(phone_obj, "en"),
        }
    else:
        kwargs = {
            "e164": None,
            "country": None,
            "region": None,
            "operator": None,
        }

    return PhoneRecord(phone_number=phone_number, is_valid=is_valid, **kwargs)


class WebpageMetadata:
    meta_tag_attrs = (
        'keywords',
        'description',
        'author',
        'robots',
        'viewport',
    )
    cdn_hints = {
        "bootstrapcdn.com", "cdn.jsdelivr.net", "unpkg.com",
        "cdnjs.cloudflare.com", "cloudflare.com", "googleapis.com",
        "gstatic.com", "ajax.googleapis.com", "yastatic.net",
        "static.hotjar.com", "stackpath.bootstrapcdn.com",
        "code.jquery.com", "cdn.sstatic.net", "cdn.shopify.com",
        "cdn.plyr.io", "use.fontawesome.com", "kit.fontawesome.com",
        "cdn.ampproject.org", "cdn.rawgit.com", "cdn.datatables.net",
        "cdn.ckeditor.com", "cdn.tiny.cloud", "cdn.ckeditor.com",
        "cdn.quilljs.com", "cdn.jsdelivr.net", "cdn.syndication.twimg.com",
        "cdn3.devexpress.com", "cdn1.devexpress.com", "cdn2.devexpress.com",
        "cdn4.devexpress.com", "cdn5.devexpress.com", "cdn6.devexpress.com",
        "cdn7.devexpress.com", "cdn8.devexpress.com", "cdn9.devexpress.com",
        "maxcdn.bootstrapcdn.com", "netdna.bootstrapcdn.com",
        "ajax.aspnetcdn.com", "ajax.microsoft.com",
        "ajax.googleapis.com", "fonts.googleapis.com",
        "fonts.gstatic.com", "code.getmdl.io", "code.angularjs.org",
    }


    def __init__(self, client: httpx.AsyncClient, url: str):
        self.client: httpx.AsyncClient = client
        self.url: str = url

    @async_retries(attempts=3, delay=0.5, backoff='expo', jitter=0.1)
    async def fetch(self) -> str:
        response = await self.client.get(self.url)
        response.raise_for_status()
        return response.text

    def collect_client_side_js(self, soup: bs4.BeautifulSoup) -> list[str]:
        scripts = []
        for script in soup.find_all("script"):
            if not script.get("src"):
                scripts.append(script.string or script.get_text())
        return scripts

    async def __call__(self) -> WebsiteRecord:
        try:
            html = await self.fetch()
        except Exception:
            raise RuntimeError(f"Failed to fetch URL: {self.url}")

        soup = bs4.BeautifulSoup(html, "lxml")
        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else None

        meta: dict = {}
        for name in self.meta_tag_attrs:
            tag = soup.find("meta", attrs={"name": name})
            if tag and 'content' and 'content' in tag.attrs:
                meta[name] = tag['content']
            else:
                meta[name] = "N/A"

        client_side_js = self.collect_client_side_js(soup)

        return WebsiteRecord(
            url=self.url,
            title=title,
            client_javascript=client_side_js,
            **meta,
        )

    @classmethod
    async def collect(cls, client: httpx.AsyncClient, url: str) -> WebsiteRecord:
        instance = cls(client, url)
        return await instance()

class SslCertificateChecker:
    context = ssl.create_default_context()

    def __init__(
        self,
        *,
        domain: str,
        port: int = 443,
        timeout: int = 30
    ) -> None:
        self.domain = domain
        self.port = port
        self.timeout = timeout

    def get_certificate(self) :
        with socket.create_connection((self.domain, self.port), timeout=self.timeout) as sock:
            with self.context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                return ssock.getpeercert()
