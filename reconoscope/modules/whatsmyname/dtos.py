'''
The data transfer objects for WhatsMyName module.
'''

from __future__ import annotations

import dataclasses as dc
from typing import Literal, TypeAlias, TypedDict

WMNMethods = Literal["GET", "POST"]
@dc.dataclass(slots=True)
class WhatsMyNameOptions:
    '''
    The optional fields for a WhatsMyName entry.

    Attributes
    ----------
    - m_code: The HTTP status code that indicates a non-existent username.

    - uri_pretty: A URL to the profile page, with `{account}` as a placeholder.

    - headers: A dictionary of HTTP headers to include in the request.

    - post_body: The body to send with a POST request, with `{account}` as a placeholder

    - known: A list of strings that, if found in the response, indicate a valid username

    - strip_bad_char: A string of characters to strip from the account name before
    making the request.

    - protection: A list of protection mechanisms the site may have
    (e.g., "captcha", "cloudflare").
    '''

    m_code: int | None = None
    uri_pretty: str | None = None
    headers: dict[str, str] = dc.field(default_factory=dict)
    post_body: str | None = None
    known: list[str] = dc.field(default_factory=list)
    strip_bad_char: str | None = None
    protection: list[str] = dc.field(default_factory=list)


@dc.dataclass(slots=True)
class WhatsMyNameEntry:
    '''
    The required fields for a WhatsMyName entry.

    Attributes
    ----------
    - name: The name of the site.
    - uri_check: The URL to check for the username, with `{account}` as a placeholder.
    - e_code: The expected HTTP status code for a valid username.
    - e_string: A string that must be present in the response for a valid username.
    - m_string: A string that must be absent in the response for a valid username.
    - cat: The category of the site (e.g., social, email, etc.).
    '''

    name: str
    uri_check: str
    e_code: int
    e_string: str
    m_string: str
    cat: str


class WhatsMyNameResponse(TypedDict, total=False):
    '''
    The response structure for a JSON site.
    '''
    license: list[str]
    authors: list[str]
    categories: list[str]
    sites: list[dict]


@dc.dataclass(slots=True, kw_only=True)
class WhatsMyNameSite:
    '''
    A WhatsMyName site entry, combining required and
    optional fields.
    '''
    entry: WhatsMyNameEntry
    options: WhatsMyNameOptions

    @property
    def method(self) -> WMNMethods:
        return "POST" if self.options.post_body else "GET"

    def get_header(self, hdr_name: str) -> str | None:
        '''
        Get a specific header value.

        Parameters
        ----------
        hdr_name : str

        Returns
        -------
        str | None
        '''
        return self.options.headers.get(hdr_name)


@dc.dataclass(slots=True)
class WMNRequestParts:
    '''
    A request to send built from a WhatsMyNameSite and account name.
    '''
    method: WMNMethods
    url: str
    headers: dict[str, str] = dc.field(default_factory=dict)
    json_payload: dict | None = None
    content_bytes: bytes | None = None




# url: "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"