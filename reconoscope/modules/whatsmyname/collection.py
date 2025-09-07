from __future__ import annotations

import asyncio
import dataclasses as dc
import pprint
from typing import Final

from reconoscope.core import httpclient
from reconoscope.modules.whatsmyname.dtos import (
    WhatsMyNameEntry,
    WhatsMyNameOptions,
    WhatsMyNameSite,
)

_ACCOUNT_PLACEHOLDER: Final[str] = "{account}"


def _replace_account_placeholder(
    template: str,
    account: str,
    *,
    _placeholder=_ACCOUNT_PLACEHOLDER
) -> str:
    """
    Replace the account placeholder in the given template with the actual
    account name, although it should be in f-string format, this sometimes
    causes issues with curly braces in URLs.

    Parameters
    ----------
    template : str
        The template string containing the placeholder.
    account : str
        The account name to replace the placeholder with.

    Returns
    -------
    str
        The resulting string with the placeholder replaced.
    """
    return template.replace(_placeholder, account)

def _sanitize_accountname(site: WhatsMyNameSite, account: str) -> str:
    """
    Sanitize the account name by removing any unwanted characters

    Parameters
    ----------
    account : str

    Returns
    -------
    str
    """
    user = account
    if site.options.strip_bad_char:
        user = user.replace(site.options.strip_bad_char, "")
    return user


class WMNSiteUtils:
    '''
    Utility functions for working with WhatsMyNameSite instances,
    not attached to the instance to conserve memory.
    '''
    @staticmethod
    def get_site_url(site: WhatsMyNameSite, account: str) -> str:
        safe_accountname = _sanitize_accountname(site, account)
        return _replace_account_placeholder(site.entry.uri_check, safe_accountname)

    @staticmethod
    def get_site_pretty_url(site: WhatsMyNameSite, account: str) -> str | None:
        '''
        Get the pretty URL for the given account name.

        Parameters
        ----------
        site : WhatsMyNameSite
        account : str

        Returns
        -------
        str | None
            _The pretty url if set in the site options_
        '''
        if not site.options.uri_pretty:
            return None
        safe_accountname = _sanitize_accountname(site, account)
        return _replace_account_placeholder(site.options.uri_pretty, safe_accountname)

    @staticmethod
    def get_site_body(site: WhatsMyNameSite, account: str) -> str | None:
        '''
        Get the body to send with the request for
        the given account name.

        Parameters
        ----------
        site : WhatsMyNameSite
        account : str

        Returns
        -------
        str | None
            _The body, if present in the site options_
        '''
        if not site.options.post_body:
            return None
        safe_accountname = _sanitize_accountname(site, account)
        return _replace_account_placeholder(site.options.post_body, safe_accountname)

    @staticmethod
    def try_load_json(json_entry: dict) -> tuple[WhatsMyNameSite | None, Exception | None]:
        '''
        Does a best-effort attempt to load a WhatsMyNameSite from a JSON
        dictionary, returning either the site or an error if one occurred.

        Parameters
        ----------
        json_entry : dict

        Returns
        -------
        tuple[WhatsMyNameSite | None, Exception | None]
            _The loaded site instance or error_
        '''
        entry_kwargs = {}
        try:
            for field in dc.fields(WhatsMyNameEntry):
                entry_kwargs[field.name] = json_entry.pop(field.name)
            entry = WhatsMyNameEntry(**entry_kwargs)
        except KeyError as e:
            return None, ValueError(f"Missing required key: {e}")
        except TypeError as e:
            return None, ValueError(f"Invalid type for key: {e}")

        try:
            extras = WhatsMyNameOptions(**json_entry)
        except TypeError as e:
            return None, ValueError(f"Invalid WMN option or unexpected key: {e}")

        site = WhatsMyNameSite(entry=entry, options=extras)

        return site, None

    @staticmethod
    def is_content_type_json(site: WhatsMyNameSite) -> bool:
        candidate = site.options.headers.get("Content-Type") or site.options.headers.get("content-type")
        return candidate is not None and "application/json" in candidate.lower()



async def test_wnm_site() -> None:
    url = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
    async with httpclient.create_httpx_client() as client:
        resp = await client.get(url)
        resp.raise_for_status()
        raw: WMNRoot = resp.json()

    sites_raw = raw.get("sites", []) or []
    for s in sites_raw:
        wmn, error = WhatsMyNameSite.try_load_json(s)
        if error:
            input(f"Error loading site: {error}")
            continue
        assert wmn is not None
        try:
            pprint.pprint(wmn.request("exampleuser"))
        except Exception as e:
            input(f"Error printing site: {e}")
            pprint.pprint(wmn)
            continue
        input("----------------------")

    print(f"Total sites loaded: {len(sites_raw)}")


async def _example() -> None:
    await test_wnm_site()


if __name__ == "__main__":
    asyncio.run(_example())
