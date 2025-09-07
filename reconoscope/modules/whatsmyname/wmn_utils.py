"""
Utility functions for working with WhatsMyNameSite instances,
not attached to the instance to conserve memory.
"""

from __future__ import annotations

import asyncio
import dataclasses as dc
import json
import logging
import pprint
from typing import Final, NamedTuple

from reconoscope.core import httpx
from reconoscope.modules.whatsmyname.dtos import (
    WhatsMyNameEntry,
    WhatsMyNameOptions,
    WhatsMyNameSite,
    WMNRequestParts,
)

_ACCOUNT_PLACEHOLDER: Final[str] = '{account}'
log = logging.getLogger(__name__)


def _replace_account_placeholder(
    template: str, account: str, *, _placeholder=_ACCOUNT_PLACEHOLDER
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
        user = user.replace(site.options.strip_bad_char, '')
    return user


def get_site_url(site: WhatsMyNameSite, account: str) -> str:
    safe_accountname = _sanitize_accountname(site, account)
    return _replace_account_placeholder(site.entry.uri_check, safe_accountname)


def get_site_pretty_url(site: WhatsMyNameSite, account: str) -> str | None:
    """
    Get the pretty URL for the given account name.

    Parameters
    ----------
    site : WhatsMyNameSite
    account : str

    Returns
    -------
    str | None
        _The pretty url if set in the site options_
    """
    if not site.options.uri_pretty:
        return None
    safe_accountname = _sanitize_accountname(site, account)
    return _replace_account_placeholder(site.options.uri_pretty, safe_accountname)


def get_site_body(site: WhatsMyNameSite, account: str) -> str | None:
    """
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
    """
    if not site.options.post_body:
        return None
    safe_accountname = _sanitize_accountname(site, account)
    return _replace_account_placeholder(site.options.post_body, safe_accountname)


class _WMNLoadResult(NamedTuple):
    site: WhatsMyNameSite | None
    error: Exception | None


def try_load_wmn_site_json(
    json_entry: dict,
) -> _WMNLoadResult:
    """
    Does a best-effort attempt to load a WhatsMyNameSite from a JSON
    dictionary, returning either the site or an error if one occurred.

    Parameters
    ----------
    json_entry : dict

    Returns
    -------
    tuple[WhatsMyNameSite | None, Exception | None]
        _The loaded site instance or error_
    """
    entry_kwargs = {}
    try:
        for field in dc.fields(WhatsMyNameEntry):
            entry_kwargs[field.name] = json_entry.pop(field.name)
        entry = WhatsMyNameEntry(**entry_kwargs)
    except KeyError as e:
        return _WMNLoadResult(None, ValueError(f'Missing required key: {e}'))
    except TypeError as e:
        return _WMNLoadResult(
            None, ValueError(f'Invalid WMN entry or unexpected key: {e}')
        )

    try:
        extras = WhatsMyNameOptions(**json_entry)
    except TypeError as e:
        return _WMNLoadResult(
            None, ValueError(f'Invalid WMN options or unexpected key: {e}')
        )

    site = WhatsMyNameSite(entry=entry, options=extras)

    return _WMNLoadResult(site, None)


def is_content_type_json(site: WhatsMyNameSite) -> bool:
    """
    Check if the Content-Type header indicates JSON content.

    Parameters
    ----------
    site : WhatsMyNameSite

    Returns
    -------
    bool
    """
    candidate = site.options.headers.get('Content-Type') or site.options.headers.get(
        'content-type'
    )
    return candidate is not None and 'application/json' in candidate.lower()


def _try_set_request_json(existing_parts: WMNRequestParts, body_string: str) -> None:
    try:
        body_json = json.loads(body_string)
        existing_parts.json_payload = body_json
    except json.JSONDecodeError:
        log.warning(
            'Body is not valid JSON, sending as raw string, using fallback content_bytes'
        )
        existing_parts.content_bytes = body_string.encode('utf-8')


def get_request_parts(
    *,
    site: WhatsMyNameSite,
    account: str,
    base_headers: dict[str, str],
) -> WMNRequestParts:
    """
    Get the request parts for the given site and account name.

    Parameters
    ----------
    site : WhatsMyNameSite
    account : str

    Returns
    -------
    WMNRequestParts
        _The parts of the request to use_
    """
    method = site.method
    site_url = get_site_url(site, account)

    merged = dict(base_headers)
    if site.options.headers:
        merged.update(site.options.headers)

    parts = WMNRequestParts(
        method=method,
        url=site_url,
        headers=merged,
    )


    if method == 'GET':
        return parts

    body_string = get_site_body(site, account) or ''
    if not is_content_type_json(site):
        parts.content_bytes = body_string.encode('utf-8')
        return parts

    _try_set_request_json(parts, body_string)
    return parts



async def _example() -> None:
    await test_wnm_site()


if __name__ == "__main__":
    asyncio.run(_example())
