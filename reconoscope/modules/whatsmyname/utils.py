"""
Utility functions for working with WhatsMyNameSite instances,
not attached to the instance to conserve memory.
"""

from __future__ import annotations

import dataclasses as dc
import json
import logging
from typing import Final, NamedTuple

import httpx

from reconoscope.modules.whatsmyname.dtos import (
    WhatsMyNameEntry,
    WhatsMyNameOptions,
    WhatsMyNameSite,
    WMNRequestParts,
)

log = logging.getLogger(__name__)

class _SanitizationUtils:
    _ACCOUNT_PLACEHOLDER: Final[str] = '{account}'

    @staticmethod
    def replace_account_placeholder(template: str, account: str) -> str:
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
        return template.replace(_SanitizationUtils._ACCOUNT_PLACEHOLDER, account)

    @staticmethod
    def sanitize_accountname(site: WhatsMyNameSite, account: str) -> str:
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

class _WMNLoadResult(NamedTuple):
    site: WhatsMyNameSite | None
    error: Exception | None


class WmnSiteUtils:
    @staticmethod
    def get_site_url(site: WhatsMyNameSite, account: str) -> str:
        safe_accountname = _SanitizationUtils.sanitize_accountname(site, account)
        return _SanitizationUtils.replace_account_placeholder(
            site.entry.uri_check, safe_accountname
        )

    @staticmethod
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
        safe_accountname = _SanitizationUtils.sanitize_accountname(site, account)
        return _SanitizationUtils.replace_account_placeholder(
            site.options.uri_pretty, safe_accountname
        )

    @staticmethod
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
        safe_accountname = _SanitizationUtils.sanitize_accountname(site, account)
        return _SanitizationUtils.replace_account_placeholder(
            site.options.post_body, safe_accountname
        )

    @staticmethod
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

    @staticmethod
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
        candidate = site.options.headers.get(
            'Content-Type'
        ) or site.options.headers.get('content-type')
        return candidate is not None and 'application/json' in candidate.lower()

    @staticmethod
    def _try_set_request_json(
        existing_parts: WMNRequestParts, body_string: str
    ) -> None:
        try:
            body_json = json.loads(body_string)
            existing_parts.json_payload = body_json
        except json.JSONDecodeError:
            log.warning(
                'Body is not valid JSON, sending as raw string, using fallback content_bytes'
            )
            existing_parts.content_bytes = body_string.encode('utf-8')

    @staticmethod
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
        site_url = WmnSiteUtils.get_site_url(site, account)

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

        body_string = WmnSiteUtils.get_site_body(site, account) or ''
        if not WmnSiteUtils.is_content_type_json(site):
            parts.content_bytes = body_string.encode('utf-8')
            return parts

        WmnSiteUtils._try_set_request_json(parts, body_string)
        return parts


class HTTPStreamUtils:
    @staticmethod
    def encode_nullable(s: str | None) -> bytes:
        return s.encode('utf-8') if s else b''

    @staticmethod
    async def stream_contains(
        response: httpx.Response,
        *,
        must_contain: str | None,
        must_not_contain: str | None,
        chunk_size: int = 16_384,
        max_size_mb: int = 10,
    ) -> tuple[bool, bool]:
        """
        Streams a httpx.response and check for the presence of certain strings
        in a very memory efficient manner.

        Technical Details
        -----------------
        This function reads the response body in chunks, checking each chunk
        for the presence of the specified strings. It handles cases where the
        strings may span across chunk boundaries by maintaining a tail of bytes
        from the end of the previous chunk.

        - Seen Positive Identifier: A flag that indicates whether the positive
        identifier has been found in the stream or the sites `m_string`

        - Seen Negative Identifier: A flag that indicates whether the negative
        identifier has been found in the stream or the sites `e_string`

        This function could've been a class tbh but I'm too sleep deprived to
        refactor it now.

        Parameters
        ----------
        response : httpx.Response
        must_contain : str | None
        must_not_contain : str | None
        chunk_size : int, optional
            _description_, by default 16_384 (16 KB)
        max_size_mb : int, optional
            _description_, by default 10

        Returns
        -------
        tuple[bool, bool]
            _(seen_positive_identifier, seen_negative_identifier)_
        """
        seen_positive_identifier = False
        seen_negative_identifier = False

        pos_identifier: bytes = HTTPStreamUtils.encode_nullable(must_contain)
        negative_identifier: bytes = HTTPStreamUtils.encode_nullable(must_not_contain)

        need_positive = bool(pos_identifier)
        need_negative = bool(negative_identifier)

        overlap_boundary = max(len(pos_identifier), len(negative_identifier), 1) - 1
        tail = b''
        total_read = 0

        max_bytes = max_size_mb * 1_048_576
        async for chunk in response.aiter_bytes(chunk_size=chunk_size):
            total_read += len(chunk)
            if total_read > max_bytes:
                break

            buffer = tail + chunk
            if need_positive and pos_identifier in buffer:
                seen_positive_identifier = True

            if need_negative and negative_identifier in buffer:
                seen_negative_identifier = True

            if need_negative and seen_negative_identifier:
                return (seen_positive_identifier, seen_negative_identifier)
            if need_positive and seen_positive_identifier and not need_negative:
                return (True, False)

            tail = buffer[-overlap_boundary:] if overlap_boundary > 0 else b''

        return (seen_positive_identifier, seen_negative_identifier)
