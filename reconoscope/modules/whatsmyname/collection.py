from __future__ import annotations

import dataclasses as dc
import json
import logging
from collections.abc import Iterator
from typing import TypedDict

import httpx

from reconoscope.core.httpx import (
    httpxretry,
)
from reconoscope.modules.whatsmyname.dtos import WhatsMyNameSite
from reconoscope.modules.whatsmyname.utils import WmnSiteUtils

log = logging.getLogger(__name__)


class WhatsMyNameSchema(TypedDict, total=False):
    """
    The response structure for a JSON site.
    """

    license: list[str]
    authors: list[str]
    categories: list[str]
    sites: list[dict]


@dc.dataclass(slots=True)
class WMNRuleSet:
    include_categories: frozenset[str] = frozenset()
    exclude_categories: frozenset[str] = frozenset()

    any_known_accounts: bool = False
    require_protections_any_of: frozenset[str] = frozenset()

    http_get_only: bool = False
    ignore_protected: bool = False

    def is_allowed(self, site: WhatsMyNameSite) -> bool:
        if self.include_categories and site.entry.cat not in self.include_categories:
            return False

        if self.exclude_categories and site.entry.cat in self.exclude_categories:
            return False

        if self.http_get_only and site.method != 'GET':
            return False

        if self.ignore_protected and site.options.protection:
            return False

        if self.require_protections_any_of:
            have = {p.lower() for p in site.options.protection}
            if not (have & self.require_protections_any_of):
                return False

        return True

    def pre_filter(self, site_json: dict) -> bool:
        cat = site_json.get('cat', '')
        if self.include_categories and cat not in self.include_categories:
            return False
        if self.exclude_categories and cat in self.exclude_categories:
            return False

        if self.http_get_only and (
            'post_body' in site_json and site_json.get('post_body')
        ):
            return False

        if self.any_known_accounts and not site_json.get('known'):
            return False

        if self.ignore_protected and site_json.get('protection'):
            return False

        if self.require_protections_any_of:
            protection = site_json.get('protection') or []
            have = {p.lower() for p in protection}
            if not (have & self.require_protections_any_of):
                return False

        return True


@dc.dataclass(slots=True)
class WMNCollection:
    sites: list[dict] = dc.field(default_factory=list)
    categories: set[str] = dc.field(default_factory=set)
    authors: set[str] = dc.field(default_factory=set)
    rule_set: WMNRuleSet | None = None

    @classmethod
    def build(
        cls,
        schema: WhatsMyNameSchema,
        rule_set: WMNRuleSet | None = None,
    ) -> 'WMNCollection':
        """
        build a WMNCollection from a WhatsMyNameSchema and optional rule set.

        Parameters
        ----------
        schema : WhatsMyNameSchema
            The schema to load sites from.
        rule_set : WMNRuleSet | None, optional
            An optional rule set to filter sites, by default None

        Returns
        -------
        WMNCollection
        """
        return cls(
            rule_set=rule_set,
            sites=schema.get('sites', []),
            authors=set(schema.get('authors', [])),
            categories=set(schema.get('categories', [])),
        )

    @property
    def size(self) -> int:
        """
        Get the total number of site entries in the collection.

        Returns
        -------
        int
        """
        return len(self.sites)

    def _auto_discard_iterator(self) -> Iterator[dict]:
        while self.sites:
            cur = self.sites.pop()
            if self.rule_set and not self.rule_set.pre_filter(cur):
                continue
            yield cur

    def _basic_iterator(self) -> Iterator[dict]:
        for entry in self.sites:
            if self.rule_set and not self.rule_set.pre_filter(entry):
                continue
            yield entry

    def iter_site_json(self, *, auto_discard: bool = True) -> Iterator[dict]:
        """
        Iterate over all sites in the collection, applying any rule set filters.

        Yields
        ------
        Iterator[WhatsMyNameSite]
        """

        if auto_discard:
            iterator = self._auto_discard_iterator
        else:
            iterator = self._basic_iterator

        for site_json in iterator():
            yield site_json

    def producer(self, *, auto_discard: bool = True) -> Iterator[WhatsMyNameSite]:
        """
        build WhatsMyNameSite instances from the collection, applying any rule set
        filters.

        Yields
        ------
        Iterator[WhatsMyNameSite]
        """

        for site_json in self.iter_site_json(auto_discard=auto_discard):
            result = WmnSiteUtils.try_load_wmn_site_json(site_json)
            if not (site := result.site):
                log.warning(f'Skipping invalid site entry: {result.error}')
                continue
            yield site

    def chunkate(self, chunk_size: int) -> Iterator[list[dict]]:
        """
        Chunk the sites into lists of a given size.

        Parameters
        ----------
        chunk_size : int
            The size of each chunk.

        Yields
        ------
        Iterator[list[WhatsMyNameSite]]
        """

        if chunk_size <= 0:
            raise ValueError('chunk_size must be greater than 0')

        chunk: list[dict] = []
        for raw_json in self._auto_discard_iterator():
            chunk.append(raw_json)

            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk


class WMNLoaders:
    _WMN_DEFAULT_URL = (
        'https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json'
    )
    _DEFAULT_PATHNAME = 'data/whatsmyname.json'

    @staticmethod
    @httpxretry(attempts=3)
    async def fetch_wmn_json(
        client: httpx.AsyncClient,
        url: str | None = None,
    ) -> WhatsMyNameSchema:
        """
        Fetch the WhatsMyName JSON schema from a URL.

        Parameters
        ----------
        url : str | None, optional
            The URL to fetch the schema from, by default None
            (uses the default WMN URL)
        client : httpx.AsyncClient
            The HTTPX client to use for the request.

        Returns
        -------
        WhatsMyNameSchema
            The fetched schema.

        Raises
        ------
        httpx.HTTPError
            If the request fails.
        ValueError
            If the response is not valid JSON or does not conform to the schema.
        """
        fetch_url = url or WMNLoaders._WMN_DEFAULT_URL
        log.debug(f'Fetching WhatsMyName JSON from {fetch_url}')
        response = await client.get(fetch_url, timeout=15)
        response.raise_for_status()
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError('Response JSON is not an object')
            return data  # type: ignore
        except Exception as exc:
            raise ValueError(f'Failed to parse WhatsMyName JSON: {exc}') from exc

    @staticmethod
    def load_json(pathname: str) -> WhatsMyNameSchema:
        """
        Load the WhatsMyName JSON schema from a local file.

        Parameters
        ----------
        pathname : str
            The path to the local JSON file.

        Returns
        -------
        WhatsMyNameSchema
            The loaded schema.

        Raises
        ------
        FileNotFoundError
            If the file does not exist.
        ValueError
            If the file is not valid JSON or does not conform to the schema.
        """
        from reconoscope.core import fs_utils

        json_string = fs_utils.read_text(pathname, join_to_root=True)

        log.debug(f'Loading WhatsMyName JSON from {pathname}')
        try:
            return json.loads(json_string)
        except Exception as exc:
            raise ValueError(f'Failed to load WhatsMyName JSON: {exc}') from exc


