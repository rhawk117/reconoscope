from __future__ import annotations

import dataclasses as dc
import functools
import random
from collections.abc import Iterator
from enum import Enum
from typing import NamedTuple

import msgspec
import msgspec.yaml

from reconoscope.core import fs_utils


class Versions(msgspec.Struct):
    chrome: str
    firefox: str
    webkit: str
    webkit_safari: str
    gecko: str
    ios_build: str


class UAConfig(msgspec.Struct):
    versions: Versions
    os: dict[str, str]
    templates: dict[str, str]
    matrix: dict[str, dict[str, str]]


class Browser(Enum):
    CHROME = 'chrome'
    FIREFOX = 'firefox'


class OS(Enum):
    WINDOWS = 'windows'
    MAC = 'mac'
    LINUX = 'linux'
    ANDROID = 'android'
    IOS = 'ios'



_USER_AGENTS_YML_PATH = 'data/user_agents.yml'


class _MatrixEntry(NamedTuple):
    browser: Browser
    os: OS
    template: str


@dc.dataclass(frozen=True)
class UserAgentSpec:
    _cached: dict[tuple[Browser, OS], str] = dc.field(default_factory=dict, init=False)
    filename: str = _USER_AGENTS_YML_PATH

    @functools.cached_property
    def config(self) -> UAConfig:
        path = fs_utils.join_root(self.filename)
        data = path.read_bytes()
        return msgspec.yaml.decode(data, type=UAConfig)

    def _create_ua_string(self, template_key: str, os_key: OS) -> str:
        fmt = self.config.templates.get(template_key)
        if fmt is None:
            raise KeyError(f"unknown template '{template_key}'")
        os_str = self.config.os.get(os_key.value)
        if os_str is None:
            raise KeyError(f"unknown os '{os_key.value}'")

        v = self.config.versions
        return fmt.format(
            os=os_str,
            chrome_version=v.chrome,
            firefox_version=v.firefox,
            webkit=v.webkit,
            webkit_safari=v.webkit_safari,
            gecko=v.gecko,
            ios_build=v.ios_build,
        )

    def header_for(self, browser: Browser, os_: OS) -> str:
        '''
        Generates a User-Agent header string for the given browser and OS.

        Parameters
        ----------
        browser : Browser
        os_ : OS

        Returns
        -------
        str

        Raises
        ------
        KeyError
            _Browser isnt support_
        KeyError
            _OS isnt supported_
        '''
        key = (browser, os_)
        if key in self._cached:
            return self._cached[key]

        os_map = self.config.matrix.get(browser.value)
        if os_map is None:
            raise KeyError(f"browser '{browser.value}' not in matrix")

        tmpl = os_map.get(os_.value)
        if tmpl is None:
            raise KeyError(f'no template for {browser.value}/{os_.value}')

        ua = self._create_ua_string(tmpl, os_)
        self._cached[key] = ua
        return ua

    def _walk_yml_matrix(self) -> Iterator[_MatrixEntry]:
        for b, os_map in self.config.matrix.items():
            for os_key, tmpl in os_map.items():
                yield _MatrixEntry(Browser(b), OS(os_key), tmpl)

    def build_cache(self) -> dict[tuple[Browser, OS], str]:
        if self._cached:
            return self._cached

        for entry in self._walk_yml_matrix():
            self._cached[(entry.browser, entry.os)] = self._create_ua_string(
                entry.template, entry.os
            )
        return self._cached

    def random_header(self) -> str:
        if not self._cached:
            self.build_cache()
        key = random.choice(list(self._cached.keys()))
        return self._cached[key]


