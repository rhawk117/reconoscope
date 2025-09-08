from __future__ import annotations

import dataclasses as dc
import random
from collections.abc import Iterator
from enum import Enum
from types import MappingProxyType
from typing import Final


class BrowserFlavor(Enum):
    CHROME = 'chrome'
    FIREFOX = 'firefox'


class OSFlavors(Enum):
    WINDOWS = 'windows'
    MAC = 'mac'
    LINUX = 'linux'
    ANDROID = 'android'
    IOS = 'ios'

    @classmethod
    def mobile(cls) -> tuple[OSFlavors, ...]:
        return (cls.ANDROID, cls.IOS)

    @classmethod
    def desktop(cls) -> tuple[OSFlavors, ...]:
        return (cls.WINDOWS, cls.MAC, cls.LINUX)


class _VersionMap:
    """
    Immutable mapping of browser engines to version strings.
    """

    __version_spec__ = MappingProxyType(
        {
            'chrome': '118.0.0.0',
            'firefox': '118.0',
            'webkit': '537.36',
            'webkit_safari': '605.1.15',
            'gecko': '109.0',
            'ios_build': '15E148',
        }
    )

    def __getitem__(self, key: str) -> str:
        return self.__version_spec__[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self.__version_spec__)

    def __setitem__(self, key: str, value: str) -> None:
        raise TypeError('VersionMap is immutable')


def _render_template(
    *,
    versions: _VersionMap,
    browser: BrowserFlavor,
    os: OSFlavors,
    template: str,
) -> str:
    return template.format(
        **{
            'os': os.value,
            'webkit': versions['webkit'],
            'webkit_safari': versions['webkit_safari'],
            f'{browser.value}_version': versions[browser.value],
            'gecko': versions['gecko'],
            'ios_build': versions['ios_build'],
        }
    )


@dc.dataclass(frozen=True)
class _UserAgents:
    """
    Singleton for generating user-agent strings using the `_VersionMap` for use
    for package users and internal usage for modules. The versions of the
    operating systems and browsers are static and should be updated as needed
    to reflect current versions.
    """

    _combo_cache: dict[str, str] = dc.field(init=False, default_factory=dict)
    versions: Final[_VersionMap] = dc.field(
        init=False,
        default_factory=_VersionMap,
    )

    def _cache_key(self, browser: BrowserFlavor, os: OSFlavors) -> str:
        return f'{browser.value}_{os.value}'

    def chrome_header(self, target_os: OSFlavors) -> str:
        """
        Generates a Chrome user-agent string based on the specified OS.

        Parameters
        ----------
        os : OSFlavors

        Raises
        ------
        ValueError
            _unsupported osflavor, should never occur_

        Returns
        -------
        str
        """
        base_str = 'Mozilla/5.0 ({os}) AppleWebKit/{webkit} (KHTML, like Gecko)'

        match target_os:
            case (
                OSFlavors.WINDOWS,
                OSFlavors.MAC,
                OSFlavors.LINUX,
            ):
                base_str += (
                    ' CriOS/{chrome_version} Mobile/{ios_build} Safari/{webkit_safari}'
                )
            case OSFlavors.IOS:
                base_str += ' Chrome/{chrome_version} Mobile Safari/{webkit}'
            case OSFlavors.ANDROID:
                base_str += ' Chrome/{chrome_version} Safari/{webkit}'
            case _:
                raise ValueError(f'Unsupported OS flavor: {target_os}')

        return _render_template(
            browser=BrowserFlavor.CHROME,
            os=target_os,
            versions=self.versions,
            template=base_str,
        )

    def firefox_header(self, target_os: OSFlavors) -> str:
        """
        Generates a Firefox user-agent string based on the specified OS.

        Parameters
        ----------
        os : OSFlavors

        Returns
        -------
        str

        Raises
        ------
        ValueError
            _unsupported osflavor, should never occur_
        """
        base_str = 'Mozilla/5.0 '

        match target_os:
            case (
                OSFlavors.WINDOWS,
                OSFlavors.MAC,
                OSFlavors.LINUX,
            ):
                base_str += (
                    '({os}; rv:{gecko}) Gecko/20100101 Firefox/{firefox_version}'
                )
            case OSFlavors.IOS:
                base_str += (
                    '({os}) AppleWebKit/{webkit_safari} (KHTML, like Gecko) '
                    'FxiOS/{firefox_version} Mobile/{ios_build} Safari/{webkit_safari}'
                )
            case OSFlavors.ANDROID:
                base_str += '({os}; rv:{gecko}) Gecko/{firefox_version} Firefox/{firefox_version}'
            case _:
                raise ValueError(f'Unsupported OS flavor: {target_os}')

        return _render_template(
            browser=BrowserFlavor.FIREFOX,
            os=target_os,
            versions=self.versions,
            template=base_str,
        )

    def iter_combinations(self) -> Iterator[str]:
        '''
        Iterates over all cached user-agent string combinations.

        Yields
        ------
        Iterator[str]
        '''
        if self._combo_cache:
            yield from self._combo_cache.values()
            return
        for browser in BrowserFlavor:
            factory = (
                self.chrome_header
                if browser == BrowserFlavor.CHROME
                else self.firefox_header
            )
            for os in OSFlavors:
                ua_str = factory(os)
                key = self._cache_key(browser, os)
                self._combo_cache[key] = ua_str
                yield ua_str

    def random(self) -> str:
        """
        Returns a random user-agent string from the cached combinations.

        Returns
        -------
        str
        """

        if not self._combo_cache:
            list(self.iter_combinations())

        return random.choice(list(self._combo_cache.values()))

user_agents: Final[_UserAgents] = _UserAgents()