from __future__ import annotations

import abc
import dataclasses as dc
import functools
from collections.abc import Callable
from typing import Protocol, Self

import httpx


class RequestHook(Protocol):
    async def __call__(self, request: httpx.Request) -> None: ...

class ResponseHook(Protocol):
    async def __call__(self, response: httpx.Response) -> None: ...

class HttpxMiddleware(abc.ABC):
    @abc.abstractmethod
    async def on_request(self, request: httpx.Request) -> None:
        pass

    @abc.abstractmethod
    async def on_response(
        self,
        response: httpx.Response,
    ) -> None:
        pass


@dc.dataclass
class ClientEvents:
    '''
    Manages HTTPX client event hooks for requests and responses and makes
    it easy to register them via decorators or through inheritance using
    the
    '''
    _request_hooks: list[RequestHook] = dc.field(default_factory=list, init=False)
    _response_hooks: list[ResponseHook] = dc.field(default_factory=list, init=False)

    def register(
        self,
        *,
        response: ResponseHook | None = None,
        request: RequestHook | None = None,
        middleware: HttpxMiddleware | None = None,
    ) -> None:
        if middleware:
            self._request_hooks.append(middleware.on_request)
            self._response_hooks.append(middleware.on_response)

        if response:
            self._response_hooks.append(response)

        if request:
            self._request_hooks.append(request)

    def request(self, func: RequestHook):
        '''
        Decorator to register a request hook.

        Parameters
        ----------
        func : RequestHook

        '''
        @functools.wraps(func)
        def _decorator(f: RequestHook):
            self._request_hooks.append(f)
            return f

        return _decorator(func)

    def response(self, func: ResponseHook):
        '''
        Decorator to register a response hook.

        Parameters
        ----------
        func : ResponseHook

        Returns
        -------
        _The decorator_
        '''
        @functools.wraps(func)
        def _decorator(f: ResponseHook):
            self._response_hooks.append(f)
            return f

        return _decorator(func)

    @property
    def request_hooks(self) -> tuple[RequestHook, ...]:
        '''
        Immutable tuple of request hooks.

        Returns
        -------
        tuple[RequestHook, ...]
        '''
        return tuple(self._request_hooks)

    @property
    def response_hooks(self) -> tuple[ResponseHook, ...]:
        '''
        Immutable tuple of response hooks.

        Returns
        -------
        tuple[ResponseHook, ...]
        '''
        return tuple(self._response_hooks)

    def httpx_args(self) -> dict[str, list[Callable]]:
        '''
        Returns a dictionary suitable for passing to the httpx.AsyncClient

        Returns
        -------
        dict[str, list[Callable]]
        '''
        return {
            'request': self._request_hooks,
            'response': self._response_hooks,
        }

    def add_to_instance(self, client: httpx.AsyncClient) -> None:
        client.event_hooks.update(self.httpx_args())

    def merge(self, other: Self) -> None:
        '''
        Merges another ClientEvents instance into this one.

        Parameters
        ----------
        other : Self
        '''
        self._request_hooks.extend(other._request_hooks)
        self._response_hooks.extend(other._response_hooks)

    def merge_all(self, *others: Self) -> None:
        '''
        Merges multiple ClientEvents instances into this one.

        Parameters
        ----------
        *others : Self
        '''
        for other in others:
            self.merge(other)
