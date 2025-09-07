


import httpx


class CersthSubdomainSearch:

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client: httpx.AsyncClient = client

        