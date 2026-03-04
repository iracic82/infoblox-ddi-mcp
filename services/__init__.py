"""Shared utilities for service clients."""

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def create_resilient_session(api_key: str):
    """Create a requests.Session with retry logic and connection pooling.

    Configures:
    - Retry: 3 attempts with exponential backoff on 429/502/503/504
    - Connection pool: 20 connections, 10 max per host
    - Auth header and content type
    """
    import requests

    retry_strategy = Retry(
        total=3,
        backoff_factor=0.5,  # 0.5s, 1s, 2s
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        raise_on_status=False,  # Let the caller handle status via raise_for_status()
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=20,
        pool_maxsize=10,
    )

    session = requests.Session()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({"Authorization": f"Token {api_key}", "Content-Type": "application/json"})

    return session
