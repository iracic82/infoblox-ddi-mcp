"""
Atcfw (Advanced Threat Control Firewall / DFP) API Client
Handles DNS Firewall Protection, Security Policies, and Threat Intelligence
API Docs: https://csp.infoblox.com/apidoc/docs/Atcfw
"""

import functools
import os
import time
from typing import Any

import pybreaker
import requests
import structlog
from cachetools import TTLCache
from cachetools.keys import hashkey
from dotenv import load_dotenv

from services import metrics

load_dotenv(override=True)  # Override system environment variables

# Initialize structured logger
logger = structlog.get_logger(__name__)

# Initialize caches for security policies (rarely change)
security_policy_cache = TTLCache(maxsize=500, ttl=300)  # 5 minutes
named_list_cache = TTLCache(maxsize=1000, ttl=300)

# Transient HTTP status codes excluded from circuit breaker failure counting
TRANSIENT_STATUS_CODES = {429, 502, 503, 504}


class TransientHTTPError(requests.exceptions.HTTPError):
    """Transient HTTP errors excluded from circuit breaker."""

    pass


# Circuit Breaker for Atcfw API
class AtcfwCircuitBreakerListener(pybreaker.CircuitBreakerListener):
    """Logs circuit breaker state changes for Atcfw API"""

    def state_change(self, cb, old_state, new_state):
        # Extract state name (e.g., "open" from "CircuitOpenState")
        new_state_str = str(new_state).split(".")[-1].replace("State object", "").strip()

        logger.warning(
            "circuit_breaker_state_change",
            name=cb.name,
            old_state=str(old_state),
            new_state=str(new_state),
            fail_counter=cb.fail_counter,
        )

        # Record metrics
        metrics.set_circuit_state(cb.name, new_state_str)
        if "Open" in str(new_state):
            metrics.record_circuit_breaker_open(cb.name)


atcfw_breaker = pybreaker.CircuitBreaker(
    fail_max=5,
    reset_timeout=60,
    exclude=[requests.exceptions.Timeout, TransientHTTPError],
    listeners=[AtcfwCircuitBreakerListener()],
    name="atcfw_api",
)


def cached_method(cache, key_func=None):
    """Decorator for caching method results with logging and metrics"""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = hashkey(*args, **kwargs)

            if cache_key in cache:
                logger.debug("cache_hit", method=func.__name__, cache_key=str(cache_key), cache_size=len(cache))
                # Record cache hit metric
                metrics.record_cache_hit("atcfw_client", func.__name__)
                return cache[cache_key]

            logger.debug("cache_miss", method=func.__name__, cache_key=str(cache_key), cache_size=len(cache))
            # Record cache miss metric
            metrics.record_cache_miss("atcfw_client", func.__name__)

            result = func(self, *args, **kwargs)
            cache[cache_key] = result
            return result

        return wrapper

    return decorator


class AtcfwClient:
    """Client for Infoblox Atcfw API - DNS Security & Threat Protection"""

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        """
        Initialize Atcfw API client

        Args:
            api_key: Infoblox API key (defaults to INFOBLOX_API_KEY env var)
            base_url: Base URL for API (defaults to https://csp.infoblox.com)
        """
        self.api_key = api_key or os.getenv("INFOBLOX_API_KEY")
        self.base_url = (base_url or os.getenv("INFOBLOX_BASE_URL", "https://csp.infoblox.com")).rstrip("/")

        if not self.api_key:
            raise ValueError("INFOBLOX_API_KEY environment variable or api_key parameter is required")

        from services import create_resilient_session

        self.session = create_resilient_session(self.api_key)

        # Set timeout for all requests (connect timeout, read timeout)
        self.timeout = (5, 30)

        logger.info(
            "atcfw_client_initialized",
            base_url=self.base_url,
            timeout_connect=self.timeout[0],
            timeout_read=self.timeout[1],
        )

    def _request(self, method: str, url: str, **kwargs) -> dict[str, Any]:
        """Make HTTP request with circuit breaker protection and metrics"""
        # Extract endpoint from URL for metrics
        endpoint = url.replace(self.base_url, "")
        start_time = time.time()
        status_code = None
        error = None

        @atcfw_breaker
        def _make_request():
            response = self.session.request(method, url, **kwargs)
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                if response.status_code in TRANSIENT_STATUS_CODES:
                    raise TransientHTTPError(str(e), response=response) from e
                raise
            return response

        try:
            response = _make_request()
            status_code = response.status_code
            duration_ms = (time.time() - start_time) * 1000

            # Record successful API call metrics
            metrics.record_api_call("atcfw_client", endpoint, duration_ms, status_code)

            return response.json()

        except pybreaker.CircuitBreakerError as e:
            duration_ms = (time.time() - start_time) * 1000
            error = "CircuitBreakerOpen"

            # Record circuit breaker open metric
            metrics.record_api_call("atcfw_client", endpoint, duration_ms, 503, error)

            logger.error("circuit_breaker_open", message="Atcfw API circuit breaker is OPEN", breaker_name="atcfw_api")
            raise Exception(
                "Atcfw API is currently unavailable (circuit breaker open). "
                "The service will automatically retry in 60 seconds."
            ) from e

        except requests.exceptions.HTTPError as e:
            duration_ms = (time.time() - start_time) * 1000
            status_code = response.status_code if "response" in locals() else 500
            error = f"HTTPError_{status_code}"

            # Record HTTP error metric
            metrics.record_api_call("atcfw_client", endpoint, duration_ms, status_code, error)

            logger.error("api_request_failed", endpoint=endpoint, status_code=status_code, error=str(e))
            raise

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error = type(e).__name__

            # Record generic error metric
            metrics.record_api_call("atcfw_client", endpoint, duration_ms, 500, error)

            logger.error("api_request_error", endpoint=endpoint, error_type=type(e).__name__, error=str(e))
            raise

    # ==================== Security Policies ====================

    @cached_method(security_policy_cache)
    def list_security_policies(self, filter_expr: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List all security policies (cached for 5 minutes)

        Note: Results are cached since security policies rarely change.
        """
        url = f"{self.base_url}/api/atcfw/v1/security_policies"
        params = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr

        return self._request("GET", url, params=params, timeout=self.timeout)

    def get_security_policy(self, policy_id: str) -> dict[str, Any]:
        """Get security policy by ID"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}"
        return self._request("GET", url, timeout=self.timeout)

    # ==================== Named Lists (Custom Threat Intel) ====================

    @cached_method(named_list_cache)
    def list_named_lists(self, filter_expr: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List custom threat intelligence named lists (cached for 5 minutes)

        Note: Results are cached since named lists rarely change.
        """
        url = f"{self.base_url}/api/atcfw/v1/named_lists"
        params = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr

        return self._request("GET", url, params=params, timeout=self.timeout)

    def create_named_list(
        self, name: str, type: str, items: list[str] | None = None, description: str = "", tags: dict | None = None
    ) -> dict[str, Any]:
        """
        Create a custom named list for threat intelligence

        Args:
            name: List name
            type: List type (custom_list, etc.)
            items: List of items (domains, IPs, etc.)
            description: List description
            tags: Optional tags

        Returns:
            Created named list details
        """
        url = f"{self.base_url}/api/atcfw/v1/named_lists"
        payload = {"name": name, "type": type, "description": description, "items": items or [], "tags": tags or {}}

        result = self._request("POST", url, json=payload, timeout=self.timeout)
        named_list_cache.clear()
        return result

    def update_named_list(self, list_id: str, **kwargs) -> dict[str, Any]:
        """Update a named list"""
        url = f"{self.base_url}/api/atcfw/v1/named_lists/{list_id}"
        result = self._request("PUT", url, json=kwargs, timeout=self.timeout)
        named_list_cache.clear()
        return result

    def delete_named_list(self, list_id: str) -> dict[str, Any]:
        """Delete a named list"""
        url = f"{self.base_url}/api/atcfw/v1/named_lists/{list_id}"
        self._request("DELETE", url, timeout=self.timeout)
        named_list_cache.clear()
        return {"status": "deleted", "id": list_id}

    def partial_update_named_list_items(
        self, list_id: str, inserts: list[str] | None = None, deletes: list[str] | None = None
    ) -> dict[str, Any]:
        """Add or remove items from a named list without replacing the entire list.

        Args:
            list_id: Named list ID
            inserts: Items to add (domains/IPs)
            deletes: Items to remove (domains/IPs)
        """
        url = f"{self.base_url}/api/atcfw/v1/named_lists/{list_id}/items"
        data = {}
        if inserts:
            data["inserts_items"] = inserts
        if deletes:
            data["deletes_items"] = deletes
        if not data:
            return {"result": "no changes — both inserts and deletes are empty"}
        result = self._request("PATCH", url, json=data, timeout=self.timeout)
        named_list_cache.clear()
        return result

    # ==================== Application Filters ====================

    def list_application_filters(self, filter_expr: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List application filters"""
        url = f"{self.base_url}/api/atcfw/v1/application_filters"
        params = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr

        return self._request("GET", url, params=params, timeout=self.timeout)

    def create_application_filter(self, name: str, criteria: list[dict], description: str = "") -> dict[str, Any]:
        """Create an application filter"""
        url = f"{self.base_url}/api/atcfw/v1/application_filters"
        payload = {"name": name, "criteria": criteria, "description": description}

        return self._request("POST", url, json=payload, timeout=self.timeout)

    def get_application_filter(self, filter_id: str) -> dict[str, Any]:
        """Get specific application filter"""
        url = f"{self.base_url}/api/atcfw/v1/application_filters/{filter_id}"
        return self._request("GET", url, timeout=self.timeout)

    def update_application_filter(self, filter_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an application filter"""
        url = f"{self.base_url}/api/atcfw/v1/application_filters/{filter_id}"
        return self._request("PUT", url, json=updates, timeout=self.timeout)

    def delete_application_filter(self, filter_id: str) -> dict[str, Any]:
        """Delete an application filter"""
        url = f"{self.base_url}/api/atcfw/v1/application_filters/{filter_id}"
        return self._request("DELETE", url, timeout=self.timeout)

    # ==================== Category Filters ====================

    def list_category_filters(self, filter_expr: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List content category filters"""
        url = f"{self.base_url}/api/atcfw/v1/category_filters"
        params = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr

        return self._request("GET", url, params=params, timeout=self.timeout)

    def get_category_filter(self, filter_id: int | str) -> dict[str, Any]:
        """Get specific category filter by ID"""
        url = f"{self.base_url}/api/atcfw/v1/category_filters/{filter_id}"
        return self._request("GET", url, timeout=self.timeout)

    def create_category_filter(self, name: str, categories: list[str], description: str = "") -> dict[str, Any]:
        """
        Create a content category filter

        Args:
            name: Filter name
            categories: List of category names to filter
            description: Optional description
        """
        url = f"{self.base_url}/api/atcfw/v1/category_filters"
        data = {"name": name, "categories": categories, "description": description}
        return self._request("POST", url, json=data, timeout=self.timeout)

    def update_category_filter(
        self, filter_id: int | str, name: str, categories: list[str], description: str = ""
    ) -> dict[str, Any]:
        """
        Update a category filter (full replace via PUT)

        Args:
            filter_id: Category filter ID
            name: Filter name (required — full replace)
            categories: List of category names (required — full replace)
            description: Optional description
        """
        url = f"{self.base_url}/api/atcfw/v1/category_filters/{filter_id}"
        data = {"name": name, "categories": categories, "description": description}
        return self._request("PUT", url, json=data, timeout=self.timeout)

    def delete_category_filter(self, filter_id: int | str) -> dict[str, Any]:
        """Delete a category filter"""
        url = f"{self.base_url}/api/atcfw/v1/category_filters/{filter_id}"
        return self._request("DELETE", url, timeout=self.timeout)

    def list_content_categories(self) -> dict[str, Any]:
        """List available content categories"""
        url = f"{self.base_url}/api/atcfw/v1/content_categories"
        return self._request("GET", url, timeout=self.timeout)

    # ==================== Internal Domain Lists ====================

    def list_internal_domain_lists(self, filter_expr: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List internal domain lists"""
        url = f"{self.base_url}/api/atcfw/v1/internal_domain_lists"
        params = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr

        return self._request("GET", url, params=params, timeout=self.timeout)

    def create_internal_domain_list(
        self, name: str, internal_domains: list[str], description: str = "", tags: dict | None = None
    ) -> dict[str, Any]:
        """Create internal domain list"""
        url = f"{self.base_url}/api/atcfw/v1/internal_domain_lists"
        payload = {"name": name, "internal_domains": internal_domains, "description": description, "tags": tags or {}}

        return self._request("POST", url, json=payload, timeout=self.timeout)

    def get_internal_domain_list(self, list_id: str) -> dict[str, Any]:
        """Get specific internal domain list"""
        url = f"{self.base_url}/api/atcfw/v1/internal_domain_lists/{list_id}"
        return self._request("GET", url, timeout=self.timeout)

    def update_internal_domain_list(self, list_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an internal domain list"""
        url = f"{self.base_url}/api/atcfw/v1/internal_domain_lists/{list_id}"
        return self._request("PUT", url, json=updates, timeout=self.timeout)

    def delete_internal_domain_list(self, list_id: str) -> dict[str, Any]:
        """Delete an internal domain list"""
        url = f"{self.base_url}/api/atcfw/v1/internal_domain_lists/{list_id}"
        return self._request("DELETE", url, timeout=self.timeout)

    # ==================== Access Codes (Bypass Codes) ====================

    def list_access_codes(self, filter_expr: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List access/bypass codes"""
        url = f"{self.base_url}/api/atcfw/v1/access_codes"
        params = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr

        return self._request("GET", url, params=params, timeout=self.timeout)

    def create_access_code(
        self, name: str, activation: str, expiration: str, rules: list[dict] | None = None, description: str = ""
    ) -> dict[str, Any]:
        """Create an access/bypass code"""
        url = f"{self.base_url}/api/atcfw/v1/access_codes"
        payload = {
            "name": name,
            "activation": activation,
            "expiration": expiration,
            "rules": rules or [],
            "description": description,
        }

        return self._request("POST", url, json=payload, timeout=self.timeout)

    def get_access_code(self, access_key: str) -> dict[str, Any]:
        """Get specific access code by key"""
        url = f"{self.base_url}/api/atcfw/v1/access_codes/{access_key}"
        return self._request("GET", url, timeout=self.timeout)

    def update_access_code(self, access_key: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an access code"""
        url = f"{self.base_url}/api/atcfw/v1/access_codes/{access_key}"
        return self._request("PUT", url, json=updates, timeout=self.timeout)

    def delete_access_code(self, access_key: str) -> dict[str, Any]:
        """Delete an access code"""
        url = f"{self.base_url}/api/atcfw/v1/access_codes/{access_key}"
        return self._request("DELETE", url, timeout=self.timeout)

    # ==================== Security Policy CRUD (full) ====================

    def create_security_policy(self, name: str, rules: list[dict] | None = None, **kwargs) -> dict[str, Any]:
        """Create a security policy"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies"
        payload = {"name": name, "rules": rules or [], **kwargs}
        result = self._request("POST", url, json=payload, timeout=self.timeout)
        security_policy_cache.clear()
        return result

    def update_security_policy(self, policy_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update a security policy"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}"
        result = self._request("PUT", url, json=updates, timeout=self.timeout)
        security_policy_cache.clear()
        return result

    def delete_security_policy(self, policy_id: str) -> dict[str, Any]:
        """Delete a security policy"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}"
        result = self._request("DELETE", url, timeout=self.timeout)
        security_policy_cache.clear()
        return result

    # ==================== Security Policy Rules ====================

    def list_security_policy_rules(self, policy_id: str) -> dict[str, Any]:
        """List rules for a security policy"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}/rules"
        return self._request("GET", url, timeout=self.timeout)

    def create_security_policy_rule(self, policy_id: str, rule: dict[str, Any]) -> dict[str, Any]:
        """Create a rule in a security policy"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}/rules"
        return self._request("POST", url, json=rule, timeout=self.timeout)

    def get_security_policy_rule(self, policy_id: str, rule_id: str) -> dict[str, Any]:
        """Get specific security policy rule"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}/rules/{rule_id}"
        return self._request("GET", url, timeout=self.timeout)

    def update_security_policy_rule(self, policy_id: str, rule_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update a security policy rule"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}/rules/{rule_id}"
        return self._request("PUT", url, json=updates, timeout=self.timeout)

    def delete_security_policy_rule(self, policy_id: str, rule_id: str) -> dict[str, Any]:
        """Delete a security policy rule"""
        url = f"{self.base_url}/api/atcfw/v1/security_policies/{policy_id}/rules/{rule_id}"
        return self._request("DELETE", url, timeout=self.timeout)

    # ==================== Network Lists ====================

    def list_network_lists(self, filter_expr: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List network lists"""
        url = f"{self.base_url}/api/atcfw/v1/network_lists"
        params = {"_limit": limit}
        if filter_expr:
            params["_filter"] = filter_expr
        return self._request("GET", url, params=params, timeout=self.timeout)

    def create_network_list(self, name: str, items: list[str] | None = None, **kwargs) -> dict[str, Any]:
        """Create a network list"""
        url = f"{self.base_url}/api/atcfw/v1/network_lists"
        payload = {"name": name, "items": items or [], **kwargs}
        return self._request("POST", url, json=payload, timeout=self.timeout)

    def get_network_list(self, list_id: str) -> dict[str, Any]:
        """Get specific network list"""
        url = f"{self.base_url}/api/atcfw/v1/network_lists/{list_id}"
        return self._request("GET", url, timeout=self.timeout)

    def update_network_list(self, list_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update a network list"""
        url = f"{self.base_url}/api/atcfw/v1/network_lists/{list_id}"
        return self._request("PUT", url, json=updates, timeout=self.timeout)

    def delete_network_list(self, list_id: str) -> dict[str, Any]:
        """Delete a network list"""
        url = f"{self.base_url}/api/atcfw/v1/network_lists/{list_id}"
        return self._request("DELETE", url, timeout=self.timeout)

    def partial_update_network_list_items(self, list_id: str, items_described: list[dict]) -> dict[str, Any]:
        """Add/remove items from a network list without replacing the entire list"""
        url = f"{self.base_url}/api/atcfw/v1/network_lists/{list_id}/items"
        return self._request("PATCH", url, json={"items_described": items_described}, timeout=self.timeout)

    # ==================== Threat Feeds & Indicators ====================

    def list_threat_feeds(self) -> dict[str, Any]:
        """List available threat feeds"""
        url = f"{self.base_url}/api/atcfw/v1/threat_feeds"
        return self._request("GET", url, timeout=self.timeout)

    def create_threat_indicator(self, data: dict[str, Any]) -> dict[str, Any]:
        """Create or lookup a threat indicator"""
        url = f"{self.base_url}/api/atcfw/v1/tid"
        return self._request("POST", url, json=data, timeout=self.timeout)

    # ==================== App/Block Approvals ====================

    def list_app_approvals(self) -> dict[str, Any]:
        """List application approvals"""
        url = f"{self.base_url}/api/atcfw/v1/app_approvals"
        return self._request("GET", url, timeout=self.timeout)

    def update_app_approvals(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Update application approvals"""
        url = f"{self.base_url}/api/atcfw/v1/app_approvals"
        return self._request("PUT", url, json=updates, timeout=self.timeout)

    def list_block_approvals(self) -> dict[str, Any]:
        """List block approvals"""
        url = f"{self.base_url}/api/atcfw/v1/block_approvals"
        return self._request("GET", url, timeout=self.timeout)

    def update_block_approvals(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Update block approvals"""
        url = f"{self.base_url}/api/atcfw/v1/block_approvals"
        return self._request("PATCH", url, json=updates, timeout=self.timeout)

    # ==================== PoP Regions & DoH ====================

    def list_pop_regions(self) -> dict[str, Any]:
        """List Point of Presence (PoP) regions"""
        url = f"{self.base_url}/api/atcfw/v1/pop_regions"
        return self._request("GET", url, timeout=self.timeout)

    def create_doh_fqdn(self, data: dict[str, Any]) -> dict[str, Any]:
        """Create DoH (DNS over HTTPS) FQDN"""
        url = f"{self.base_url}/api/atcfw/v1/doh_fqdns"
        return self._request("POST", url, json=data, timeout=self.timeout)
