"""
Infoblox BloxOne DDI API Client
Handles authentication and API calls to Infoblox Cloud Services Platform
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

# Initialize caches with 5-minute TTL
# IP Spaces, DNS Zones, and Security Policies rarely change
ip_space_cache = TTLCache(maxsize=1000, ttl=300)  # 5 minutes
dns_zone_cache = TTLCache(maxsize=1000, ttl=300)
dhcp_option_cache = TTLCache(maxsize=500, ttl=300)
address_block_cache = TTLCache(maxsize=1000, ttl=300)


# Circuit Breaker Listener for logging state changes and metrics
class CircuitBreakerListener(pybreaker.CircuitBreakerListener):
    """Logs circuit breaker state changes and records metrics"""

    def state_change(self, cb, old_state, new_state):
        """Called when circuit breaker changes state"""
        new_state_str = str(new_state).split(".")[-1].replace("State object", "").strip()

        logger.warning(
            "circuit_breaker_state_change",
            name=cb.name,
            old_state=str(old_state),
            new_state=str(new_state),
            fail_counter=cb.fail_counter,
            failure_threshold=cb.fail_max,
        )

        # Record metrics
        metrics.set_circuit_state("infoblox_api", new_state_str)

        # Record if opening
        if "Open" in str(new_state):
            metrics.record_circuit_breaker_open("infoblox_api")

    def failure(self, cb, exc):
        """Called when a call fails"""
        logger.debug(
            "circuit_breaker_failure",
            name=cb.name,
            exception=str(exc),
            fail_counter=cb.fail_counter,
            failure_threshold=cb.fail_max,
        )

    def success(self, cb):
        """Called when a call succeeds"""
        logger.debug("circuit_breaker_success", name=cb.name, fail_counter=cb.fail_counter)


# Initialize circuit breaker for Infoblox API
# Opens after 5 consecutive failures, closes after 60 seconds
infoblox_breaker = pybreaker.CircuitBreaker(
    fail_max=5,  # Open circuit after 5 failures
    reset_timeout=60,  # Try to close after 60 seconds
    exclude=[  # Don't count these as failures
        requests.exceptions.Timeout,
        KeyError,
        ValueError,
    ],
    listeners=[CircuitBreakerListener()],
    name="infoblox_api",
)


def cached_method(cache, key_func=None):
    """
    Decorator for caching method results with logging and metrics

    Args:
        cache: TTLCache instance to use
        key_func: Optional function to generate cache key from args
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = hashkey(*args, **kwargs)

            # Check cache
            if cache_key in cache:
                logger.debug("cache_hit", method=func.__name__, cache_key=str(cache_key), cache_size=len(cache))
                # Record cache hit metric
                metrics.record_cache_hit("infoblox_client", func.__name__)
                return cache[cache_key]

            # Cache miss - call the actual method
            logger.debug("cache_miss", method=func.__name__, cache_key=str(cache_key), cache_size=len(cache))
            # Record cache miss metric
            metrics.record_cache_miss("infoblox_client", func.__name__)

            result = func(self, *args, **kwargs)

            # Store in cache
            cache[cache_key] = result
            return result

        return wrapper

    return decorator


class InfobloxClient:
    """Client for Infoblox BloxOne DDI API"""

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        """
        Initialize Infoblox API client

        Args:
            api_key: Infoblox API key (defaults to INFOBLOX_API_KEY env var)
            base_url: Base URL for API (defaults to INFOBLOX_BASE_URL env var or https://csp.infoblox.com)
        """
        self.api_key = api_key or os.getenv("INFOBLOX_API_KEY")
        self.base_url = (base_url or os.getenv("INFOBLOX_BASE_URL", "https://csp.infoblox.com")).rstrip("/")

        if not self.api_key:
            raise ValueError("INFOBLOX_API_KEY environment variable or api_key parameter is required")

        from services import create_resilient_session

        self.session = create_resilient_session(self.api_key)

        # Set default timeout: (connect timeout, read timeout)
        self.timeout = (5, 30)  # 5s to connect, 30s to read response

        logger.info(
            "infoblox_client_initialized",
            base_url=self.base_url,
            timeout_connect=self.timeout[0],
            timeout_read=self.timeout[1],
        )

    @staticmethod
    def _resource_endpoint(resource_id: str, resource_prefix: str) -> str:
        """Build API endpoint for a specific resource, handling both full and short IDs.

        The BloxOne DDI API returns resource IDs as full paths (e.g., "ipam/host/abc-123")
        but our methods also accept bare IDs ("abc-123"). This normalizes both forms
        to avoid path doubling like "/api/ddi/v1/ipam/host/ipam/host/abc-123".
        """
        if resource_id.startswith(resource_prefix):
            return f"/api/ddi/v1/{resource_id}"
        return f"/api/ddi/v1/{resource_prefix}/{resource_id}"

    def _request(self, method: str, endpoint: str, **kwargs) -> dict[str, Any]:
        """
        Make HTTP request to Infoblox API with circuit breaker protection

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint path (e.g., /api/ddi/v1/ipam/subnet)
            **kwargs: Additional arguments for requests

        Returns:
            Response JSON data

        Raises:
            pybreaker.CircuitBreakerError: If circuit is open
            Exception: If request fails
        """
        url = f"{self.base_url}{endpoint}"
        start_time = time.time()
        status_code = None
        error = None

        # Wrap the actual request in circuit breaker
        @infoblox_breaker
        def _make_request():
            # For DELETE requests, remove Content-Type header as it can cause HTTP 501 errors
            # DELETE requests don't have a body, so Content-Type is not needed
            if method.upper() == "DELETE":
                # Make a copy of session headers without Content-Type
                headers = {k: v for k, v in self.session.headers.items() if k.lower() != "content-type"}
                if "headers" in kwargs:
                    headers.update(kwargs["headers"])
                kwargs["headers"] = headers

            # Add timeout if not already specified
            if "timeout" not in kwargs:
                kwargs["timeout"] = self.timeout

            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response

        try:
            response = _make_request()
            status_code = response.status_code
            duration_ms = (time.time() - start_time) * 1000

            # Record successful API call metrics
            metrics.record_api_call("infoblox_client", endpoint, duration_ms, status_code)

            # Handle empty responses (common for DELETE operations)
            if response.status_code == 204:  # No content
                return {"success": True}

            # Check if response has content before parsing JSON
            if not response.text or response.text.strip() == "":
                return {"success": True}

            # Handle empty JSON object response
            if response.text.strip() == "{}":
                return {"success": True}

            return response.json()

        except pybreaker.CircuitBreakerError as e:
            duration_ms = (time.time() - start_time) * 1000
            error = "CircuitBreakerOpen"
            metrics.record_api_call("infoblox_client", endpoint, duration_ms, 503, error)

            # Circuit breaker is open - API is degraded
            logger.error(
                "circuit_breaker_open",
                message="Infoblox API circuit breaker is OPEN - API appears to be down",
                breaker_name="infoblox_api",
            )
            raise Exception(
                "Infoblox API is currently unavailable (circuit breaker open). "
                "The service will automatically retry in 60 seconds."
            ) from e
        except requests.exceptions.HTTPError as e:
            duration_ms = (time.time() - start_time) * 1000
            resp = e.response
            status_code = resp.status_code if resp is not None else 500
            error = f"HTTPError_{status_code}"
            metrics.record_api_call("infoblox_client", endpoint, duration_ms, status_code, error)

            error_msg = f"HTTP {status_code}: {resp.text if resp is not None else str(e)}"
            raise Exception(error_msg) from e
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error = type(e).__name__
            metrics.record_api_call("infoblox_client", endpoint, duration_ms, 500, error)
            raise Exception(f"Request failed: {str(e)}") from e

    # ==================== IPAM API Methods ====================

    def list_subnets(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List subnets from IPAM"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/ipam/subnet", params=params)

    def get_subnet(self, subnet_id: str) -> dict[str, Any]:
        """Get specific subnet by ID"""
        return self._request("GET", self._resource_endpoint(subnet_id, "ipam/subnet"))

    def create_subnet(self, address: str, space: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """
        Create a new subnet

        Args:
            address: CIDR notation (e.g., "192.168.1.0/24")
            space: IP space ID
            comment: Optional description
            **kwargs: Additional subnet properties
        """
        data = {"address": address, "space": space, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/ipam/subnet", json=data)

    @cached_method(ip_space_cache)
    def list_ip_spaces(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List IP spaces (cached for 5 minutes)

        Note: Results are cached since IP spaces rarely change.
        Cache automatically expires after 5 minutes.
        """
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/ipam/ip_space", params=params)

    def create_fixed_address(self, address: str, space: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """
        Reserve a fixed IP address

        Args:
            address: IP address to reserve
            space: IP space ID
            comment: Optional description
        """
        data = {"address": address, "space": space, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/ipam/fixed_address", json=data)

    def list_addresses(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List IP addresses"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/ipam/address", params=params)

    def get_next_available_ip(self, resource_id: str, count: int = 1) -> list[str]:
        """Get next available IP address(es) from a subnet, range, or address block.

        Args:
            resource_id: Resource ID — works for subnets ("ipam/subnet/..."),
                         ranges ("ipam/range/..."), or address blocks ("ipam/address_block/...")
            count: Number of IPs to retrieve (default 1)

        Returns:
            List of available IP address strings
        """
        resp = self._request(
            "GET", f"/api/ddi/v1/{resource_id}/nextavailableip", params={"count": count, "contiguous": False}
        )
        results = resp.get("results", [])
        return [r["address"] for r in results]

    # IPAM Host operations
    def list_ipam_hosts(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List IPAM hosts

        IPAM Host represents any network connected equipment that is assigned
        one or more IP addresses (combines A/AAAA and PTR records)
        """
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/ipam/host", params=params)

    def create_ipam_host(
        self, name: str, addresses: list[dict[str, Any]], comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create IPAM host with DNS and IP address associations

        Args:
            name: Hostname (FQDN)
            addresses: List of address configs with 'address', 'space' keys
            comment: Optional description

        Example addresses:
            [{"address": "192.168.1.10", "space": "ipam/ip_space/id"}]
        """
        data = {"name": name, "addresses": addresses, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/ipam/host", json=data)

    def get_ipam_host(self, host_id: str) -> dict[str, Any]:
        """Get specific IPAM host by ID"""
        return self._request("GET", self._resource_endpoint(host_id, "ipam/host"))

    def update_ipam_host(self, host_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update IPAM host"""
        return self._request("PATCH", self._resource_endpoint(host_id, "ipam/host"), json=updates)

    def delete_ipam_host(self, host_id: str) -> dict[str, Any]:
        """Delete IPAM host (removes DNS and IP associations)"""
        return self._request("DELETE", self._resource_endpoint(host_id, "ipam/host"))

    # Fixed Address operations
    def get_fixed_address(self, address_id: str) -> dict[str, Any]:
        """Get specific fixed address by ID"""
        return self._request("GET", self._resource_endpoint(address_id, "ipam/fixed_address"))

    def update_fixed_address(self, address_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update fixed address"""
        return self._request("PATCH", self._resource_endpoint(address_id, "ipam/fixed_address"), json=updates)

    def delete_fixed_address(self, address_id: str) -> dict[str, Any]:
        """Delete fixed address (moves to recycle bin)"""
        return self._request("DELETE", self._resource_endpoint(address_id, "ipam/fixed_address"))

    # Subnet operations
    def update_subnet(self, subnet_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update subnet"""
        return self._request("PATCH", self._resource_endpoint(subnet_id, "ipam/subnet"), json=updates)

    def delete_subnet(self, subnet_id: str) -> dict[str, Any]:
        """Delete subnet (moves to recycle bin)"""
        return self._request("DELETE", self._resource_endpoint(subnet_id, "ipam/subnet"))

    # Range operations
    def list_ranges(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List IP ranges"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/ipam/range", params=params)

    def create_range(self, start: str, end: str, space: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """
        Create IP range

        Args:
            start: Start IP address
            end: End IP address
            space: IP space ID
            comment: Optional description
        """
        data = {"start": start, "end": end, "space": space, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/ipam/range", json=data)

    def get_range(self, range_id: str) -> dict[str, Any]:
        """Get specific range by ID"""
        return self._request("GET", self._resource_endpoint(range_id, "ipam/range"))

    def update_range(self, range_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update range"""
        return self._request("PATCH", self._resource_endpoint(range_id, "ipam/range"), json=updates)

    def delete_range(self, range_id: str) -> dict[str, Any]:
        """Delete range (moves to recycle bin)"""
        return self._request("DELETE", self._resource_endpoint(range_id, "ipam/range"))

    # Address Block operations
    @cached_method(address_block_cache)
    def list_address_blocks(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List address blocks (cached for 5 minutes)

        Note: Results are cached since address blocks rarely change.
        """
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/ipam/address_block", params=params)

    def create_address_block(self, address: str, space: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """
        Create address block

        Args:
            address: CIDR notation (e.g., "10.0.0.0/8")
            space: IP space ID
            comment: Optional description
        """
        data = {"address": address, "space": space, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/ipam/address_block", json=data)

    def get_address_block(self, block_id: str) -> dict[str, Any]:
        """Get specific address block by ID"""
        return self._request("GET", self._resource_endpoint(block_id, "ipam/address_block"))

    def update_address_block(self, block_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update address block"""
        return self._request("PATCH", self._resource_endpoint(block_id, "ipam/address_block"), json=updates)

    def delete_address_block(self, block_id: str) -> dict[str, Any]:
        """Delete address block (moves to recycle bin)"""
        return self._request("DELETE", self._resource_endpoint(block_id, "ipam/address_block"))

    # Next-available subnet/address block operations
    def allocate_next_available_subnet(
        self, block_id: str, cidr: int, count: int = 1, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Allocate next available subnet from an address block

        Args:
            block_id: Parent address block ID
            cidr: CIDR prefix length (e.g., 24 for /24)
            count: Number of subnets to allocate
            comment: Optional description
        """
        data = {"cidr": cidr, "count": count, "comment": comment, **kwargs}
        return self._request(
            "POST",
            f"{self._resource_endpoint(block_id, 'ipam/address_block')}/nextavailablesubnet",
            json=data,
        )

    def allocate_next_available_address_block(
        self, block_id: str, cidr: int, count: int = 1, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Allocate next available address block from a parent block

        Args:
            block_id: Parent address block ID
            cidr: CIDR prefix length
            count: Number of blocks to allocate
            comment: Optional description
        """
        data = {"cidr": cidr, "count": count, "comment": comment, **kwargs}
        return self._request(
            "POST",
            f"{self._resource_endpoint(block_id, 'ipam/address_block')}/nextavailableaddressblock",
            json=data,
        )

    # ==================== DHCP API Methods ====================

    # DHCP Host operations
    def list_dhcp_hosts(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DHCP hosts"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dhcp/host", params=params)

    def get_dhcp_host(self, host_id: str) -> dict[str, Any]:
        """Get specific DHCP host by ID"""
        return self._request("GET", self._resource_endpoint(host_id, "dhcp/host"))

    def update_dhcp_host(self, host_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update DHCP host"""
        return self._request("PATCH", self._resource_endpoint(host_id, "dhcp/host"), json=updates)

    # DHCP Lease operations
    def list_dhcp_leases(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List active DHCP leases"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dhcp/lease", params=params)

    def get_dhcp_lease(self, lease_id: str) -> dict[str, Any]:
        """Get specific DHCP lease by ID"""
        return self._request("GET", self._resource_endpoint(lease_id, "dhcp/lease"))

    def send_lease_command(
        self, command: str, address: list[dict[str, str]], subnet: str | None = None, range_: str | None = None
    ) -> dict[str, Any]:
        """
        Send a command to DHCP leases (clear or resend-ddns)

        Args:
            command: Command to send — "clear" (wipe leases) or "resend-ddns"
            address: List of address objects [{"address": "10.0.0.1", "space": "ipam/ip_space/..."}]
            subnet: Optional subnet ID to scope the command
            range_: Optional range ID to scope the command
        """
        data: dict[str, Any] = {"command": command, "address": address}
        if subnet:
            data["subnet"] = subnet
        if range_:
            data["range"] = range_
        return self._request("POST", "/api/ddi/v1/dhcp/leases_command", json=data)

    # Hardware operations
    def list_hardware(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List hardware (physical hosts for DHCP)"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dhcp/hardware", params=params)

    def create_hardware(
        self, address: str, name: str | None = None, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create hardware entry

        Args:
            address: MAC address
            name: Hostname
            comment: Optional description
        """
        data = {"address": address, "name": name, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dhcp/hardware", json=data)

    def get_hardware(self, hardware_id: str) -> dict[str, Any]:
        """Get specific hardware by ID"""
        return self._request("GET", self._resource_endpoint(hardware_id, "dhcp/hardware"))

    def update_hardware(self, hardware_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update hardware"""
        return self._request("PATCH", self._resource_endpoint(hardware_id, "dhcp/hardware"), json=updates)

    def delete_hardware(self, hardware_id: str) -> dict[str, Any]:
        """Delete hardware"""
        return self._request("DELETE", self._resource_endpoint(hardware_id, "dhcp/hardware"))

    # HA Group operations
    def list_ha_groups(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List High Availability groups"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dhcp/ha_group", params=params)

    def create_ha_group(
        self, name: str, mode: str, hosts: list[dict[str, Any]], comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create HA group

        Args:
            name: Group name
            mode: HA mode ("active-active", "active-passive")
            hosts: List of host configurations
            comment: Optional description
        """
        data = {"name": name, "mode": mode, "hosts": hosts, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dhcp/ha_group", json=data)

    def get_ha_group(self, group_id: str) -> dict[str, Any]:
        """Get specific HA group by ID"""
        return self._request("GET", self._resource_endpoint(group_id, "dhcp/ha_group"))

    def update_ha_group(self, group_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update HA group"""
        return self._request("PATCH", self._resource_endpoint(group_id, "dhcp/ha_group"), json=updates)

    def delete_ha_group(self, group_id: str) -> dict[str, Any]:
        """Delete HA group"""
        return self._request("DELETE", self._resource_endpoint(group_id, "dhcp/ha_group"))

    # Option Code operations
    @cached_method(dhcp_option_cache)
    def list_option_codes(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List DHCP option codes (cached for 5 minutes)

        Note: Results are cached since DHCP option codes rarely change.
        """
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dhcp/option_code", params=params)

    def create_option_code(
        self, code: int, name: str, type: str, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create DHCP option code

        Args:
            code: Option code number
            name: Option name
            type: Data type (e.g., "string", "ip-address", "uint32")
            comment: Optional description
        """
        data = {"code": code, "name": name, "type": type, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dhcp/option_code", json=data)

    def get_option_code(self, code_id: str) -> dict[str, Any]:
        """Get specific option code by ID"""
        return self._request("GET", self._resource_endpoint(code_id, "dhcp/option_code"))

    def update_option_code(self, code_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update option code"""
        return self._request("PATCH", self._resource_endpoint(code_id, "dhcp/option_code"), json=updates)

    def delete_option_code(self, code_id: str) -> dict[str, Any]:
        """Delete option code"""
        return self._request("DELETE", self._resource_endpoint(code_id, "dhcp/option_code"))

    # Hardware Filter operations
    def list_hardware_filters(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List hardware filters"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dhcp/hardware_filter", params=params)

    def create_hardware_filter(
        self, name: str, protocol: str = "mac", comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create hardware filter

        Args:
            name: Filter name
            protocol: Protocol type
            comment: Optional description
        """
        data = {"name": name, "protocol": protocol, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dhcp/hardware_filter", json=data)

    def get_hardware_filter(self, filter_id: str) -> dict[str, Any]:
        """Get specific hardware filter by ID"""
        return self._request("GET", self._resource_endpoint(filter_id, "dhcp/hardware_filter"))

    def update_hardware_filter(self, filter_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update hardware filter"""
        return self._request("PATCH", self._resource_endpoint(filter_id, "dhcp/hardware_filter"), json=updates)

    def delete_hardware_filter(self, filter_id: str) -> dict[str, Any]:
        """Delete hardware filter (moves to recycle bin)"""
        return self._request("DELETE", self._resource_endpoint(filter_id, "dhcp/hardware_filter"))

    # Option Filter operations
    def list_option_filters(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List option filters"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dhcp/option_filter", params=params)

    def create_option_filter(self, name: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """
        Create option filter

        Args:
            name: Filter name
            comment: Optional description
        """
        data = {"name": name, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dhcp/option_filter", json=data)

    def get_option_filter(self, filter_id: str) -> dict[str, Any]:
        """Get specific option filter by ID"""
        return self._request("GET", self._resource_endpoint(filter_id, "dhcp/option_filter"))

    def update_option_filter(self, filter_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update option filter"""
        return self._request("PATCH", self._resource_endpoint(filter_id, "dhcp/option_filter"), json=updates)

    def delete_option_filter(self, filter_id: str) -> dict[str, Any]:
        """Delete option filter (moves to recycle bin)"""
        return self._request("DELETE", self._resource_endpoint(filter_id, "dhcp/option_filter"))

    # ==================== DNS Data API Methods ====================

    def list_dns_records(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DNS records"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/dns/record", params=params)

    def get_dns_record(self, record_id: str) -> dict[str, Any]:
        """Get specific DNS record by ID"""
        return self._request("GET", self._resource_endpoint(record_id, "dns/record"))

    def create_dns_record(
        self,
        name_in_zone: str,
        zone: str,
        record_type: str,
        rdata: dict[str, Any],
        view: str | None = None,
        ttl: int | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create DNS record

        Args:
            name_in_zone: Record name within zone (e.g., "www" for www.example.com)
            zone: Zone ID
            record_type: Record type (A, AAAA, CNAME, MX, TXT, PTR, SRV, etc.)
            rdata: Record-specific data (e.g., {"address": "192.168.1.1"} for A record)
            view: DNS view ID
            ttl: Time to live in seconds
            comment: Optional description
        """
        data = {"name_in_zone": name_in_zone, "zone": zone, "type": record_type, "rdata": rdata}

        if view:
            data["view"] = view
        if ttl:
            data["ttl"] = ttl
        if comment:
            data["comment"] = comment

        return self._request("POST", "/api/ddi/v1/dns/record", json=data)

    def update_dns_record(self, record_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update DNS record"""
        return self._request("PATCH", self._resource_endpoint(record_id, "dns/record"), json=updates)

    def delete_dns_record(self, record_id: str) -> dict[str, Any]:
        """Delete DNS record (moves to recycle bin)"""
        return self._request("DELETE", f"/api/ddi/v1/{record_id}")

    def create_aaaa_record(
        self,
        name_in_zone: str,
        zone: str,
        address: str,
        ttl: int | None = None,
        view: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create AAAA record (IPv6 address)

        Args:
            name_in_zone: Record name (e.g., "web" for web.example.com)
            zone: Zone ID
            address: IPv6 address (e.g., "2001:db8::1")
            ttl: Time to live in seconds
            view: DNS view ID
            comment: Optional description
        """
        rdata = {"address": address}
        return self.create_dns_record(name_in_zone, zone, "AAAA", rdata, view, ttl, comment)

    def create_ptr_record(
        self,
        name_in_zone: str,
        zone: str,
        dname: str,
        ttl: int | None = None,
        view: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create PTR record (Reverse DNS)

        Args:
            name_in_zone: Reverse IP (e.g., "100" for 100.1.168.192.in-addr.arpa)
            zone: Reverse zone ID
            dname: Domain name to point to (e.g., "web.example.com")
            ttl: Time to live in seconds
            view: DNS view ID
            comment: Optional description
        """
        rdata = {"dname": dname}
        return self.create_dns_record(name_in_zone, zone, "PTR", rdata, view, ttl, comment)

    def create_srv_record(
        self,
        name_in_zone: str,
        zone: str,
        priority: int,
        weight: int,
        port: int,
        target: str,
        ttl: int | None = None,
        view: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create SRV record (Service record)

        Args:
            name_in_zone: Service name (e.g., "_sip._tcp")
            zone: Zone ID
            priority: Priority (lower is higher priority)
            weight: Load balancing weight
            port: Service port number
            target: Target hostname
            ttl: Time to live in seconds
            view: DNS view ID
            comment: Optional description
        """
        rdata = {"priority": priority, "weight": weight, "port": port, "target": target}
        return self.create_dns_record(name_in_zone, zone, "SRV", rdata, view, ttl, comment)

    def create_ns_record(
        self,
        name_in_zone: str,
        zone: str,
        dname: str,
        ttl: int | None = None,
        view: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create NS record (Name Server)

        Args:
            name_in_zone: Subdomain or @ for zone apex
            zone: Zone ID
            dname: Name server hostname (e.g., "ns1.example.com")
            ttl: Time to live in seconds
            view: DNS view ID
            comment: Optional description
        """
        rdata = {"dname": dname}
        return self.create_dns_record(name_in_zone, zone, "NS", rdata, view, ttl, comment)

    def create_caa_record(
        self,
        name_in_zone: str,
        zone: str,
        flags: int,
        tag: str,
        value: str,
        ttl: int | None = None,
        view: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create CAA record (Certificate Authority Authorization)

        Args:
            name_in_zone: Record name or @ for zone apex
            zone: Zone ID
            flags: Flags (0 for non-critical, 128 for critical)
            tag: Property tag ("issue", "issuewild", "iodef")
            value: Property value (CA domain or mailto URI)
            ttl: Time to live in seconds
            view: DNS view ID
            comment: Optional description

        Example:
            create_caa_record("@", zone_id, 0, "issue", "letsencrypt.org")
        """
        rdata = {"flags": flags, "tag": tag, "value": value}
        return self.create_dns_record(name_in_zone, zone, "CAA", rdata, view, ttl, comment)

    def create_naptr_record(
        self,
        name_in_zone: str,
        zone: str,
        order: int,
        preference: int,
        flags: str,
        services: str,
        regexp: str,
        replacement: str,
        ttl: int | None = None,
        view: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create NAPTR record (Name Authority Pointer)

        Args:
            name_in_zone: Record name
            zone: Zone ID
            order: Order of processing
            preference: Preference for records with same order
            flags: Flags ("S", "A", "U", "P", etc.)
            services: Service parameters
            regexp: Regular expression for substitution
            replacement: Replacement pattern or domain
            ttl: Time to live in seconds
            view: DNS view ID
            comment: Optional description
        """
        rdata = {
            "order": order,
            "preference": preference,
            "flags": flags,
            "services": services,
            "regexp": regexp,
            "replacement": replacement,
        }
        return self.create_dns_record(name_in_zone, zone, "NAPTR", rdata, view, ttl, comment)

    # ==================== DNS Config API Methods ====================

    @cached_method(dns_zone_cache)
    def list_auth_zones(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List authoritative DNS zones (cached for 5 minutes)

        Note: Results are cached since DNS zones rarely change.
        """
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/dns/auth_zone", params=params)

    def create_auth_zone(
        self, fqdn: str, primary_type: str = "cloud", view: str | None = None, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create authoritative DNS zone

        Args:
            fqdn: Fully qualified domain name (e.g., "example.com")
            primary_type: Primary type (cloud, external)
            view: DNS view ID
            comment: Optional description
        """
        data = {"fqdn": fqdn, "primary_type": primary_type, "comment": comment, **kwargs}

        if view:
            data["view"] = view

        return self._request("POST", "/api/ddi/v1/dns/auth_zone", json=data)

    @cached_method(dns_zone_cache)
    def list_forward_zones(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """
        List forward zones (cached for 5 minutes)

        Note: Results are cached since forward zones rarely change.
        """
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/dns/forward_zone", params=params)

    def create_forward_zone(
        self,
        fqdn: str,
        forward_only: bool = True,
        hosts: list[str] | None = None,
        view: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Create forward zone

        Args:
            fqdn: Fully qualified domain name
            forward_only: Forward only (no recursion)
            hosts: List of DNS host IDs
            view: DNS view ID
            comment: Optional description
        """
        data = {"fqdn": fqdn, "forward_only": forward_only, "comment": comment}

        if hosts:
            data["hosts"] = hosts
        if view:
            data["view"] = view

        return self._request("POST", "/api/ddi/v1/dns/forward_zone", json=data)

    def list_dns_views(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DNS views"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/dns/view", params=params)

    def get_dns_view(self, view_id: str) -> dict[str, Any]:
        """Get specific DNS view by ID"""
        return self._request("GET", self._resource_endpoint(view_id, "dns/view"))

    def create_dns_view(self, name: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """
        Create a DNS view

        Args:
            name: View name
            comment: Optional description
        """
        data = {"name": name, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dns/view", json=data)

    def update_dns_view(self, view_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update DNS view"""
        return self._request("PATCH", self._resource_endpoint(view_id, "dns/view"), json=updates)

    def delete_dns_view(self, view_id: str) -> dict[str, Any]:
        """Delete DNS view"""
        return self._request("DELETE", self._resource_endpoint(view_id, "dns/view"))

    # RPZ Zone operations
    def list_rpz_zones(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List Response Policy Zones"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dns/auth_zone", params=params)

    def create_rpz_zone(
        self, name: str, primary_type: str = "cloud", view: str | None = None, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create a Response Policy Zone

        Args:
            name: RPZ zone name
            primary_type: Primary type (cloud, external)
            view: DNS view ID
            comment: Optional description
        """
        data = {"fqdn": name, "primary_type": primary_type, "comment": comment, **kwargs}
        if view:
            data["view"] = view
        return self._request("POST", "/api/ddi/v1/dns/auth_zone", json=data)

    def get_rpz_zone(self, zone_id: str) -> dict[str, Any]:
        """Get specific RPZ zone by ID"""
        return self._request("GET", self._resource_endpoint(zone_id, "dns/auth_zone"))

    def update_rpz_zone(self, zone_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update RPZ zone"""
        return self._request("PATCH", self._resource_endpoint(zone_id, "dns/auth_zone"), json=updates)

    def delete_rpz_zone(self, zone_id: str) -> dict[str, Any]:
        """Delete RPZ zone"""
        return self._request("DELETE", self._resource_endpoint(zone_id, "dns/auth_zone"))

    def reorder_rpz_zones(self, zone_ids: list[str]) -> dict[str, Any]:
        """
        Reorder Response Policy Zones

        Args:
            zone_ids: Ordered list of RPZ zone IDs
        """
        return self._request("POST", "/api/ddi/v1/dns/auth_zone/reorder", json={"zone_ids": zone_ids})

    # DNSSEC operations
    def sign_auth_zone(self, zone_ids: list[str]) -> dict[str, Any]:
        """
        Sign authoritative zones with DNSSEC

        Args:
            zone_ids: List of auth zone IDs to sign
        """
        return self._request("POST", "/api/ddi/v1/dns/auth_zone/sign", json={"zone_ids": zone_ids})

    def unsign_auth_zone(self, zone_ids: list[str]) -> dict[str, Any]:
        """
        Remove DNSSEC signing from authoritative zones

        Args:
            zone_ids: List of auth zone IDs to unsign
        """
        return self._request("POST", "/api/ddi/v1/dns/auth_zone/unsign", json={"zone_ids": zone_ids})

    def get_dnssec_key_status(self, zone_id: str) -> dict[str, Any]:
        """
        Get DNSSEC key status for an authoritative zone

        Args:
            zone_id: Auth zone ID
        """
        return self._request("GET", f"{self._resource_endpoint(zone_id, 'dns/auth_zone')}/dnssec_key_status")

    # DNS Delegation operations
    def list_dns_delegations(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DNS delegations"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dns/delegation", params=params)

    def create_dns_delegation(
        self,
        fqdn: str,
        delegation_servers: list[dict[str, Any]] | None = None,
        view: str | None = None,
        comment: str | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Create a DNS delegation

        Args:
            fqdn: Delegated zone FQDN
            delegation_servers: List of delegation server objects
            view: DNS view ID
            comment: Optional description
        """
        data: dict[str, Any] = {"fqdn": fqdn, "comment": comment, **kwargs}
        if delegation_servers:
            data["delegation_servers"] = delegation_servers
        if view:
            data["view"] = view
        return self._request("POST", "/api/ddi/v1/dns/delegation", json=data)

    def get_dns_delegation(self, delegation_id: str) -> dict[str, Any]:
        """Get specific DNS delegation by ID"""
        return self._request("GET", self._resource_endpoint(delegation_id, "dns/delegation"))

    def update_dns_delegation(self, delegation_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update DNS delegation"""
        return self._request("PATCH", self._resource_endpoint(delegation_id, "dns/delegation"), json=updates)

    def delete_dns_delegation(self, delegation_id: str) -> dict[str, Any]:
        """Delete DNS delegation"""
        return self._request("DELETE", self._resource_endpoint(delegation_id, "dns/delegation"))

    def flush_dns_cache(self, fqdn: str, view_id: str | None = None) -> dict[str, Any]:
        """Flush DNS cache for a specific domain.

        Args:
            fqdn: Domain name to flush (e.g., "example.com")
            view_id: Optional DNS view ID to scope the flush
        """
        data = {"fqdn": fqdn}
        if view_id:
            data["view"] = view_id
        return self._request("POST", "/api/ddi/v1/dns/cache_flush", json=data)

    # Infrastructure Management API
    def list_infra_hosts(self, limit: int = 100) -> dict[str, Any]:
        """List on-prem infrastructure hosts (BloxOne appliances)."""
        return self._request("GET", "/api/infra/v1/detail_hosts", params={"_limit": limit})

    def list_infra_services(self, limit: int = 100) -> dict[str, Any]:
        """List infrastructure services running on on-prem hosts."""
        return self._request("GET", "/api/infra/v1/detail_services", params={"_limit": limit})

    # ==================== IPAM Federation API Methods ====================

    # Federated Realms
    def list_federated_realms(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List federated realms"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/federation/federated_realm", params=params)

    def get_federated_realm(self, realm_id: str) -> dict[str, Any]:
        """Get specific federated realm by ID"""
        return self._request("GET", self._resource_endpoint(realm_id, "federation/federated_realm"))

    def create_federated_realm(self, name: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """
        Create a federated realm

        Args:
            name: Realm name
            comment: Optional description
            **kwargs: Additional realm properties
        """
        data = {"name": name, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/federation/federated_realm", json=data)

    def update_federated_realm(self, realm_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update federated realm"""
        return self._request("PATCH", self._resource_endpoint(realm_id, "federation/federated_realm"), json=updates)

    def delete_federated_realm(self, realm_id: str) -> dict[str, Any]:
        """Delete federated realm"""
        return self._request("DELETE", self._resource_endpoint(realm_id, "federation/federated_realm"))

    # Federated Blocks
    def list_federated_blocks(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List federated blocks"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/federation/federated_block", params=params)

    def get_federated_block(self, block_id: str) -> dict[str, Any]:
        """Get specific federated block by ID"""
        return self._request("GET", self._resource_endpoint(block_id, "federation/federated_block"))

    def create_federated_block(
        self, address: str, federated_realm: str, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create a federated block

        Args:
            address: CIDR notation (e.g., "10.0.0.0/8")
            federated_realm: Federated realm ID
            comment: Optional description
            **kwargs: Additional block properties
        """
        data = {"address": address, "federated_realm": federated_realm, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/federation/federated_block", json=data)

    def update_federated_block(self, block_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update federated block"""
        return self._request("PATCH", self._resource_endpoint(block_id, "federation/federated_block"), json=updates)

    def delete_federated_block(self, block_id: str) -> dict[str, Any]:
        """Delete federated block"""
        return self._request("DELETE", self._resource_endpoint(block_id, "federation/federated_block"))

    def allocate_next_available_federated_block(
        self, federated_block_id: str, cidr: int, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Allocate next available federated block from a parent block

        Args:
            federated_block_id: Parent federated block ID
            cidr: CIDR prefix length (e.g., 24 for /24)
            comment: Optional description
            **kwargs: Additional properties
        """
        data = {"cidr": cidr, "comment": comment, **kwargs}
        return self._request(
            "POST",
            f"{self._resource_endpoint(federated_block_id, 'federation/federated_block')}/next_available_federated_block",
            json=data,
        )

    # Delegations
    def list_delegations(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List delegations"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/federation/delegation", params=params)

    def get_delegation(self, delegation_id: str) -> dict[str, Any]:
        """Get specific delegation by ID"""
        return self._request("GET", self._resource_endpoint(delegation_id, "federation/delegation"))

    def create_delegation(
        self, address: str, federated_realm: str, delegated_to: str, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create a delegation

        Args:
            address: CIDR notation
            federated_realm: Federated realm ID
            delegated_to: Tenant/organization ID to delegate to
            comment: Optional description
            **kwargs: Additional delegation properties
        """
        data = {
            "address": address,
            "federated_realm": federated_realm,
            "delegated_to": delegated_to,
            "comment": comment,
            **kwargs,
        }
        return self._request("POST", "/api/ddi/v1/federation/delegation", json=data)

    def update_delegation(self, delegation_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update delegation"""
        return self._request("PATCH", self._resource_endpoint(delegation_id, "federation/delegation"), json=updates)

    def delete_delegation(self, delegation_id: str) -> dict[str, Any]:
        """Delete delegation"""
        return self._request("DELETE", self._resource_endpoint(delegation_id, "federation/delegation"))

    # Overlapping Blocks
    def list_overlapping_blocks(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List overlapping blocks"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/federation/overlapping_block", params=params)

    def get_overlapping_block(self, block_id: str) -> dict[str, Any]:
        """Get specific overlapping block by ID"""
        return self._request("GET", self._resource_endpoint(block_id, "federation/overlapping_block"))

    def create_overlapping_block(
        self, address: str, federated_realm: str, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create an overlapping block

        Args:
            address: CIDR notation
            federated_realm: Federated realm ID
            comment: Optional description
            **kwargs: Additional properties
        """
        data = {"address": address, "federated_realm": federated_realm, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/federation/overlapping_block", json=data)

    def update_overlapping_block(self, block_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update overlapping block"""
        return self._request("PATCH", self._resource_endpoint(block_id, "federation/overlapping_block"), json=updates)

    def delete_overlapping_block(self, block_id: str) -> dict[str, Any]:
        """Delete overlapping block"""
        return self._request("DELETE", self._resource_endpoint(block_id, "federation/overlapping_block"))

    # Reserved Blocks
    def list_reserved_blocks(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List reserved blocks"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/federation/reserved_block", params=params)

    def get_reserved_block(self, block_id: str) -> dict[str, Any]:
        """Get specific reserved block by ID"""
        return self._request("GET", self._resource_endpoint(block_id, "federation/reserved_block"))

    def create_reserved_block(
        self, address: str, federated_realm: str, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create a reserved block

        Args:
            address: CIDR notation
            federated_realm: Federated realm ID
            comment: Optional description
            **kwargs: Additional properties
        """
        data = {"address": address, "federated_realm": federated_realm, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/federation/reserved_block", json=data)

    def update_reserved_block(self, block_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update reserved block"""
        return self._request("PATCH", self._resource_endpoint(block_id, "federation/reserved_block"), json=updates)

    def delete_reserved_block(self, block_id: str) -> dict[str, Any]:
        """Delete reserved block"""
        return self._request("DELETE", self._resource_endpoint(block_id, "federation/reserved_block"))

    # Forward-Looking Delegations
    def list_forward_delegations(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List forward-looking delegations"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/federation/forward_looking_delegation", params=params)

    def get_forward_delegation(self, delegation_id: str) -> dict[str, Any]:
        """Get specific forward-looking delegation by ID"""
        return self._request("GET", self._resource_endpoint(delegation_id, "federation/forward_looking_delegation"))

    def create_forward_delegation(
        self, address: str, federated_realm: str, delegated_to: str, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create a forward-looking delegation

        Args:
            address: CIDR notation
            federated_realm: Federated realm ID
            delegated_to: Tenant/organization ID to delegate to
            comment: Optional description
            **kwargs: Additional properties
        """
        data = {
            "address": address,
            "federated_realm": federated_realm,
            "delegated_to": delegated_to,
            "comment": comment,
            **kwargs,
        }
        return self._request("POST", "/api/ddi/v1/federation/forward_looking_delegation", json=data)

    def update_forward_delegation(self, delegation_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update forward-looking delegation"""
        return self._request(
            "PATCH", self._resource_endpoint(delegation_id, "federation/forward_looking_delegation"), json=updates
        )

    def delete_forward_delegation(self, delegation_id: str) -> dict[str, Any]:
        """Delete forward-looking delegation"""
        return self._request("DELETE", self._resource_endpoint(delegation_id, "federation/forward_looking_delegation"))

    def preview_forward_delegation(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Preview a forward-looking delegation before creating it

        Args:
            data: Delegation data to preview
        """
        return self._request("POST", "/api/ddi/v1/federation/forward_looking_delegation_preview", json=data)

    # Federated Pools
    def list_federated_pools(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List federated pools"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter

        return self._request("GET", "/api/ddi/v1/federation/federated_pool", params=params)

    def get_federated_pool(self, pool_id: str) -> dict[str, Any]:
        """Get specific federated pool by ID"""
        return self._request("GET", self._resource_endpoint(pool_id, "federation/federated_pool"))

    def create_federated_pool(
        self, name: str, federated_realm: str, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create a federated pool

        Args:
            name: Pool name
            federated_realm: Federated realm ID
            comment: Optional description
            **kwargs: Additional properties
        """
        data = {"name": name, "federated_realm": federated_realm, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/federation/federated_pool", json=data)

    def update_federated_pool(self, pool_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update federated pool"""
        return self._request("PATCH", self._resource_endpoint(pool_id, "federation/federated_pool"), json=updates)

    def delete_federated_pool(self, pool_id: str) -> dict[str, Any]:
        """Delete federated pool"""
        return self._request("DELETE", self._resource_endpoint(pool_id, "federation/federated_pool"))

    # ==================== DTC (DNS Traffic Control / GSLB) Methods ====================

    # LBDN operations
    def list_lbdn(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DNS Traffic Control LBDNs (Load Balanced Domain Names)"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dtc/lbdn", params=params)

    def create_lbdn(
        self, name: str, view: str | None = None, dtc_policy: str | None = None, comment: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create a DTC LBDN

        Args:
            name: LBDN name
            view: DNS view ID
            dtc_policy: DTC policy ID
            comment: Optional description
        """
        data: dict[str, Any] = {"name": name, "comment": comment, **kwargs}
        if view:
            data["view"] = view
        if dtc_policy:
            data["dtc_policy"] = dtc_policy
        return self._request("POST", "/api/ddi/v1/dtc/lbdn", json=data)

    def get_lbdn(self, lbdn_id: str) -> dict[str, Any]:
        """Get specific LBDN by ID"""
        return self._request("GET", self._resource_endpoint(lbdn_id, "dtc/lbdn"))

    def update_lbdn(self, lbdn_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update LBDN"""
        return self._request("PATCH", self._resource_endpoint(lbdn_id, "dtc/lbdn"), json=updates)

    def delete_lbdn(self, lbdn_id: str) -> dict[str, Any]:
        """Delete LBDN"""
        return self._request("DELETE", self._resource_endpoint(lbdn_id, "dtc/lbdn"))

    # DTC Pool operations
    def list_dtc_pools(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DTC pools"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dtc/pool", params=params)

    def get_dtc_pool(self, pool_id: str) -> dict[str, Any]:
        """Get specific DTC pool by ID"""
        return self._request("GET", self._resource_endpoint(pool_id, "dtc/pool"))

    def create_dtc_pool(self, name: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """Create a DTC pool"""
        data = {"name": name, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dtc/pool", json=data)

    def update_dtc_pool(self, pool_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update DTC pool"""
        return self._request("PATCH", self._resource_endpoint(pool_id, "dtc/pool"), json=updates)

    def delete_dtc_pool(self, pool_id: str) -> dict[str, Any]:
        """Delete DTC pool"""
        return self._request("DELETE", self._resource_endpoint(pool_id, "dtc/pool"))

    # DTC Server operations
    def list_dtc_servers(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DTC servers"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dtc/server", params=params)

    def get_dtc_server(self, server_id: str) -> dict[str, Any]:
        """Get specific DTC server by ID"""
        return self._request("GET", self._resource_endpoint(server_id, "dtc/server"))

    def create_dtc_server(self, name: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """Create a DTC server"""
        data = {"name": name, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dtc/server", json=data)

    def update_dtc_server(self, server_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update DTC server"""
        return self._request("PATCH", self._resource_endpoint(server_id, "dtc/server"), json=updates)

    def delete_dtc_server(self, server_id: str) -> dict[str, Any]:
        """Delete DTC server"""
        return self._request("DELETE", self._resource_endpoint(server_id, "dtc/server"))

    # DTC Policy operations
    def list_dtc_policies(self, filter: str | None = None, limit: int = 100) -> dict[str, Any]:
        """List DTC policies"""
        params = {"_limit": limit}
        if filter:
            params["_filter"] = filter
        return self._request("GET", "/api/ddi/v1/dtc/policy", params=params)

    def get_dtc_policy(self, policy_id: str) -> dict[str, Any]:
        """Get specific DTC policy by ID"""
        return self._request("GET", self._resource_endpoint(policy_id, "dtc/policy"))

    def create_dtc_policy(self, name: str, comment: str | None = None, **kwargs) -> dict[str, Any]:
        """Create a DTC policy"""
        data = {"name": name, "comment": comment, **kwargs}
        return self._request("POST", "/api/ddi/v1/dtc/policy", json=data)

    def update_dtc_policy(self, policy_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update DTC policy"""
        return self._request("PATCH", self._resource_endpoint(policy_id, "dtc/policy"), json=updates)

    def delete_dtc_policy(self, policy_id: str) -> dict[str, Any]:
        """Delete DTC policy"""
        return self._request("DELETE", self._resource_endpoint(policy_id, "dtc/policy"))
