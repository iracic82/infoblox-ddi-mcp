"""
Infoblox SOC Insights API Client

This client provides access to the Infoblox Security Operations Center (SOC) Insights API
for threat intelligence, security event monitoring, and policy compliance.

API Documentation: https://csp.infoblox.com/apidoc/docs/Insights
"""

import os
import time
from typing import Any

import pybreaker
import requests
import structlog

from services import metrics

# Initialize structured logger
logger = structlog.get_logger(__name__)

# Transient HTTP status codes excluded from circuit breaker failure counting
TRANSIENT_STATUS_CODES = {429, 502, 503, 504}


class TransientHTTPError(requests.exceptions.HTTPError):
    """Transient HTTP errors excluded from circuit breaker."""

    pass


# Circuit Breaker for Insights API
class InsightsCircuitBreakerListener(pybreaker.CircuitBreakerListener):
    """Logs circuit breaker state changes for Insights API"""

    def state_change(self, cb, old_state, new_state):
        new_state_str = str(new_state).split(".")[-1].replace("State object", "").strip()
        logger.warning(
            "circuit_breaker_state_change",
            name=cb.name,
            old_state=str(old_state),
            new_state=str(new_state),
            fail_counter=cb.fail_counter,
        )
        metrics.set_circuit_state(cb.name, new_state_str)
        if "Open" in str(new_state):
            metrics.record_circuit_breaker_open(cb.name)


insights_breaker = pybreaker.CircuitBreaker(
    fail_max=5,
    reset_timeout=60,
    exclude=[requests.exceptions.Timeout, TransientHTTPError],
    listeners=[InsightsCircuitBreakerListener()],
    name="insights_api",
)


class InsightsClient:
    """Client for Infoblox SOC Insights API - Threat Intelligence & Security Monitoring"""

    def __init__(self, api_key: str | None = None, base_url: str | None = None):
        """
        Initialize the Insights API client.

        Args:
            api_key: Infoblox API key (Token). If not provided, reads from INFOBLOX_API_KEY env var.
            base_url: Base URL for Infoblox API. Defaults to https://csp.infoblox.com
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
            "insights_client_initialized",
            base_url=self.base_url,
            timeout_connect=self.timeout[0],
            timeout_read=self.timeout[1],
        )

    def _request(self, method: str, endpoint: str, **kwargs) -> dict[str, Any]:
        """Make HTTP request with circuit breaker protection and metrics."""
        url = f"{self.base_url}/api/insights/v1{endpoint}"
        start_time = time.time()
        status_code = None
        error = None

        @insights_breaker
        def _make_request():
            if "timeout" not in kwargs:
                kwargs["timeout"] = self.timeout
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
            metrics.record_api_call("insights_client", endpoint, duration_ms, status_code)
            return response.json() if response.text else {}

        except pybreaker.CircuitBreakerError as e:
            duration_ms = (time.time() - start_time) * 1000
            error = "CircuitBreakerOpen"
            metrics.record_api_call("insights_client", endpoint, duration_ms, 503, error)
            logger.error(
                "circuit_breaker_open", message="Insights API circuit breaker is OPEN", breaker_name="insights_api"
            )
            raise Exception(
                "Insights API is currently unavailable (circuit breaker open). "
                "The service will automatically retry in 60 seconds."
            ) from e

        except requests.exceptions.HTTPError as e:
            duration_ms = (time.time() - start_time) * 1000
            status_code = response.status_code if "response" in locals() else 500
            error = f"HTTPError_{status_code}"
            metrics.record_api_call("insights_client", endpoint, duration_ms, status_code, error)
            logger.error("api_request_failed", endpoint=endpoint, status_code=status_code, error=str(e))
            raise

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            error = type(e).__name__
            metrics.record_api_call("insights_client", endpoint, duration_ms, 500, error)
            logger.error("api_request_error", endpoint=endpoint, error_type=type(e).__name__, error=str(e))
            raise

    # ============================================================
    # Insights Management
    # ============================================================

    def list_insights(
        self,
        status: str | None = None,
        threat_type: str | None = None,
        priority: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """
        List security insights with optional filtering.

        Args:
            status: Filter by insight status (e.g., 'OPEN', 'IN_PROGRESS', 'CLOSED')
            threat_type: Filter by threat type (e.g., 'malware', 'phishing', 'data_exfiltration')
            priority: Filter by priority level (e.g., 'critical', 'high', 'medium', 'low')
            limit: Maximum number of insights to return
            offset: Offset for pagination

        Returns:
            Dict with insights list and metadata
        """
        params = {"_limit": limit, "_offset": offset}
        if status:
            params["status"] = status
        if threat_type:
            params["threat_type"] = threat_type
        if priority:
            params["priority"] = priority

        return self._request("GET", "/insights", params=params)

    def get_insight(self, insight_id: str) -> dict[str, Any]:
        """
        Get detailed information for a specific security insight.

        Args:
            insight_id: The unique identifier for the insight

        Returns:
            Dict with comprehensive insight details including threat context
        """
        return self._request("GET", f"/insights/{insight_id}")

    def update_insight_status(self, insight_ids: list[str], status: str, comment: str | None = None) -> dict[str, Any]:
        """
        Update the status of one or more insights.

        Args:
            insight_ids: List of insight IDs to update
            status: New status (e.g., 'IN_PROGRESS', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE')
            comment: Optional comment explaining the status change

        Returns:
            Dict with update results
        """
        payload = {"ids": insight_ids, "status": status}
        if comment:
            payload["comment"] = comment

        return self._request("PUT", "/insights/status", json=payload)

    def get_insight_indicators(
        self,
        insight_id: str,
        confidence: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """
        Get threat indicators associated with a security insight.

        Args:
            insight_id: The insight ID
            confidence: Filter by confidence level (e.g., 'high', 'medium', 'low')
            actor: Filter by threat actor
            action: Filter by indicator action (e.g., 'blocked', 'allowed')
            limit: Maximum indicators to return (max: 5000)

        Returns:
            Dict with threat indicators and IOCs (Indicators of Compromise)
        """
        params = {"_limit": min(limit, 5000)}
        if confidence:
            params["confidence"] = confidence
        if actor:
            params["actor"] = actor
        if action:
            params["action"] = action

        return self._request("GET", f"/insights/{insight_id}/indicators", params=params)

    def get_insight_events(
        self,
        insight_id: str,
        threat_level: str | None = None,
        confidence: str | None = None,
        source_ip: str | None = None,
        device_ip: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """
        Get security events associated with an insight.

        Args:
            insight_id: The insight ID
            threat_level: Filter by threat level (e.g., 'critical', 'high', 'medium', 'low')
            confidence: Filter by confidence level
            source_ip: Filter by source IP address
            device_ip: Filter by device IP address
            start_time: Start time for event range (ISO 8601 format)
            end_time: End time for event range (ISO 8601 format)
            limit: Maximum events to return

        Returns:
            Dict with security events linked to the insight
        """
        params = {"_limit": limit}
        if threat_level:
            params["threat_level"] = threat_level
        if confidence:
            params["confidence"] = confidence
        if source_ip:
            params["source_ip"] = source_ip
        if device_ip:
            params["device_ip"] = device_ip
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time

        return self._request("GET", f"/insights/{insight_id}/events", params=params)

    def get_insight_assets(
        self,
        insight_id: str,
        os_version: str | None = None,
        user: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """
        Get affected assets (devices, IPs, MACs) for a security insight.

        Args:
            insight_id: The insight ID
            os_version: Filter by OS version
            user: Filter by username
            start_time: Start time for asset activity (ISO 8601 format)
            end_time: End time for asset activity (ISO 8601 format)
            limit: Maximum assets to return

        Returns:
            Dict with affected assets, threat indicators, and severity per asset
        """
        params = {"_limit": limit}
        if os_version:
            params["os_version"] = os_version
        if user:
            params["user"] = user
        if start_time:
            params["start_time"] = start_time
        if end_time:
            params["end_time"] = end_time

        return self._request("GET", f"/insights/{insight_id}/assets", params=params)

    def get_insight_comments(
        self, insight_id: str, start_date: str | None = None, end_date: str | None = None
    ) -> dict[str, Any]:
        """
        Get historical comments and status changes for an insight.

        Args:
            insight_id: The insight ID
            start_date: Start date for comment range (ISO 8601 format)
            end_date: End date for comment range (ISO 8601 format)

        Returns:
            Dict with comment history and status transitions
        """
        params = {}
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date

        return self._request("GET", f"/insights/{insight_id}/comments", params=params)

    # ============================================================
    # Policy Configuration Insights
    # ============================================================

    def list_analytics_insights(self, status: str | None = None, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """
        List policy analytics insights.

        Args:
            status: Filter by insight status
            limit: Maximum insights to return
            offset: Offset for pagination

        Returns:
            Dict with analytics insights
        """
        params = {"_limit": limit, "_offset": offset}
        if status:
            params["status"] = status

        return self._request("GET", "/config-insights/analytics", params=params)

    def get_analytics_insight(self, analytic_insight_id: str) -> dict[str, Any]:
        """
        Get specific policy analytics insight details.

        Args:
            analytic_insight_id: The analytics insight ID

        Returns:
            Dict with detailed analytics insight information
        """
        return self._request("GET", f"/config-insights/analytics/{analytic_insight_id}")

    def list_policy_check_insights(
        self, check_type: str | None = None, limit: int = 100, offset: int = 0
    ) -> dict[str, Any]:
        """
        List policy compliance check insights.

        Args:
            check_type: Filter by configuration check type
            limit: Maximum insights to return
            offset: Offset for pagination

        Returns:
            Dict with policy compliance insights
        """
        params = {"_limit": limit, "_offset": offset}
        if check_type:
            params["check_type"] = check_type

        return self._request("GET", "/config-insights/policy-check", params=params)
