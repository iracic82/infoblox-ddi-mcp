"""
Infoblox SOC Insights API Client

This client provides access to the Infoblox Security Operations Center (SOC) Insights API
for threat intelligence, security event monitoring, and policy compliance.

API Documentation: https://csp.infoblox.com/apidoc/docs/Insights
"""

import os
from typing import Any

import requests
import structlog

# Initialize structured logger
logger = structlog.get_logger(__name__)


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

        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Token {self.api_key}", "Content-Type": "application/json"})

        # Set timeout for all requests (connect timeout, read timeout)
        self.timeout = (5, 30)

        logger.info(
            "insights_client_initialized",
            base_url=self.base_url,
            timeout_connect=self.timeout[0],
            timeout_read=self.timeout[1],
        )

    def _request(self, method: str, endpoint: str, **kwargs) -> dict[str, Any]:
        """Make an HTTP request to the Insights API."""
        url = f"{self.base_url}/api/insights/v1{endpoint}"

        # Add timeout if not already specified
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.timeout

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            return {"error": str(e), "status_code": getattr(e.response, "status_code", None)}

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
