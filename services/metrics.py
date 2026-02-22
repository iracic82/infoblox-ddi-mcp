"""
Centralized Metrics Collection for Infoblox MCP Server

Provides lightweight metrics collection without external dependencies.
Metrics are collected in-memory and can be exposed via HTTP endpoint.
"""

import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class MetricsCollector:
    """Thread-safe metrics collector for MCP server"""

    def __init__(self):
        self._lock = threading.Lock()

        # Counters
        self.api_calls = defaultdict(int)  # {(service, endpoint, status): count}
        self.cache_hits = defaultdict(int)  # {(service, method): count}
        self.cache_misses = defaultdict(int)  # {(service, method): count}
        self.circuit_breaker_opens = defaultdict(int)  # {service: count}
        self.errors = defaultdict(int)  # {(service, error_type): count}

        # Latency tracking (keep last 1000 measurements per endpoint)
        self.latencies = defaultdict(lambda: deque(maxlen=1000))  # {(service, endpoint): [durations]}

        # Circuit breaker state
        self.circuit_states = {}  # {service: state}

        # Start time
        self.start_time = time.time()

        logger.info("metrics_collector_initialized")

    def record_api_call(
        self, service: str, endpoint: str, duration_ms: float, status_code: int, error: str | None = None
    ):
        """Record an API call with latency"""
        with self._lock:
            # Count by status
            key = (service, endpoint, status_code)
            self.api_calls[key] += 1

            # Track latency
            latency_key = (service, endpoint)
            self.latencies[latency_key].append(duration_ms)

            # Track errors
            if error:
                error_key = (service, error)
                self.errors[error_key] += 1

        # Log for observability
        logger.debug(
            "api_call_recorded",
            service=service,
            endpoint=endpoint,
            duration_ms=round(duration_ms, 2),
            status_code=status_code,
            error=error,
        )

    def record_cache_hit(self, service: str, method: str):
        """Record a cache hit"""
        with self._lock:
            key = (service, method)
            self.cache_hits[key] += 1

    def record_cache_miss(self, service: str, method: str):
        """Record a cache miss"""
        with self._lock:
            key = (service, method)
            self.cache_misses[key] += 1

    def record_circuit_breaker_open(self, service: str):
        """Record circuit breaker opening"""
        with self._lock:
            self.circuit_breaker_opens[service] += 1

        logger.warning("circuit_breaker_opened", service=service, total_opens=self.circuit_breaker_opens[service])

    def set_circuit_state(self, service: str, state: str):
        """Update circuit breaker state"""
        with self._lock:
            self.circuit_states[service] = {"state": state, "updated_at": datetime.utcnow().isoformat()}

    def get_metrics(self) -> dict[str, Any]:
        """Get current metrics snapshot"""
        with self._lock:
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "uptime_seconds": int(time.time() - self.start_time),
                "api_calls": self._get_api_call_metrics(),
                "cache": self._get_cache_metrics(),
                "latency": self._get_latency_metrics(),
                "circuit_breakers": dict(self.circuit_states),
                "errors": self._get_error_metrics(),
            }

    def _get_api_call_metrics(self) -> dict[str, Any]:
        """Calculate API call metrics"""
        total_calls = sum(self.api_calls.values())

        # Group by service
        by_service = defaultdict(lambda: {"total": 0, "by_status": {}})
        for (service, _endpoint, status), count in self.api_calls.items():
            by_service[service]["total"] += count
            if status not in by_service[service]["by_status"]:
                by_service[service]["by_status"][status] = 0
            by_service[service]["by_status"][status] += count

        return {"total": total_calls, "by_service": dict(by_service)}

    def _get_cache_metrics(self) -> dict[str, Any]:
        """Calculate cache metrics"""
        total_hits = sum(self.cache_hits.values())
        total_misses = sum(self.cache_misses.values())
        total_requests = total_hits + total_misses

        hit_rate = (total_hits / total_requests * 100) if total_requests > 0 else 0

        # By service/method
        by_method = {}
        all_keys = set(self.cache_hits.keys()) | set(self.cache_misses.keys())
        for key in all_keys:
            hits = self.cache_hits.get(key, 0)
            misses = self.cache_misses.get(key, 0)
            total = hits + misses
            method_hit_rate = (hits / total * 100) if total > 0 else 0

            by_method[f"{key[0]}.{key[1]}"] = {
                "hits": hits,
                "misses": misses,
                "hit_rate_percent": round(method_hit_rate, 2),
            }

        return {
            "total_hits": total_hits,
            "total_misses": total_misses,
            "hit_rate_percent": round(hit_rate, 2),
            "by_method": by_method,
        }

    def _get_latency_metrics(self) -> dict[str, Any]:
        """Calculate latency percentiles"""
        latency_stats = {}

        for (service, endpoint), durations in self.latencies.items():
            if not durations:
                continue

            sorted_durations = sorted(durations)
            count = len(sorted_durations)

            latency_stats[f"{service}/{endpoint}"] = {
                "count": count,
                "min_ms": round(sorted_durations[0], 2),
                "max_ms": round(sorted_durations[-1], 2),
                "p50_ms": round(sorted_durations[int(count * 0.50)], 2),
                "p95_ms": round(sorted_durations[int(count * 0.95)], 2),
                "p99_ms": round(sorted_durations[int(count * 0.99)], 2),
                "avg_ms": round(sum(sorted_durations) / count, 2),
            }

        return latency_stats

    def _get_error_metrics(self) -> dict[str, Any]:
        """Calculate error metrics"""
        total_errors = sum(self.errors.values())

        by_type = {}
        for (service, error_type), count in self.errors.items():
            key = f"{service}/{error_type}"
            by_type[key] = count

        return {"total": total_errors, "by_type": by_type}

    def get_summary(self) -> str:
        """Get human-readable summary"""
        metrics = self.get_metrics()

        lines = [
            "=" * 70,
            "INFOBLOX MCP SERVER - METRICS SUMMARY",
            "=" * 70,
            f"Uptime: {metrics['uptime_seconds']}s",
            "",
            "API Calls:",
            f"  Total: {metrics['api_calls']['total']}",
        ]

        for service, data in metrics["api_calls"]["by_service"].items():
            lines.append(f"  {service}: {data['total']} calls")
            for status, count in data["by_status"].items():
                lines.append(f"    - {status}: {count}")

        lines.extend(
            [
                "",
                "Cache Performance:",
                f"  Hit Rate: {metrics['cache']['hit_rate_percent']:.1f}%",
                f"  Hits: {metrics['cache']['total_hits']}",
                f"  Misses: {metrics['cache']['total_misses']}",
            ]
        )

        if metrics["latency"]:
            lines.extend(["", "Latency (ms):"])
            for endpoint, stats in metrics["latency"].items():
                lines.append(f"  {endpoint}:")
                lines.append(f"    p50: {stats['p50_ms']}ms, p95: {stats['p95_ms']}ms, p99: {stats['p99_ms']}ms")

        if metrics["circuit_breakers"]:
            lines.extend(["", "Circuit Breakers:"])
            for service, state in metrics["circuit_breakers"].items():
                lines.append(f"  {service}: {state['state']}")

        if metrics["errors"]["total"] > 0:
            lines.extend(["", f"Errors: {metrics['errors']['total']} total"])

        lines.append("=" * 70)

        return "\n".join(lines)


# Global singleton instance
_metrics_collector: MetricsCollector | None = None
_lock = threading.Lock()


def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector"""
    global _metrics_collector

    if _metrics_collector is None:
        with _lock:
            if _metrics_collector is None:
                _metrics_collector = MetricsCollector()

    return _metrics_collector


# Convenience functions
def record_api_call(service: str, endpoint: str, duration_ms: float, status_code: int, error: str | None = None):
    """Record an API call"""
    get_metrics_collector().record_api_call(service, endpoint, duration_ms, status_code, error)


def record_cache_hit(service: str, method: str):
    """Record a cache hit"""
    get_metrics_collector().record_cache_hit(service, method)


def record_cache_miss(service: str, method: str):
    """Record a cache miss"""
    get_metrics_collector().record_cache_miss(service, method)


def record_circuit_breaker_open(service: str):
    """Record circuit breaker opening"""
    get_metrics_collector().record_circuit_breaker_open(service)


def set_circuit_state(service: str, state: str):
    """Update circuit breaker state"""
    get_metrics_collector().set_circuit_state(service, state)


def get_metrics() -> dict[str, Any]:
    """Get current metrics"""
    return get_metrics_collector().get_metrics()


def get_summary() -> str:
    """Get metrics summary"""
    return get_metrics_collector().get_summary()
