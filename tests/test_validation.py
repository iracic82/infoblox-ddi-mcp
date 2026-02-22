"""Tests for input-validation and sanitisation helpers (~25 tests)."""

from mcp_intent import (
    sanitize_filter,
    validate_action,
    validate_cidr,
    validate_fqdn,
    validate_ip,
    validate_mac,
    validate_resource_type,
)

# ── sanitize_filter ──────────────────────────────────────────────────


class TestSanitizeFilter:
    def test_passthrough_safe_string(self):
        assert sanitize_filter("prod-space") == "prod-space"

    def test_escapes_double_quotes(self):
        assert sanitize_filter('foo"bar') == 'foo\\"bar'

    def test_escapes_backslash(self):
        assert sanitize_filter("foo\\bar") == "foo\\\\bar"

    def test_escapes_both(self):
        assert sanitize_filter('a\\"b') == 'a\\\\\\"b'

    def test_empty_string(self):
        assert sanitize_filter("") == ""


# ── validate_action ──────────────────────────────────────────────────


class TestValidateAction:
    def test_valid_action(self):
        ok, msg = validate_action("create", ["create", "delete"])
        assert ok is True
        assert msg == ""

    def test_invalid_action(self):
        ok, msg = validate_action("drop", ["create", "delete"])
        assert ok is False
        assert "Invalid action" in msg
        assert "drop" in msg

    def test_case_sensitive(self):
        ok, _ = validate_action("Create", ["create"])
        assert ok is False


# ── validate_resource_type ───────────────────────────────────────────


class TestValidateResourceType:
    def test_valid_type(self):
        ok, msg = validate_resource_type("subnet", ["subnet", "range"])
        assert ok is True

    def test_invalid_type(self):
        ok, msg = validate_resource_type("vlan", ["subnet", "range"])
        assert ok is False
        assert "vlan" in msg


# ── validate_cidr ────────────────────────────────────────────────────


class TestValidateCidr:
    def test_valid_ipv4(self):
        ok, _ = validate_cidr("10.0.0.0/24")
        assert ok is True

    def test_valid_ipv6(self):
        ok, _ = validate_cidr("2001:db8::/32")
        assert ok is True

    def test_host_bits_set_strict_false(self):
        """strict=False means 10.0.0.5/24 is accepted (normalises to 10.0.0.0/24)."""
        ok, _ = validate_cidr("10.0.0.5/24")
        assert ok is True

    def test_invalid_string(self):
        ok, msg = validate_cidr("not-a-cidr")
        assert ok is False
        assert "Invalid CIDR" in msg

    def test_bare_ip_is_valid_as_host_route(self):
        """ipaddress.ip_network('10.0.0.0', strict=False) → 10.0.0.0/32"""
        ok, _ = validate_cidr("10.0.0.0")
        assert ok is True

    def test_garbage_string(self):
        ok, msg = validate_cidr("hello world")
        assert ok is False


# ── validate_ip ──────────────────────────────────────────────────────


class TestValidateIp:
    def test_valid_ipv4(self):
        ok, _ = validate_ip("192.168.1.1")
        assert ok is True

    def test_valid_ipv6(self):
        ok, _ = validate_ip("::1")
        assert ok is True

    def test_invalid(self):
        ok, msg = validate_ip("999.999.999.999")
        assert ok is False
        assert "Invalid IP" in msg


# ── validate_mac ─────────────────────────────────────────────────────


class TestValidateMac:
    def test_colon_separated(self):
        ok, _ = validate_mac("AA:BB:CC:DD:EE:FF")
        assert ok is True

    def test_dash_separated(self):
        ok, _ = validate_mac("aa-bb-cc-dd-ee-ff")
        assert ok is True

    def test_invalid(self):
        ok, msg = validate_mac("not-a-mac")
        assert ok is False
        assert "Invalid MAC" in msg

    def test_too_short(self):
        ok, _ = validate_mac("AA:BB:CC")
        assert ok is False


# ── validate_fqdn ───────────────────────────────────────────────────


class TestValidateFqdn:
    def test_valid_domain(self):
        ok, _ = validate_fqdn("host.example.com")
        assert ok is True

    def test_trailing_dot(self):
        ok, _ = validate_fqdn("host.example.com.")
        assert ok is True

    def test_too_long(self):
        long_name = "a" * 254 + ".com"
        ok, msg = validate_fqdn(long_name)
        assert ok is False

    def test_invalid_chars(self):
        ok, msg = validate_fqdn("host!.example.com")
        assert ok is False
        assert "Invalid FQDN" in msg
