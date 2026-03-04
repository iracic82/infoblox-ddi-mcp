"""Tests for resolver functions: resolve_space, resolve_zone, resolve_view, resolve_realm."""

import mcp_intent
from mcp_intent import resolve_realm, resolve_space, resolve_view, resolve_zone

# ── resolve_space ────────────────────────────────────────────────────


class TestResolveSpace:
    def test_client_none(self, monkeypatch):
        monkeypatch.setattr(mcp_intent, "client", None)
        space_id, step, err = resolve_space("prod")
        assert space_id is None
        assert "not initialized" in err

    def test_id_passthrough(self, mock_infoblox_client):
        space_id, step, err = resolve_space("ipam/ip_space/abc123")
        assert space_id == "ipam/ip_space/abc123"
        assert step["status"] == "success"
        assert err == ""

    def test_exact_match(self, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = {"results": [{"id": "ipam/ip_space/123", "name": "prod"}]}
        space_id, step, err = resolve_space("prod")
        assert space_id == "ipam/ip_space/123"
        assert err == ""

    def test_fuzzy_match(self, mock_infoblox_client):
        # Exact returns empty, fuzzy returns one
        mock_infoblox_client.list_ip_spaces.side_effect = [
            {"results": []},
            {"results": [{"id": "ipam/ip_space/456", "name": "production"}]},
        ]
        space_id, step, err = resolve_space("prod")
        assert space_id == "ipam/ip_space/456"

    def test_no_match(self, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.return_value = {"results": []}
        space_id, step, err = resolve_space("nonexistent")
        assert space_id is None
        assert "not found" in err

    def test_api_exception(self, mock_infoblox_client):
        mock_infoblox_client.list_ip_spaces.side_effect = Exception("timeout")
        space_id, step, err = resolve_space("prod")
        assert space_id is None
        assert "timeout" in err


# ── resolve_zone ─────────────────────────────────────────────────────


class TestResolveZone:
    def test_client_none(self, monkeypatch):
        monkeypatch.setattr(mcp_intent, "client", None)
        zone_id, step, err = resolve_zone("example.com")
        assert zone_id is None
        assert "not initialized" in err

    def test_id_passthrough(self, mock_infoblox_client):
        zone_id, step, err = resolve_zone("dns/auth_zone/abc123")
        assert zone_id == "dns/auth_zone/abc123"
        assert err == ""

    def test_exact_match(self, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.return_value = {
            "results": [{"id": "dns/auth_zone/789", "fqdn": "example.com."}]
        }
        zone_id, step, err = resolve_zone("example.com")
        assert zone_id == "dns/auth_zone/789"

    def test_trailing_dot_fallback(self, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.side_effect = [
            {"results": []},
            {"results": [{"id": "dns/auth_zone/999", "fqdn": "example.com."}]},
        ]
        zone_id, step, err = resolve_zone("example.com")
        assert zone_id == "dns/auth_zone/999"

    def test_no_match(self, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.return_value = {"results": []}
        zone_id, step, err = resolve_zone("nope.test")
        assert zone_id is None
        assert "not found" in err

    def test_api_exception(self, mock_infoblox_client):
        mock_infoblox_client.list_auth_zones.side_effect = Exception("conn refused")
        zone_id, step, err = resolve_zone("example.com")
        assert zone_id is None
        assert "conn refused" in err

    def test_with_view_filter(self, mock_infoblox_client):
        """When view is specified, filter zones to matching view."""
        mock_infoblox_client.list_dns_views.return_value = {"results": [{"id": "dns/view/default", "name": "default"}]}
        mock_infoblox_client.list_auth_zones.return_value = {
            "results": [
                {"id": "dns/auth_zone/1", "fqdn": "example.com.", "view": "dns/view/azure"},
                {"id": "dns/auth_zone/2", "fqdn": "example.com.", "view": "dns/view/default"},
            ]
        }
        zone_id, step, err = resolve_zone("example.com", view="default")
        assert zone_id == "dns/auth_zone/2"
        assert err == ""

    def test_with_view_no_match(self, mock_infoblox_client):
        """When view is specified but zone doesn't exist in that view."""
        mock_infoblox_client.list_dns_views.return_value = {"results": [{"id": "dns/view/default", "name": "default"}]}
        mock_infoblox_client.list_auth_zones.return_value = {
            "results": [
                {"id": "dns/auth_zone/1", "fqdn": "example.com.", "view": "dns/view/azure"},
            ]
        }
        zone_id, step, err = resolve_zone("example.com", view="default")
        assert zone_id is None
        assert "not found in view" in err

    def test_multiple_views_no_view_specified(self, mock_infoblox_client):
        """When multiple zones match and no view is specified, return error listing views."""
        mock_infoblox_client.list_auth_zones.return_value = {
            "results": [
                {"id": "dns/auth_zone/1", "fqdn": "example.com.", "view": "dns/view/azure"},
                {"id": "dns/auth_zone/2", "fqdn": "example.com.", "view": "dns/view/default"},
                {"id": "dns/auth_zone/3", "fqdn": "example.com.", "view": "dns/view/aws"},
            ]
        }
        zone_id, step, err = resolve_zone("example.com")
        assert zone_id is None
        assert "3 views" in err
        assert "disambiguate" in err

    def test_single_zone_no_view_specified(self, mock_infoblox_client):
        """When only one zone matches, no view needed — backward compatible."""
        mock_infoblox_client.list_auth_zones.return_value = {
            "results": [{"id": "dns/auth_zone/1", "fqdn": "example.com.", "view": "dns/view/default"}]
        }
        zone_id, step, err = resolve_zone("example.com")
        assert zone_id == "dns/auth_zone/1"
        assert err == ""


# ── resolve_view ────────────────────────────────────────────────────


class TestResolveView:
    def test_client_none(self, monkeypatch):
        monkeypatch.setattr(mcp_intent, "client", None)
        view_id, step, err = resolve_view("default")
        assert view_id is None
        assert "not initialized" in err

    def test_id_passthrough(self, mock_infoblox_client):
        view_id, step, err = resolve_view("dns/view/abc123")
        assert view_id == "dns/view/abc123"
        assert step["status"] == "success"
        assert err == ""

    def test_exact_match(self, mock_infoblox_client):
        mock_infoblox_client.list_dns_views.return_value = {"results": [{"id": "dns/view/default", "name": "default"}]}
        view_id, step, err = resolve_view("default")
        assert view_id == "dns/view/default"
        assert err == ""

    def test_fuzzy_match(self, mock_infoblox_client):
        mock_infoblox_client.list_dns_views.side_effect = [
            {"results": []},
            {"results": [{"id": "dns/view/azure-priv", "name": "Azure.private-2"}]},
        ]
        view_id, step, err = resolve_view("Azure")
        assert view_id == "dns/view/azure-priv"

    def test_no_match(self, mock_infoblox_client):
        mock_infoblox_client.list_dns_views.return_value = {"results": []}
        view_id, step, err = resolve_view("nonexistent")
        assert view_id is None
        assert "not found" in err

    def test_api_exception(self, mock_infoblox_client):
        mock_infoblox_client.list_dns_views.side_effect = Exception("timeout")
        view_id, step, err = resolve_view("default")
        assert view_id is None
        assert "timeout" in err


# ── resolve_realm ────────────────────────────────────────────────────


class TestResolveRealm:
    def test_client_none(self, monkeypatch):
        monkeypatch.setattr(mcp_intent, "client", None)
        realm_id, step, err = resolve_realm("us-west")
        assert realm_id is None
        assert "not initialized" in err

    def test_id_passthrough(self, mock_infoblox_client):
        realm_id, step, err = resolve_realm("federation/realm/abc")
        assert realm_id == "federation/realm/abc"
        assert err == ""

    def test_exact_match(self, mock_infoblox_client):
        mock_infoblox_client.list_federated_realms.return_value = {
            "results": [{"id": "federation/realm/111", "name": "us-west"}]
        }
        realm_id, step, err = resolve_realm("us-west")
        assert realm_id == "federation/realm/111"

    def test_fuzzy_match(self, mock_infoblox_client):
        mock_infoblox_client.list_federated_realms.side_effect = [
            {"results": []},
            {"results": [{"id": "federation/realm/222", "name": "us-west-2"}]},
        ]
        realm_id, step, err = resolve_realm("us-west")
        assert realm_id == "federation/realm/222"

    def test_no_match(self, mock_infoblox_client):
        mock_infoblox_client.list_federated_realms.return_value = {"results": []}
        realm_id, step, err = resolve_realm("nowhere")
        assert realm_id is None
        assert "not found" in err

    def test_api_exception(self, mock_infoblox_client):
        mock_infoblox_client.list_federated_realms.side_effect = Exception("500")
        realm_id, step, err = resolve_realm("us-west")
        assert realm_id is None
        assert "500" in err
