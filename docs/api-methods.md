# Infoblox DDI MCP — Full API Method Coverage

**303 API methods** across 3 service clients, wrapped into **26 intent-level MCP tools**.

---

## DDI Client (243 methods)

### IPAM

| Domain | Methods |
|--------|---------|
| **IP Spaces** | `list_ip_spaces`, `create_ip_space`, `get_ip_space`, `update_ip_space`, `delete_ip_space` |
| **Subnets** | `list_subnets`, `get_subnet`, `create_subnet`, `update_subnet`, `delete_subnet` |
| **Address Blocks** | `list_address_blocks`, `get_address_block`, `create_address_block`, `update_address_block`, `delete_address_block`, `allocate_next_available_subnet`, `allocate_next_available_address_block` |
| **IP Addresses** | `list_addresses`, `get_next_available_ip` |
| **Fixed Addresses** | `create_fixed_address`, `get_fixed_address`, `update_fixed_address`, `delete_fixed_address` |
| **Ranges** | `list_ranges`, `create_range`, `get_range`, `update_range`, `delete_range` |
| **IPAM Hosts** | `list_ipam_hosts`, `create_ipam_host`, `get_ipam_host`, `update_ipam_host`, `delete_ipam_host` |

### DNS

| Domain | Methods |
|--------|---------|
| **DNS Records** | `list_dns_records`, `get_dns_record`, `create_dns_record`, `update_dns_record`, `delete_dns_record`, `create_aaaa_record`, `create_ptr_record`, `create_srv_record`, `create_ns_record`, `create_caa_record`, `create_naptr_record` |
| **Auth Zones** | `list_auth_zones`, `create_auth_zone`, `get_auth_zone`, `update_auth_zone`, `delete_auth_zone` |
| **Forward Zones** | `list_forward_zones`, `create_forward_zone`, `get_forward_zone`, `update_forward_zone`, `delete_forward_zone` |
| **DNS Views** | `list_dns_views`, `get_dns_view`, `create_dns_view`, `update_dns_view`, `delete_dns_view` |
| **RPZ Zones** | `list_rpz_zones`, `create_rpz_zone`, `get_rpz_zone`, `update_rpz_zone`, `delete_rpz_zone` |
| **DNS Delegations** | `list_dns_delegations`, `create_dns_delegation`, `get_dns_delegation`, `update_dns_delegation`, `delete_dns_delegation` |
| **Auth Zones (ops)** | `copy_auth_zone`, `export_trust_anchors`, `delete_dnssec_key`, `import_keyset` |
| **Forward Zones (ops)** | `copy_forward_zone` |
| **DNS Cache** | `flush_dns_cache` |
| **DNSSEC** | `get_dnssec_key_status`, `sign_auth_zone`, `unsign_auth_zone` |
| **RPZ Operations** | `reorder_rpz_zones` |
| **RPZ Rules** | `list_rpz_rules`, `create_rpz_rule`, `get_rpz_rule`, `update_rpz_rule`, `delete_rpz_rule` |
| **DNS Record Ops** | `increment_serial`, `configure_record_protection` |
| **DNS Utilities** | `convert_domain_name`, `convert_rname` |

### DNS Config

| Domain | Methods |
|--------|---------|
| **DNS ACLs** | `list_dns_acls`, `create_dns_acl`, `get_dns_acl`, `update_dns_acl`, `delete_dns_acl` |
| **Auth NSGs** | `list_auth_nsgs`, `create_auth_nsg`, `get_auth_nsg`, `update_auth_nsg`, `delete_auth_nsg` |
| **Forward NSGs** | `list_forward_nsgs`, `create_forward_nsg`, `get_forward_nsg`, `update_forward_nsg`, `delete_forward_nsg` |
| **DNS Servers** | `list_dns_servers`, `create_dns_server`, `get_dns_server`, `update_dns_server`, `delete_dns_server` |
| **DNS Global** | `get_dns_global`, `update_dns_global` |
| **DNS Hosts** | `list_dns_hosts`, `get_dns_host`, `update_dns_host` |
| **DNS Services** | `list_dns_services`, `get_dns_service` |

### DHCP

| Domain | Methods |
|--------|---------|
| **DHCP Hosts** | `list_dhcp_hosts`, `get_dhcp_host`, `update_dhcp_host`, `get_dhcp_host_associations` |
| **DHCP Leases** | `list_dhcp_leases`, `get_dhcp_lease`, `clear_dhcp_lease`, `resend_ddns_update` |
| **HA Groups** | `list_ha_groups`, `create_ha_group`, `get_ha_group`, `update_ha_group`, `delete_ha_group`, `get_linked_ha_groups` |
| **DHCP Servers** | `list_dhcp_servers`, `create_dhcp_server`, `get_dhcp_server`, `update_dhcp_server`, `delete_dhcp_server` |
| **DHCP Global** | `get_dhcp_global`, `update_dhcp_global` |
| **Option Codes** | `list_option_codes`, `create_option_code`, `get_option_code`, `update_option_code`, `delete_option_code` |
| **Option Groups** | `list_option_groups`, `create_option_group`, `get_option_group`, `update_option_group`, `delete_option_group` |
| **Option Spaces** | `list_option_spaces`, `create_option_space`, `get_option_space`, `update_option_space`, `delete_option_space` |
| **DHCP Filters** | `list_dhcp_filters` |
| **Hardware Filters** | `list_hardware_filters`, `create_hardware_filter`, `get_hardware_filter`, `update_hardware_filter`, `delete_hardware_filter` |
| **MAC Address Items** | `list_mac_address_items`, `create_mac_address_item`, `get_mac_address_item`, `update_mac_address_item`, `delete_mac_address_item`, `bulk_create_mac_address_items` |
| **Config Profiles** | `list_config_profiles`, `list_config_profile_subnets`, `link_config_profile`, `delink_config_profile` |
| **Option Filters** | `list_option_filters`, `create_option_filter`, `get_option_filter`, `update_option_filter`, `delete_option_filter` |
| **Hardware** | `list_hardware`, `create_hardware`, `get_hardware`, `update_hardware`, `delete_hardware` |

### Infrastructure

| Domain | Methods |
|--------|---------|
| **On-Prem Hosts** | `list_infra_hosts` |
| **Services** | `list_infra_services` |

### Federation

| Domain | Methods |
|--------|---------|
| **Realms** | `list_federated_realms`, `get_federated_realm`, `create_federated_realm`, `update_federated_realm`, `delete_federated_realm` |
| **Blocks** | `list_federated_blocks`, `get_federated_block`, `create_federated_block`, `update_federated_block`, `delete_federated_block` |
| **Delegations** | `list_delegations`, `get_delegation`, `create_delegation`, `update_delegation`, `delete_delegation` |
| **Overlapping Blocks** | `list_overlapping_blocks`, `get_overlapping_block`, `create_overlapping_block`, `update_overlapping_block`, `delete_overlapping_block` |
| **Reserved Blocks** | `list_reserved_blocks`, `get_reserved_block`, `create_reserved_block`, `update_reserved_block`, `delete_reserved_block` |
| **Forward Delegations** | `list_forward_delegations`, `get_forward_delegation`, `create_forward_delegation`, `update_forward_delegation`, `delete_forward_delegation`, `preview_forward_delegation`, `list_next_available_fld`, `create_next_available_fld` |
| **Next Available** | `allocate_next_available_federated_block`, `allocate_next_available_subnet`, `allocate_next_available_address_block`, `next_appropriate_delegation` |
| **Block Sub-resources** | `list_next_available_overlapping_block`, `create_next_available_overlapping_block`, `list_next_available_reserved_block`, `create_next_available_reserved_block` |
| **Pools** | `list_federated_pools`, `get_federated_pool`, `create_federated_pool`, `update_federated_pool`, `delete_federated_pool`, `list_pool_next_available_block`, `create_pool_next_available_block` |

### DNS Traffic Control (DTC/GSLB)

| Domain | Methods |
|--------|---------|
| **LBDNs** | `list_lbdn`, `create_lbdn`, `get_lbdn`, `update_lbdn`, `delete_lbdn` |
| **Pools** | `list_dtc_pools`, `get_dtc_pool`, `create_dtc_pool`, `update_dtc_pool`, `delete_dtc_pool` |
| **Servers** | `list_dtc_servers`, `get_dtc_server`, `create_dtc_server`, `update_dtc_server`, `delete_dtc_server` |
| **Policies** | `list_dtc_policies`, `get_dtc_policy`, `create_dtc_policy`, `update_dtc_policy`, `delete_dtc_policy` |

---

## Insights Client (10 methods)

| Domain | Methods |
|--------|---------|
| **Security Insights** | `list_insights`, `get_insight`, `update_insight_status`, `get_insight_indicators`, `get_insight_events`, `get_insight_assets`, `get_insight_comments` |
| **Analytics** | `list_analytics_insights`, `get_analytics_insight`, `list_policy_check_insights` |

---

## Security/ATCFW Client (50 methods)

| Domain | Methods |
|--------|---------|
| **Security Policies** | `list_security_policies`, `get_security_policy` |
| **Named Lists** | `list_named_lists`, `create_named_list`, `update_named_list`, `delete_named_list`, `partial_update_named_list_items` |
| **Application Filters** | `list_application_filters`, `create_application_filter`, `get_application_filter`, `update_application_filter`, `delete_application_filter` |
| **Category Filters** | `list_category_filters`, `get_category_filter`, `create_category_filter`, `update_category_filter`, `delete_category_filter` |
| **Content Categories** | `list_content_categories` |
| **Internal Domain Lists** | `list_internal_domain_lists`, `create_internal_domain_list`, `get_internal_domain_list`, `update_internal_domain_list`, `delete_internal_domain_list` |
| **Access Codes** | `list_access_codes`, `create_access_code`, `get_access_code`, `update_access_code`, `delete_access_code` |
| **Security Policy CRUD** | `create_security_policy`, `update_security_policy`, `delete_security_policy` |
| **Security Policy Rules** | `list_security_policy_rules`, `create_security_policy_rule`, `get_security_policy_rule`, `update_security_policy_rule`, `delete_security_policy_rule` |
| **Network Lists** | `list_network_lists`, `create_network_list`, `get_network_list`, `update_network_list`, `delete_network_list`, `partial_update_network_list_items` |
| **Threat Feeds** | `list_threat_feeds`, `create_threat_indicator` |
| **App/Block Approvals** | `list_app_approvals`, `update_app_approvals`, `list_block_approvals`, `update_block_approvals` |
| **PoP Regions & DoH** | `list_pop_regions`, `create_doh_fqdn` |

---

## Summary

| Client | Methods | Covers |
|--------|---------|--------|
| DDI | 243 | IPAM, DNS, DHCP, Infrastructure, Federation, DTC |
| Insights | 10 | SOC Insights, Analytics, Policy Checks |
| Security (ATCFW) | 50 | Policies, Rules, Named Lists, Network Lists, Filters, Approvals, Threat Feeds |
| **Total** | **303** | **→ 26 intent-level MCP tools** |
