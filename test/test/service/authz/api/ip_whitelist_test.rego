package test.service.authz.api.ip_whitelist

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

forbidden_code(result, code) {
    result.forbidden[_].code == code
}

# Session token: whitelists of the organizations selected by the party on op
# and by the verified object the operation refers to. All of them apply.

test_session_ip_in_org_whitelist_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
}

test_session_ipv6_in_org_whitelist_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_doc_ipv6,
        context.user_administrator_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
}

test_session_ip_not_in_org_whitelist_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_empty_org_whitelist_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_foreign,
        context.user_administrator_empty_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
}

test_session_whitelist_of_another_org_ignored {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_whitelist_other_org,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
}

test_session_capi_op_party_selects_org {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_create_webhook
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_anapi_op_party_selects_org {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_anapi_reports
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_claimmgmt_op_party_selects_org {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_claimmgmt_createClaim
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_apikeymgmt_op_party_selects_org {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid
    ]) with input.apikeymgmt.op as {"id": "IssueApiKey", "party": {"id": "PARTY"}}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_op_party_of_foreign_org_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_create_webhook
    ]) with input.capi.op.party as {"id": "NOT_MY_PARTY"}
    not forbidden_code(result, "ip_not_whitelisted")
}

test_session_outside_party_does_not_override_inside_party {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ]) with input.capi.op.party as {"id": "PARTY_2"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_orgmgmt_ip_not_whitelisted_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_orgmgmt_switch_context
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_wapi_op_party_selects_org {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id": "ListWithdrawals", "party": "PARTY"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_wapi_inside_wallet_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {
        "id": "CreateWithdrawal",
        "wallet": "WalletId",
        "destination": "DestinationId"
    } with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_without_requester_ip_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "requester_ip_missing"
}

test_session_without_whitelist_and_requester_ip_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
}

test_session_op_without_org_skips_whitelist {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_foreign,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_shortener_shorten_url
    ])
}

test_session_invoice_template_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_invoice_template_by_id,
        context.payproc_invoice_template
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_webhook_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_delete_webhook,
        context.webhooks_webhook
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_customer_party_not_overridden_by_op_party {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ]) with input.capi.op.party as {"id": "NOT_MY_PARTY"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_anapi_report_and_file_party_not_overridden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_anapi_download_file,
        context.reports_report
    ]) with input.anapi.op.party as {"id": "NOT_MY_PARTY"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_apikey_entity_party_not_overridden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_apikeymgmt_get_api_key_1,
        context.api_key_apikey_1
    ]) with input.apikeymgmt.op.party as {"id": "NOT_MY_PARTY"}
    forbidden_code(result, "ip_not_whitelisted")
}

test_session_binapi_op_party_selects_org {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_binapi_lookup_card_info
    ]) with input.binapi.op.party as {"id": "PARTY"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_ignores_party_fragment_whitelist {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_foreign,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ]) with input.party as context.party_foreign_allowed_ips.party
}

# Api key: whitelist from the party context fragment.

test_api_key_ip_in_party_whitelist_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice,
        context.party_allowed_ips
    ])
}

test_api_key_ip_not_in_party_whitelist_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice,
        context.party_foreign_allowed_ips
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_api_key_empty_party_whitelist_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_foreign,
        context.api_key_token_valid,
        context.op_capi_create_invoice,
        context.party_empty_allowed_ips
    ])
}

test_api_key_malformed_entries_skipped {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice,
        context.party_malformed_allowed_ips
    ])
}

test_api_key_only_malformed_entries_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice,
        context.party_only_malformed_allowed_ips
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_api_key_without_party_fragment_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_foreign,
        context.api_key_token_valid,
        context.op_capi_create_invoice
    ])
}

test_api_key_party_context_of_another_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice,
        context.party_allowed_ips
    ]) with input.party.id as "PARTY_2"
    count(result.forbidden) == 1
    result.forbidden[_].code == "party_context_mismatch"
}

test_api_key_party_context_without_id_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice
    ]) with input.party as {"organization": {"id": "ORG", "allowed_ips": ["203.0.113.0/24"]}}
    count(result.forbidden) == 1
    result.forbidden[_].code == "party_context_mismatch"
}

test_api_key_without_requester_ip_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice,
        context.party_foreign_allowed_ips
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "requester_ip_missing"
}

test_api_key_ignores_user_org_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.api_key_token_valid,
        context.op_capi_create_invoice
    ])
    not forbidden_code(result, "ip_not_whitelisted")
}

session_refunds_with_allowed_ips(allowed_ips, ip) = ctx {
    ctx := util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice,
        {"requester": {"ip": ip}},
        {"user": {
            "id": "USER",
            "orgs": [{
                "id": "ORG",
                "owner": {"id": "OWNER"},
                "party": {"id": "PARTY"},
                "roles": [{"id": "Administrator"}],
                "allowed_ips": allowed_ips
            }]
        }}
    ])
}

test_non_string_whitelist_entry_still_forbids {
    result := api.assertions with input as session_refunds_with_allowed_ips(
        ["203.0.113.0/24", 5], "95.217.228.176"
    )
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_ip_not_whitelisted_description {
    result := api.assertions with input as session_refunds_with_allowed_ips(
        ["95.217.228.176"], "95.217.228.177"
    )
    result.forbidden[_].description ==
        "Requester IP address 95.217.228.177 is not whitelisted for organization ORG"
}

# Other auth methods are not checked.

test_invoice_access_token_ignores_ip_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_foreign,
        context.invoice_access_token_valid,
        context.user_administrator_foreign_allowed_ips,
        context.op_capi_get_invoice,
        context.payproc_invoice
    ]) with input.party as context.party_foreign_allowed_ips.party
    not forbidden_code(result, "ip_not_whitelisted")
}
