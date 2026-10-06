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

test_session_every_org_in_scope_must_whitelist_ip {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_two_orgs_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ]) with input.capi.op.party as {"id": "PARTY_2"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_every_org_in_scope_must_whitelist_ip_mirror {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.user_administrator_two_orgs_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ]) with input.capi.op.party as {"id": "PARTY_2"}
       with input.requester.ip as "203.0.113.5"
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_only_object_org_in_scope_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.user_administrator_two_orgs_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ]) with input.requester.ip as "203.0.113.5"
}

# Owner access matches op party against org id too (see user.is_owner).

test_session_owner_by_org_id_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_shops_for_party
    ]) with input.capi.op.party as {"id": "ORG"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_owner_org_without_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner_org_without_party_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_create_webhook
    ])
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_orgmgmt_owner_by_party_id_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner_foreign_allowed_ips,
        context.session_token_valid,
        context.op_orgmgmt_get_org_member
    ]) with input.orgmgmt.op.organization as {"id": "PARTY"}
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

# Each verified object selects its party on its own.

test_session_wapi_withdrawal_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id": "GetWithdrawal", "withdrawal": "WithdrawalId"}
       with input.wallet as context.wallet_pool_with_withdrawal.wallet
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_wapi_report_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id": "GetReport", "report": "ReportId"}
       with input.wallet as context.wallet_pool_with_report.wallet
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_wapi_webhook_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id": "GetWebhookByID", "webhook": "WebhookId"}
       with input.wallet as context.wallet_pool_with_webhook.wallet
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_wapi_foreign_object_id_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id": "GetWithdrawal", "withdrawal": "AnotherWithdrawalId"}
       with input.wallet as context.wallet_pool_with_withdrawal.wallet
    not forbidden_code(result, "ip_not_whitelisted")
}

test_session_anapi_report_party_not_overridden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_anapi_get_report,
        context.reports_report
    ]) with input.anapi.op.party as {"id": "NOT_MY_PARTY"}
    forbidden_code(result, "ip_not_whitelisted")
}

test_session_anapi_file_party_not_overridden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.reports_report
    ]) with input.anapi.op as {
        "id": "DownloadFile",
        "party": {"id": "NOT_MY_PARTY"},
        "file": {"id": "FILE"}
    }
    forbidden_code(result, "ip_not_whitelisted")
}

test_session_wapi_wallet_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id": "GetWallet", "wallet": "WalletId"}
       with input.wallet as context.wallet_pool_with_wallet.wallet
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_session_wapi_destination_party_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id": "GetDestination", "destination": "DestinationId"}
       with input.wallet as context.wallet_pool_with_destination.wallet
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

# An object that is not the one op refers to does not select its party.

test_session_foreign_invoice_template_id_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_invoice_template_by_id,
        context.payproc_invoice_template
    ]) with input.capi.op.invoice_template.id as "ANOTHER_INVOICE_TEMPLATE"
    not forbidden_code(result, "ip_not_whitelisted")
}

test_session_foreign_webhook_id_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_delete_webhook,
        context.webhooks_webhook
    ]) with input.capi.op.webhook.id as "ANOTHER_WEBHOOK"
    not forbidden_code(result, "ip_not_whitelisted")
}

test_session_foreign_customer_id_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ]) with input.capi.op.customer.id as "ANOTHER_CUSTOMER"
       with input.capi.op.party as {"id": "NOT_MY_PARTY"}
    not forbidden_code(result, "ip_not_whitelisted")
}

test_session_foreign_report_and_file_id_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.reports_report
    ]) with input.anapi.op as {
        "id": "DownloadFile",
        "party": {"id": "NOT_MY_PARTY"},
        "report": {"id": "ANOTHER_REPORT"},
        "file": {"id": "ANOTHER_FILE"}
    }
    not forbidden_code(result, "ip_not_whitelisted")
}

test_session_foreign_api_key_id_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_apikeymgmt_get_api_key_1,
        context.api_key_apikey_1
    ]) with input.apikeymgmt.op.api_key.id as "ANOTHER_APIKEY"
       with input.apikeymgmt.op.party as {"id": "NOT_MY_PARTY"}
    not forbidden_code(result, "ip_not_whitelisted")
}

test_session_foreign_invoice_id_skips_whitelist {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_foreign_allowed_ips,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ]) with input.capi.op.invoice.id as "ANOTHER_INVOICE"
    not forbidden_code(result, "ip_not_whitelisted")
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

test_api_key_malformed_party_context_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice
    ]) with input.party as "PARTY"
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

# Whitelist entry forms: a plain address matches only itself, a range matches
# its whole network.

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

test_plain_ipv4_entry_matches_itself_allowed {
    util.is_allowed with input as session_refunds_with_allowed_ips(
        ["95.217.228.176"], "95.217.228.176"
    )
}

test_plain_ipv4_entry_neighbour_forbidden {
    result := api.assertions with input as session_refunds_with_allowed_ips(
        ["95.217.228.176"], "95.217.228.177"
    )
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_ipv4_cidr_entry_allowed {
    util.is_allowed with input as session_refunds_with_allowed_ips(
        ["95.217.228.0/24"], "95.217.228.177"
    )
}

test_ipv4_cidr_entry_outside_forbidden {
    result := api.assertions with input as session_refunds_with_allowed_ips(
        ["95.217.228.0/24"], "95.217.229.1"
    )
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_plain_ipv6_entry_matches_itself_allowed {
    util.is_allowed with input as session_refunds_with_allowed_ips(
        ["2001:db8::1"], "2001:db8::1"
    )
}

test_plain_ipv6_entry_neighbour_forbidden {
    result := api.assertions with input as session_refunds_with_allowed_ips(
        ["2001:db8::1"], "2001:db8::2"
    )
    count(result.forbidden) == 1
    result.forbidden[_].code == "ip_not_whitelisted"
}

test_ipv6_cidr_entry_allowed {
    util.is_allowed with input as session_refunds_with_allowed_ips(
        ["2001:db8::/32"], "2001:db8::2"
    )
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
