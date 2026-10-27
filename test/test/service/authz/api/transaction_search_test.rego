package test.service.authz.api.transaction_search

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.transaction_search as fixtures

payment_context := util.deepmerge([fixtures.base, fixtures.payment])
withdrawal_context := util.deepmerge([fixtures.base, fixtures.withdrawal])

contexts := [payment_context, withdrawal_context]

test_payment_allowed {
    util.is_allowed with input as payment_context
}

test_withdrawal_allowed {
    util.is_allowed with input as withdrawal_context
}

test_mismatched_transaction_forbidden {
    failures := [ctx | ctx := contexts[_]; not forbidden_transaction(ctx)]
    count(failures) == 0
}

forbidden_transaction(ctx) {
    util.is_forbidden with input as ctx with input.transaction_search.op.transaction.id as "OTHER"
}

test_mismatched_party_forbidden {
    failures := [ctx | ctx := contexts[_]; not forbidden_party(ctx)]
    count(failures) == 0
}

forbidden_party(ctx) {
    result := api.assertions with input as ctx with input.transaction_search.op.party.id as "OTHER"
    result.forbidden[_].code == "transaction_not_found"
}

test_missing_fields_forbidden {
    patches := [
        {"transaction_search": {"op": {}}},
        {"transaction_search": {"op": {"id": "GetTransactionByID", "party": {"id": "PARTY"}}}},
        {"transaction_search": {"op": {"id": "GetTransactionByID", "transaction": {"id": "TRANSACTION"}}}},
        {"payment_processing": {}},
        {"payment_processing": {"payment": {"id": "TRANSACTION"}}},
        {"payment_processing": {"payment": {"party": {"id": "PARTY"}}}},
        {"user": {}},
        {"auth": {}}
    ]
    failures := [patch | patch := patches[_]; not forbidden_patch(payment_context, patch)]
    count(failures) == 0
}

forbidden_patch(ctx, patch) {
    # Replace patched sections entirely instead of recursively merging missing fields back in.
    patched := object.union(object.remove(ctx, object.keys(patch)), patch)
    util.is_forbidden with input as patched
}

test_other_auth_methods_forbidden {
    methods := ["ApiKeyToken", "InvoiceAccessToken", "CustomerAccessToken", "InvoiceTemplateAccessToken", "Unknown"]
    failures := [method | method := methods[_]; not forbidden_method(method)]
    count(failures) == 0
}

forbidden_method(method) {
    util.is_forbidden with input as payment_context with input.auth.method as method
}

test_other_roles_and_owner_forbidden {
    roles := [[], [{"id": "Administrator"}], [{"id": "WalletManager"}], [{"id": "TransactionSearcher", "scope": {"shop": {"id": "SHOP"}}}]]
    failures := [rs | rs := roles[_]; not forbidden_roles(rs)]
    count(failures) == 0
}

forbidden_roles(rs) {
    orgs := [{"id": "ORG", "owner": {"id": "USER"}, "party": {"id": "PARTY"}, "roles": rs}]
    util.is_forbidden with input as payment_context with input.user.orgs as orgs
}

test_foreign_organization_payment_allowed {
    orgs := [{"id": "OTHER_ORG", "party": {"id": "OTHER"}, "roles": [{"id": "TransactionSearcher"}]}]
    util.is_allowed with input as payment_context with input.user.orgs as orgs
}

test_foreign_organization_withdrawal_allowed {
    orgs := [{"id": "OTHER_ORG", "party": {"id": "OTHER"}, "roles": [{"id": "TransactionSearcher"}]}]
    util.is_allowed with input as withdrawal_context with input.user.orgs as orgs
}

test_role_in_another_organization_allowed {
    orgs := [
        {"party": {"id": "PARTY"}, "roles": []},
        {"party": {"id": "OTHER"}, "roles": [{"id": "TransactionSearcher"}]}
    ]
    util.is_allowed with input as payment_context with input.user.orgs as orgs
}

test_foreign_organization_without_role_forbidden {
    orgs := [{"party": {"id": "OTHER"}, "roles": [{"id": "Administrator"}]}]
    util.is_forbidden with input as payment_context with input.user.orgs as orgs
}

test_unknown_operation_forbidden {
    util.is_forbidden with input as payment_context with input.transaction_search.op.id as "Unknown"
}

test_wrong_entity_type_forbidden {
    util.is_forbidden with input as withdrawal_context with input.wallet as [{"type": "Wallet", "id": "TRANSACTION", "party": "PARTY"}]
}

test_missing_withdrawal_forbidden {
    util.is_forbidden with input as withdrawal_context with input.wallet as []
}

test_expired_session_forbidden {
    result := api.assertions with input as payment_context with input.auth.expiration as "2020-01-01T00:00:00Z"
    result.forbidden[_].code == "auth_expired"
}

test_missing_expiration_forbidden {
    util.is_forbidden with input as payment_context with input.auth as {"method": "SessionToken"}
}

test_session_ip_whitelist_applies {
    orgs := [{"party": {"id": "PARTY"}, "roles": [{"id": "TransactionSearcher"}], "allowed_ips": ["192.0.2.1"]}]
    result := api.assertions with input as payment_context with input.user.orgs as orgs with data.service.authz.features.session_ip_whitelist as true
    result.forbidden[_].code == "requester_ip_missing"
}
