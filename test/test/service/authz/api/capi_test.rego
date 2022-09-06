package test.service.authz.api.capi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_get_refunds_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_refunds,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "org_role_allows_operation"
}

test_fulfill_invoice_forbidden_context_mismatch {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_capi_fulfill_invoice,
        context.payproc_invoice_another_shop
    ])
}

test_forbidden_create_payment_resource {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_capi_create_payment_resource
    ])
    result.forbidden
}

test_forbidden_invoicing_context_no_shop {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_fulfill_invoice,
        context.payproc_invoice_no_shop_context
    ])
}

test_forbidden_invoicing_context_no_party {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_fulfill_invoice,
        context.payproc_invoice_no_party_context
    ])
}

test_create_invoice_access_token_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_invoice_access_token,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_insufficient_input_forbidden {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_refund_by_id,
        context.payproc_insufficient_input
    ])
}

test_op_insufficient_input_forbidden {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_payment_insufficient_input,
        context.payproc_invoice
    ])
}

test_get_refund_by_id_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_refund_by_id,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_rescind_invoice_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_capi_rescind_invoice,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

capi_public_operation_session_token_ctx = util.deepmerge([
    context.env_default,
    context.requester_default,
    context.user_default,
    context.session_token_valid,
    context.op_capi_empty
])

test_get_categories_allowed_by_session_token {
    result := api.assertions with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetCategories"}
    not result.forbidden
    count(result.allowed) == 1
}

test_get_countries_allowed_by_session_token {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetCountries"}
}

test_get_tradeblocs_allowed_by_session_token {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetTradeBlocs"}
}

test_get_service_provider_allowed_by_session_token {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetServiceProviderByID"}
}

test_capi_allowed_by_session_token_3 {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetCategoryByRef"}
}

test_capi_allowed_by_session_token_5 {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutions"}
}

test_capi_allowed_by_session_token_6 {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionByRef"}
}

test_capi_allowed_by_session_token_7 {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPaymentTerms"}
}

test_capi_allowed_by_session_token_8 {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutMethods"}
}

test_capi_allowed_by_session_token_9 {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutSchedules"}
}

test_capi_allowed_by_session_token_10 {
    util.is_allowed with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "GetScheduleByRef"}
}

test_update_invoice_template_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_update_invoice_template,
        context.payproc_invoice_template
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_create_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_binding,
        context.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_get_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_binding,
        context.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_session_token_and_owner_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_capi_get_binding,
        context.payproc_customer
    ])
}

test_create_webhook_allowed {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_webhook
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_search_invoices_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_search_invoices
    ])
}

test_search_specific_invoice_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_search_specific_invoice,
        context.payproc_invoice
    ])
}

test_search_specific_payout_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_shop,
        context.session_token_valid,
        context.op_capi_search_specific_payout,
        context.payouts_payout
    ])
}

test_search_foreign_invoice_forbidden {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_search_specific_invoice,
        context.payproc_invoice_foreign
    ])
}

test_search_another_party_invoice_allowed_owner_another_party {
    # NOTE
    # This is kinda unusual: search within `PARTY` for specific invoice owned by
    # `PARTY_2`. It's **allowed** because the user has, independently, an access
    # to searches within `PARTY` **and** an access to invoice owned by `PARTY_2`,
    # even though such request as a whole doesn't make sense.
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_owner_another_party,
        context.session_token_valid,
        context.op_capi_search_specific_invoice,
        context.payproc_invoice_foreign
    ])
}

test_search_another_party_invoice_forbidden_manager_another_party {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_manager_another_party,
        context.session_token_valid,
        context.op_capi_search_specific_invoice,
        context.payproc_invoice_foreign
    ])
}

test_delete_webhook_allowed_administrator {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_delete_webhook,
        context.webhooks_webhook
    ])
}

test_delete_webhook_allowed_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator_owner_another_party,
        context.session_token_valid,
        context.op_capi_delete_webhook,
        context.webhooks_webhook_foreign
    ])
}

test_delete_foreign_webhook_forbidden {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_delete_webhook,
        context.webhooks_webhook_foreign
    ])
}

test_delete_webhook_forbidden_default_user {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_capi_delete_webhook,
        context.webhooks_webhook
    ])
}

test_unknown_operation_forbidden_no_access {
    util.is_forbidden with input as capi_public_operation_session_token_ctx with input.capi.op as {"id" : "NewOperation"}
}

test_create_invoice_with_api_token {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_invoice
    ])
}

test_create_invoice_with_different_api_token {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_create_invoice
    ])
}

test_create_webhook_allowed_with_api_token {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_webhook
    ])
}

test_create_webhook_forbidden_with_api_token {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_create_webhook
    ])
}

test_forbid_no_api_token_scope {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_no_scope,
        context.op_capi_create_invoice
    ])
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_no_scope,
        context.op_capi_create_webhook
    ])
}

test_forbidden_create_payment_resource_with_api_key {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_payment_resource
    ])
}

capi_public_operation_api_token_ctx = util.deepmerge([
    context.env_default,
    context.requester_default,
    context.api_key_token_valid,
    context.op_capi_empty
])

test_get_categories_allowed_by_api_token {
    result := api.assertions with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetCategories"}
    not result.forbidden
    count(result.allowed) == 1
}

test_get_countries_allowed_by_api_token {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetCountries"}
}

test_get_tradeblocs_allowed_by_api_token {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetTradeBlocs"}
}

test_get_service_providers_allowed_by_api_token {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetServiceProviderByID"}
}

test_capi_allowed_by_api_token_3 {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetCategoryByRef"}
}

test_capi_allowed_by_api_token_5 {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutions"}
}

test_capi_allowed_by_api_token_6 {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionByRef"}
}

test_capi_allowed_by_api_token_7 {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPaymentTerms"}
}

test_capi_allowed_by_api_token_8 {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutMethods"}
}

test_capi_allowed_by_api_token_9 {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutSchedules"}
}

test_capi_allowed_by_api_token_10 {
    util.is_allowed with input as capi_public_operation_api_token_ctx with input.capi.op as {"id" : "GetScheduleByRef"}
}
