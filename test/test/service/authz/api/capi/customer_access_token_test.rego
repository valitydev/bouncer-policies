package test.service.authz.api.capi.customer_access_token

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_customer_access_token_allows_get_customer_by_id {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ])
    not result.forbidden
    result.allowed[_].code == "customer_access_token_allows_operation"
}

test_customer_access_token_allows_get_customer_payments {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_payments,
        context.cubasty_customer
    ])
    not result.forbidden
    result.allowed[_].code == "customer_access_token_allows_operation"
}

test_customer_access_token_allows_get_customer_bank_cards {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_bank_cards,
        context.cubasty_customer
    ])
    not result.forbidden
    result.allowed[_].code == "customer_access_token_allows_operation"
}

test_customer_access_token_forbids_create_payment {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_create_payment_for_customer,
        context.payproc_invoice
    ])
    result.forbidden
    not result.allowed
}

test_customer_access_token_allows_get_payments {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_payments_for_customer,
        context.payproc_invoice
    ])
    not result.forbidden
    result.allowed[_].code == "customer_access_token_allows_operation_with_customer"
}

test_customer_access_token_forbids_create_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_create_customer
    ])
    result.forbidden
    not result.allowed
}

test_customer_access_token_forbids_delete_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_delete_customer,
        context.cubasty_customer
    ])
    result.forbidden
    not result.allowed
}

test_customer_access_token_forbids_create_customer_access_token {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_create_customer_access_token,
        context.cubasty_customer
    ])
    result.forbidden
    not result.allowed
}

test_customer_access_token_forbids_mismatched_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.cubasty_customer
    ]) with input.capi.op as {
        "id": "GetCustomerByID",
        "customer": {"id": "OTHER_CUSTOMER"},
        "party": {"id": "PARTY"}
    }
    result.forbidden
    not result.allowed
}

test_customer_access_token_forbids_foreign_cubasty_party {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer_foreign
    ])
    result.forbidden
    not result.allowed
}

test_customer_access_token_expired_forbidden {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_expired,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "auth_expired"
}
