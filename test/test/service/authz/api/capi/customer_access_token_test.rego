package test.service.authz.api.capi.customer_access_token

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_customer_access_token_allows_get_customer_by_id {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_by_id
    ])
    not result.forbidden
    result.allowed[_].code == "customer_access_token_allows_operation"
}

test_customer_access_token_allows_get_customer_payments {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_payments
    ])
    not result.forbidden
    result.allowed[_].code == "customer_access_token_allows_operation"
}

test_customer_access_token_allows_get_customer_bank_cards {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_bank_cards
    ])
    not result.forbidden
    result.allowed[_].code == "customer_access_token_allows_operation"
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
        context.op_capi_delete_customer
    ])
    result.forbidden
    not result.allowed
}

test_customer_access_token_forbids_create_customer_access_token {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_create_customer_access_token
    ])
    result.forbidden
    not result.allowed
}

test_customer_access_token_forbids_mismatched_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid
    ]) with input.capi.op as {
        "id": "GetCustomerByID",
        "customer": {"id": "OTHER_CUSTOMER"},
        "party": {"id": "PARTY"}
    }
    not result.forbidden
    not result.allowed
}

test_customer_access_token_forbids_mismatched_party {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid
    ]) with input.capi.op as {
        "id": "GetCustomerByID",
        "customer": {"id": "CUSTOMER"},
        "party": {"id": "OTHER_PARTY"}
    }
    result.forbidden
    not result.allowed
}
