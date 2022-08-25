package test.authz.api.wachter

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_wachter_allowed_create_deposit {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_create_deposit,
        context.auth_resource_access_techsuppoort
    ])
}

test_wachter_forbidden_operation_auth_invalid {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.invoice_access_token_valid,
        context.op_wachter_create_deposit,
        context.auth_resource_access_techsuppoort
    ])
}

test_wachter_forbidden_resource_access_with_unknown_role {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_create_claim,
        context.auth_resource_access_with_unknown_role
    ])
}

test_wachter_support_op_wachter_checkout_method_with_repairer_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_checkout_method_with_repairer_service,
        context.auth_resource_access_techsuppoort
    ])
}

test_wachter_support_op_wachter_unknown_method {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_unknown_method,
        context.auth_resource_access_techsuppoort
    ])
}

test_wachter_support_op_wachter_unknown_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_unknown_service,
        context.auth_resource_access_techsuppoort
    ])
}

test_wachter_support_op_wachter_without_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_without_service,
        context.auth_resource_access_techsuppoort
    ])
}
