package test.authz.api.wachter

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_wachter_support_roles {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_support
    ])
}

test_wachter_forbidden_operation_auth_invalid {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.invoice_access_token_valid,
        context.op_wachter_support
    ])
}

test_wachter_support_op_wachter_with_unknown_role {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_with_unknown_role
    ])
}

test_wachter_support_op_wachter_checkout_method_with_another_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_checkout_method_with_another_service
    ])
}

test_wachter_support_op_wachter_unknown_method {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_unknown_method
    ])
}

test_wachter_support_op_wachter_unknown_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_unknown_service
    ])
}

test_wachter_support_op_wachter_without_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.session_token_valid,
        context.op_wachter_without_service
    ])
}
