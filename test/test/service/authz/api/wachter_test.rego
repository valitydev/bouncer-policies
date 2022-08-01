package test.authz.api.wachter

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_wachter_allowed_user_administrator_not_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_wachter_checkout
    ])
}

test_wachter_allowed_user_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.user_owner,
        context.session_token_valid,
        context.op_wachter_checkout
    ])
}

test_wachter_allowed_two_roles_with_administrator {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.user_administrator_manager,
        context.session_token_valid,
        context.op_wachter_checkout
    ])
}

test_wachter_forbidden_without_op {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid
    ])
}

test_wachter_forbidden_with_not_allowed_method {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_wachter_unknown_method
    ])
}

test_wachter_forbidden_with_not_allowed_role {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_accountant,
        context.session_token_valid,
        context.op_wachter_checkout
    ])
}

test_wachter_forbidden_with_user_no_roles {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_no_roles,
        context.session_token_valid,
        context.op_wachter_checkout
    ])
}

test_wachter_forbidden_operation_auth_invalid {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.invoice_access_token_valid,
        context.op_wachter_checkout
    ])
}

test_wachter_forbidden_operation_without_party {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_wachter_checkout_without_party
    ])
}

test_wachter_forbidden_unknown_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_wachter_unknown_service
    ])
}

test_wachter_forbidden_without_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_wachter_without_service
    ])
}

test_wachter_forbidden_method_with_another_service {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_wachter_checkout_method_with_another_service
    ])
}
