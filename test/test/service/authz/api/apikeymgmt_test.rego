package test.service.authz.api.apikeymgmt

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context


test_apikeymgmt_allowed_get_api_key {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_apikeymgmt_get_api_key_1,
        context.api_key_apikey_1
    ])
}

test_apikeymgmt_allowed_get_api_key_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_apikeymgmt_get_api_key_1,
        context.api_key_apikey_1
    ])
}

test_apikeymgmt_forbidden_get_api_key_not_owned {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_apikeymgmt_get_api_key_2,
        context.api_key_apikey_2
    ])
}

test_apikeymgmt_forbidden_get_api_key_insufficient_rights {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_apikeymgmt_get_api_key_1,
        context.api_key_apikey_1
    ])
}

test_apikeymgmt_forbidden_get_api_key_invalid_method {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_apikeymgmt_get_api_key_1,
        context.api_key_apikey_1
    ])
}

test_apikeymgmt_forbidden_get_api_key_missing_context{
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_apikeymgmt_non_existant
    ])
}
