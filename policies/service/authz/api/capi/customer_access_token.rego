package service.authz.api.capi.customer_access_token

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.capi.op

api_name := "CommonAPI"
access_matrix := data.service.authz.access.api[api_name]

allowed[why] {
    # NOTE
    # Set of allowed universal operations here additionally restricted with
    # `data.service.authz.methods` document.
    op.id == access_matrix.universal.operations[_]
    why := {
        "code": "customer_access_token_allows_universal_operation",
        "description": "Customer access token allows universal operations"
    }
}

allowed[why] {
    customer_matches_token_scope
    why := {
        "code": "customer_access_token_allows_operation",
        "description": "Customer access token allows operation on this customer"
    }
}

customer_matches_token_scope {
    scope := input.auth.scope[_]
    scope.customer.id == op.customer.id
    scope.party.id == op.party.id
}
