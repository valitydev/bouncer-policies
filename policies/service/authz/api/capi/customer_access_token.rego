package service.authz.api.capi.customer_access_token

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.capi.op
import input.cubasty

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
    scope.party.id == cubasty.customer.party.id
}
