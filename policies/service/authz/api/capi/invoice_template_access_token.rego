package service.authz.api.capi.invoice_template_access_token

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.capi.op
import input.payment_processing

api_name := "CommonAPI"
access_matrix := data.service.authz.access.api[api_name]

allowed[why] {
    # NOTE
    # Set of allowed universal operations here additionally restricted with
    # `data.service.authz.methods` document.
    op.id == access_matrix.universal.operations[_]
    why := {
        "code": "invoice_template_access_token_allows_universal_operation",
        "description": "Invoice template access token allows universal operations"
    }
}

allowed[why] {
    invoice_template_matches_token_scope
    why := {
        "code": "invoice_template_access_token_allows_operation",
        "description": "Invoice template access token allows operation on this invoice template"
    }
}

invoice_template_matches_token_scope {
    scope := input.auth.scope[_]
    scope.invoice_template.id == op.invoice_template.id
    scope.party.id == payment_processing.invoice_template.party.id
}
