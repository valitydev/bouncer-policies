package service.authz.api.capi.invoice_access_token

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
        "code": "invoice_access_token_allows_universal_operation",
        "description": "Invoice access token allows universal operations"
    }
}

allowed[why] {
    op.id == "CreatePaymentResource"
    party_matches_token_scope
    why := {
        "code": "invoice_access_token_allows_tokenization",
        "description": "Invoice access token allows payment resource tokenization"
    }
}

allowed[why] {
    op.id != "CreatePaymentResource"
    invoice_matches_token_scope
    why := {
        "code": "invoice_access_token_allows_operation",
        "description": "Invoice access token allows operation on this invoice"
    }
}

party_matches_token_scope {
    scope := input.auth.scope[_]
    scope.party.id == op.party.id
}

invoice_matches_token_scope {
    scope := input.auth.scope[_]
    scope.invoice.id == op.invoice.id
    scope.party.id == payment_processing.invoice.party.id
}
