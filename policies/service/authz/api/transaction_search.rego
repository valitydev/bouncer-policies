package service.authz.api.transaction_search

import data.service.authz.api.user
import data.service.authz.methods

import input.transaction_search.op
import input.payment_processing
import input.wallet

api_name := "TransactionSearchAPI"
operation_name := "GetTransactionByID"
transaction_id := op.transaction.id
party_id := op.party.id

forbidden[why] {
    not transaction_id
    why := {
        "code": "transaction_id_missing",
        "description": "Transaction identifier is required"
    }
}

forbidden[why] {
    not party_id
    why := {
        "code": "transaction_party_missing",
        "description": "Transaction party identifier is required"
    }
}

forbidden[why] {
    transaction_id
    party_id
    not matching_payment
    not matching_withdrawal
    why := {
        "code": "transaction_not_found",
        "description": "No payment or withdrawal matches the requested transaction and party"
    }
}

forbidden[why] {
    input.auth.method != "SessionToken"
    why := {
        "code": "transaction_search_session_token_required",
        "description": "Transaction search requires a session token"
    }
}

forbidden[why] {
    input.auth.method == "SessionToken"
    not operation_available
    why := {
        "code": "unknown_auth_method_forbids_operation",
        "description": "Operation is not available for the authorization method"
    }
}

forbidden[why] {
    input.auth.method == "SessionToken"
    operation_available
    transaction_id
    party_id
    not transaction_search_role_allowed
    why := {
        "code": "transaction_search_role_required",
        "description": "TransactionSearcher role is required for transaction search"
    }
}

allowed[why] {
    input.auth.method == "SessionToken"
    operation_available
    transaction_id
    party_id
    matching_payment
    transaction_search_role_allowed
    why := {
        "code": "transaction_search_allowed",
        "description": "Session token has TransactionSearcher access to the requested payment"
    }
}

allowed[why] {
    input.auth.method == "SessionToken"
    operation_available
    transaction_id
    party_id
    matching_withdrawal
    transaction_search_role_allowed
    why := {
        "code": "transaction_search_allowed",
        "description": "Session token has TransactionSearcher access to the requested withdrawal"
    }
}

operation_available {
    op.id == operation_name
    methods.permissions[input.auth.method].apis[api_name].operations[_] == operation_name
}

transaction_search_role_allowed {
    # This dedicated role grants cross-party access, regardless of its organization.
    role := input.user.orgs[_].roles[_]
    role.id == "TransactionSearcher"
    not role.scope
    user.operations_by_role(api_name, role)[_] == operation_name
}

matching_payment {
    payment := payment_processing.payment
    payment.id == transaction_id
    payment.party.id == party_id
}

matching_withdrawal {
    entity := wallet[_]
    entity.type == "Withdrawal"
    entity.id == transaction_id
    entity.party == party_id
}
