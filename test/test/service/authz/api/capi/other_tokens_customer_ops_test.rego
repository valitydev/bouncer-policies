package test.service.authz.api.capi.other_tokens_customer_ops

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

# Customer series of Operations invoked with auth methods other than
# CustomerAccessToken:
#   * SessionToken               - full customer management allowed for users
#                                  holding appropriate roles / ownership.
#   * ApiKeyToken                - full customer management allowed within the
#                                  scope of the api key party.
#   * InvoiceAccessToken         - customer management is outside of scope; only
#                                  invoice-bound operations (CreatePayment,
#                                  GetPayments) are allowed for the bound invoice.
#   * InvoiceTemplateAccessToken - customer operations are entirely outside of
#                                  scope and must be forbidden.
#
# Per-auth-method × per-operation outcomes:
#
# | Operation                 | Session admin | Session default | ApiKey (party) | ApiKey (other) | InvoiceToken | InvoiceTemplateToken |
# |---------------------------|---------------|-----------------|----------------|----------------|--------------|----------------------|
# | CreateCustomer            | allowed       | —               | allowed        | forbidden      | forbidden    | forbidden            |
# | GetCustomerByID           | allowed       | —               | allowed        | forbidden      | forbidden    | forbidden            |
# | DeleteCustomer            | allowed       | forbidden       | allowed        | forbidden      | forbidden    | forbidden            |
# | CreateCustomerAccessToken | allowed       | —               | allowed        | forbidden      | forbidden    | forbidden            |
# | GetCustomerPayments       | allowed       | —               | allowed        | forbidden      | forbidden    | forbidden            |
# | GetCustomerBankCards      | allowed       | —               | allowed        | forbidden      | forbidden    | forbidden            |
# | CreatePayment (customer)  | —             | —               | —              | —              | allowed      | forbidden            |
# | GetPayments  (customer)   | —             | —               | —              | —              | allowed      | —                    |
#
# CreatePayment × customer party id:
#
# | Scenario                                 | Session admin | ApiKey (party=PARTY) | InvoiceToken (party=PARTY) |
# |------------------------------------------|---------------|----------------------|----------------------------|
# | customer.party == invoice.party (PARTY)  | allowed       | allowed              | allowed                    |
# | customer.party == PARTY_2 (foreign)      | forbidden     | forbidden            | forbidden                  |

# --- SessionToken ---

test_session_token_allows_create_customer {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_customer
    ])
}

test_session_token_allows_get_customer_by_id {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ])
}

test_session_token_allows_delete_customer {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_delete_customer,
        context.cubasty_customer
    ])
}

test_session_token_allows_create_customer_access_token {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_customer_access_token,
        context.cubasty_customer
    ])
}

test_session_token_allows_get_customer_payments {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_customer_payments,
        context.cubasty_customer
    ])
}

test_session_token_allows_get_customer_bank_cards {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_get_customer_bank_cards,
        context.cubasty_customer
    ])
}

test_session_token_default_user_forbids_delete_customer {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_capi_delete_customer,
        context.cubasty_customer
    ])
}

# --- ApiKeyToken ---

test_api_key_token_allows_create_customer {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_customer
    ])
}

test_api_key_token_allows_get_customer_by_id {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ])
}

test_api_key_token_allows_delete_customer {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_delete_customer,
        context.cubasty_customer
    ])
}

test_api_key_token_allows_create_customer_access_token {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_customer_access_token,
        context.cubasty_customer
    ])
}

test_api_key_token_allows_get_customer_payments {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_get_customer_payments,
        context.cubasty_customer
    ])
}

test_api_key_token_allows_get_customer_bank_cards {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_get_customer_bank_cards,
        context.cubasty_customer
    ])
}

test_api_key_token_different_party_forbids_create_customer {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_create_customer
    ])
}

test_api_key_token_different_party_forbids_get_customer_by_id {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ])
}

test_api_key_token_different_party_forbids_delete_customer {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_delete_customer,
        context.cubasty_customer
    ])
}

test_api_key_token_different_party_forbids_create_customer_access_token {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_create_customer_access_token,
        context.cubasty_customer
    ])
}

test_api_key_token_different_party_forbids_get_customer_payments {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_get_customer_payments,
        context.cubasty_customer
    ])
}

test_api_key_token_different_party_forbids_get_customer_bank_cards {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_different_party,
        context.op_capi_get_customer_bank_cards,
        context.cubasty_customer
    ])
}

# --- InvoiceAccessToken ---
# Invoice tokens must not grant access to customer management operations.

test_invoice_access_token_forbids_create_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_access_token_forbids_get_customer_by_id {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_access_token_forbids_delete_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_delete_customer,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_access_token_forbids_create_customer_access_token {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_customer_access_token,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_access_token_forbids_get_customer_payments {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_customer_payments,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_access_token_forbids_get_customer_bank_cards {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_customer_bank_cards,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

# Invoice token is allowed to create / list payments for the bound invoice even
# when the operation carries a customer context.

test_invoice_access_token_allows_create_payment_for_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_payment_for_customer,
        context.payproc_invoice,
        context.cubasty_customer
    ])
    not result.forbidden
    result.allowed[_].code == "invoice_access_token_allows_operation"
}

test_invoice_access_token_allows_get_payments_for_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_payments_for_customer,
        context.payproc_invoice
    ])
    not result.forbidden
    result.allowed[_].code == "invoice_access_token_allows_operation"
}

# --- InvoiceTemplateAccessToken ---
# Invoice template tokens must not grant access to any customer operation.

test_invoice_template_access_token_forbids_create_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_template_access_token_valid,
        context.op_capi_create_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_template_access_token_forbids_get_customer_by_id {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_template_access_token_valid,
        context.op_capi_get_customer_by_id,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_template_access_token_forbids_delete_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_template_access_token_valid,
        context.op_capi_delete_customer,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_template_access_token_forbids_create_customer_access_token {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_template_access_token_valid,
        context.op_capi_create_customer_access_token,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_template_access_token_forbids_get_customer_payments {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_template_access_token_valid,
        context.op_capi_get_customer_payments,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_template_access_token_forbids_get_customer_bank_cards {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_template_access_token_valid,
        context.op_capi_get_customer_bank_cards,
        context.cubasty_customer
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

test_invoice_template_access_token_forbids_create_payment_for_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_template_access_token_valid,
        context.op_capi_create_payment_for_customer,
        context.payproc_invoice
    ])
    result.forbidden[_].code == "unknown_auth_method_forbids_operation"
    not result.allowed
}

# --- CreatePayment enforces customer party id ---
# CreatePayment carries a customer context; the discretionary customer access
# requirement must ensure the caller has access to the customer's party,
# independently of the invoice party.

test_session_token_admin_allows_create_payment_matching_customer_party {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_payment_for_customer,
        object.union(context.payproc_invoice, context.cubasty_customer)
    ])
}

test_session_token_admin_forbids_create_payment_foreign_customer_party {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_capi_create_payment_for_customer,
        object.union(context.payproc_invoice, context.cubasty_customer_foreign)
    ])
}

test_api_key_token_allows_create_payment_matching_customer_party {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_payment_for_customer,
        object.union(context.payproc_invoice, context.cubasty_customer)
    ])
}

test_api_key_token_forbids_create_payment_foreign_customer_party {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_payment_for_customer,
        object.union(context.payproc_invoice, context.cubasty_customer_foreign)
    ])
}

test_invoice_access_token_forbids_create_payment_foreign_customer_party {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_payment_for_customer,
        object.union(context.payproc_invoice, context.cubasty_customer_foreign)
    ])
}
