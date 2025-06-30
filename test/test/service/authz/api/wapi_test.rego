package test.service.authz.api.wapi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_get_residence_apikey_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {"id" : "GetResidence"}
}

test_create_withdrawal_apikey_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {
        "id" : "CreateWithdrawal",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

wapi_public_operation_session_token_ctx = util.deepmerge([
    context.env_default,
    context.requester_default,
    context.user_administrator,
    context.session_token_valid,
    context.op_wapi_empty
])

wapi_public_operation_api_key_token_ctx = util.deepmerge([
    context.env_default,
    context.requester_default,
    context.api_key_token_valid,
    context.op_wapi_empty
])

wapi_public_operation_invalid_token_ctx = util.deepmerge([
    context.env_default,
    context.requester_default,
    context.invoice_access_token_valid,
    context.op_wapi_empty
])

test_get_residence_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetResidence"}
}

test_get_currency_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetCurrency"}
}

test_list_providers_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "ListProviders"}
}

test_get_provider_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetProvider"}
}

test_list_withdrawals_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "ListWithdrawals",
        "party" : "PARTY"
    }
}

test_list_wallets_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "ListWallets",
        "party" : "PARTY"
    }
}

test_list_destinations_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "ListDestinations",
        "party" : "PARTY"
    }
}

test_list_deposits_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "ListDeposits",
        "party" : "PARTY"
    }
}

test_create_withdrawal_with_invalid_auth_method_forbidden {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.api_key_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {
        "id" : "CreateWithdrawal",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

test_create_withdrawal_by_owner_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {
        "id" : "CreateWithdrawal",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

test_create_withdrawal_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWithdrawal",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

test_create_withdrawal_forbidden_with_undefined_op_name {
    util.is_forbidden with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWithdrawal"
    }
    with input.wallet as []
}

test_store_bank_card_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "StoreBankCard"
    }
    util.is_allowed with input as wapi_public_operation_api_key_token_ctx with input.wapi.op as {
        "id" : "StoreBankCard"
    }
}

test_get_bank_card_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetBankCard"
    }
    util.is_allowed with input as wapi_public_operation_api_key_token_ctx with input.wapi.op as {
        "id" : "GetBankCard"
    }
}

test_store_bank_card_forbidden {
    util.is_forbidden with input as wapi_public_operation_invalid_token_ctx with input.wapi.op as {
        "id" : "StoreBankCard"
    }
}

test_get_bank_card_forbidden {
    util.is_forbidden with input as wapi_public_operation_invalid_token_ctx with input.wapi.op as {
        "id" : "GetBankCard"
    }
}

test_create_report_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateReport",
        "party" : "PARTY"
    }
}

test_create_webhook_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWebhook",
        "party" : "PARTY"
    }
}

test_create_destination_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateDestination",
        "party" : "PARTY"
    }
}

test_get_webhooks_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWebhooks",
        "party" : "PARTY"
    }
}

test_get_reports_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetReports",
        "party" : "PARTY"
    }
}

test_get_wallet_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWallet",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_get_wallet_by_external_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWalletByExternalID",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_get_wallet_account_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWalletAccount",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_create_quote_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateQuote",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

test_create_withdrawal_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWithdrawal",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

test_get_destination_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetDestination",
        "destination" : "DestinationId"
    }
    with input.wallet as context.wallet_pool_with_destination.wallet
}

test_get_destination_by_external_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetDestinationByExternalID",
        "destination" : "DestinationId"
    }
    with input.wallet as context.wallet_pool_with_destination.wallet
}

test_get_withdrawal_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWithdrawal",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_get_withdrawal_by_external_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWithdrawalByExternalID",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_poll_withdrawal_events_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "PollWithdrawalEvents",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_get_withdrawal_events_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWithdrawalEvents",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_get_webhook_by_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWebhookByID",
        "webhook" : "WebhookId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_webhook.wallet
    ])
}

test_delete_webhook_by_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "DeleteWebhookByID",
        "webhook" : "WebhookId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_webhook.wallet
    ])
}

test_get_report_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetReport",
        "report" : "ReportId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_report.wallet
    ])
}
