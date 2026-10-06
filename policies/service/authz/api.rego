package service.authz.api

import data.service.authz.api.invoice_access_token
import data.service.authz.api.url_shortener
import data.service.authz.api.binapi
import data.service.authz.api.anapi
import data.service.authz.api.capi
import data.service.authz.api.orgmgmt
import data.service.authz.api.wapi
import data.service.authz.api.claimmgmt
import data.service.authz.api.apikeymgmt
import data.service.authz.blacklists
import data.service.authz.whitelists
import data.service.authz.roles
import data.service.authz.org
import data.service.authz.judgement
import data.service.authz.methods

assertions = a {
    a0 := {
        "forbidden" : { why | forbidden[why] },
        "allowed"   : { why | allowed[why] },
        "restrictions": { what.type: what.restrictions[what.type] | restrictions[what] }
    }
    a := { name: values | values := a0[name]; count(values) > 0 }
}

judgement := judgement.judge(assertions)

# Set of assertions which tell why operation under the input context is forbidden.
# When the set is empty operation is not explicitly forbidden.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```
forbidden[why] {
    input
    not input.auth.method
    why := {
        "code": "auth_required",
        "description": "Authorization is required"
    }
}

forbidden[why] {
    not known_auth_method
    why := {
        "code": "unknown_auth_method",
        "description": "Authorization method is unknown"
    }
}

forbidden[why] {
    not tolerate_no_expiration
    not input.auth.expiration
    why := {
        "code": "auth_no_token_expiration",
        "description": "Tokens without expiration are not allowed"
    }
}

forbidden[why] {
    not tolerate_expired_token
    exp := time.parse_rfc3339_ns(input.auth.expiration)
    now := time.parse_rfc3339_ns(input.env.now)
    now > exp
    why := {
        "code": "auth_expired",
        "description": sprintf("Authorization expired at: %s", [input.auth.expiration])
    }
}

forbidden[why] {
    ip := input.requester.ip
    blacklist := blacklists.source_ip_range.entries
    matches := net.cidr_contains_matches(blacklist, ip)
    matches[_]
    ranges := [ range | matches[_][0] = i; range := blacklist[i] ]
    why := {
        "code": "ip_range_blacklisted",
        "description": sprintf(
            "Requester IP address is blacklisted with ranges: %v",
            [concat(", ", ranges)]
        )
    }
}

# IP whitelist. Only SessionToken and ApiKeyToken are checked.
# A missing or empty allowed_ips means the whitelist is not configured.
# Entries are IP addresses or CIDR ranges. Malformed entries are skipped.
forbidden[why] {
    whitelist := ip_whitelists[_]
    not input.requester.ip
    why := {
        "code": "requester_ip_missing",
        "description": sprintf(
            "Requester IP address is required by whitelist for %s",
            [whitelist.subject]
        )
    }
}

forbidden[why] {
    whitelist := ip_whitelists[_]
    input.requester.ip
    not requester_ip_whitelisted(whitelist.ranges)
    why := {
        "code": "ip_not_whitelisted",
        "description": sprintf(
            "Requester IP address %s is not whitelisted for %s",
            [input.requester.ip, whitelist.subject]
        )
    }
}

ip_whitelists[whitelist] {
    input.auth.method == "SessionToken"
    org := session_orgs_in_scope[_]
    count(org.allowed_ips) > 0
    whitelist := {
        "subject": sprintf("organization %s", [object.get(org, "id", "undefined")]),
        "ranges": org.allowed_ips
    }
}

forbidden[why] {
    input.auth.method == "ApiKeyToken"
    party_id := object.get(input.party, "id", "undefined")
    not api_key_party_in_scope(party_id)
    why := {
        "code": "party_context_mismatch",
        "description": sprintf(
            "Party context %s does not match api key scope",
            [party_id]
        )
    }
}

api_key_party_in_scope(party_id) {
    input.auth.scope[_].party.id == party_id
}

# Party context is provided only for a party that belongs to an organization.
# A party without an organization has no whitelist to apply.
ip_whitelists[whitelist] {
    input.auth.method == "ApiKeyToken"
    api_key_party_in_scope(input.party.id)
    ranges := input.party.organization.allowed_ips
    count(ranges) > 0
    whitelist := {
        "subject": sprintf("party %s", [object.get(input.party, "id", "undefined")]),
        "ranges": ranges
    }
}

forbidden[why] {
    input.anapi
    anapi.forbidden[why]
}

forbidden[why] {
    input.capi
    capi.forbidden[why]
}

forbidden[why] {
    input.orgmgmt
    orgmgmt.forbidden[why]
}

forbidden[why] {
    input.wapi
    wapi.forbidden[why]
}

forbidden[why] {
    input.claimmgmt
    claimmgmt.forbidden[why]
}

forbidden[why] {
    input.apikeymgmt
    apikeymgmt.forbidden[why]
}

known_auth_method {
    methods.methods[_] == input.auth.method
}

tolerate_no_expiration {
    input.auth.method == "ApiKeyToken"
}

tolerate_no_expiration {
    # Invoice template access tokens currently have unlimited(undefined) expiration
    input.auth.method == "InvoiceTemplateAccessToken"
}

tolerate_expired_token {
    input.capi
    input.auth.method == "SessionToken"
}

tolerate_expired_token {
    input.anapi
    input.auth.method == "SessionToken"
}

tolerate_expired_token {
    input.wapi
    input.auth.method == "SessionToken"
}

# Organizations the session request is scoped to: the party named in op and the
# party of the verified object op refers to. Every one of them is checked, so a
# forged op party can only add a whitelist, never replace the object's one.
# Org management names the organization itself.
session_orgs_in_scope[org] {
    org := input.user.orgs[_]
    org_in_request_scope(org)
}

org_in_request_scope(org) {
    org.party.id == request_party_ids[_]
}

org_in_request_scope(org) {
    org.id == request_org_ids[_]
}

request_org_ids[id] {
    id := input.orgmgmt.op.organization.id
}

request_party_ids[id] {
    id := input.capi.op.party.id
}

request_party_ids[id] {
    id := input.anapi.op.party.id
}

request_party_ids[id] {
    id := input.claimmgmt.op.party.id
}

request_party_ids[id] {
    id := input.apikeymgmt.op.party.id
}

request_party_ids[id] {
    id := input.binapi.op.party.id
}

request_party_ids[id] {
    id := input.wapi.op.party
}

request_party_ids[id] {
    invoice := input.payment_processing.invoice
    invoice.id == input.capi.op.invoice.id
    id := invoice.party.id
}

request_party_ids[id] {
    invoice_template := input.payment_processing.invoice_template
    invoice_template.id == input.capi.op.invoice_template.id
    id := invoice_template.party.id
}

request_party_ids[id] {
    webhook := input.webhooks.webhook
    webhook.id == input.capi.op.webhook.id
    id := webhook.party.id
}

request_party_ids[id] {
    customer := input.cubasty.customer
    customer.id == input.capi.op.customer.id
    id := customer.party.id
}

request_party_ids[id] {
    report := input.reports.report
    report.id == input.anapi.op.report.id
    id := report.party.id
}

request_party_ids[id] {
    report := input.reports.report
    report.files[_].id == input.anapi.op.file.id
    id := report.party.id
}

wallet_party_refs := [
    {"field": "wallet", "type": "Wallet"},
    {"field": "destination", "type": "Destination"},
    {"field": "withdrawal", "type": "Withdrawal"},
    {"field": "report", "type": "WalletReport"},
    {"field": "webhook", "type": "WalletWebhook"},
]

request_party_ids[id] {
    ref := wallet_party_refs[_]
    entity := input.wallet[_]
    entity.type == ref.type
    entity.id == input.wapi.op[ref.field]
    id := entity.party
}

request_party_ids[id] {
    entity := input.entities[_]
    entity.type == "ApiKey"
    entity.id == input.apikeymgmt.op.api_key.id
    id := entity.party
}

requester_ip_whitelisted(allowed_ips) {
    ip := input.requester.ip
    cidrs := [
        cidr |
            entry := allowed_ips[_]
            cidr := ip_or_cidr(entry)
            net.cidr_is_valid(cidr)
    ]
    matches := net.cidr_contains_matches(cidrs, ip)
    matches[_]
}

ip_or_cidr(entry) = entry {
    contains(entry, "/")
}

ip_or_cidr(entry) = cidr {
    not contains(entry, "/")
    not contains(entry, ":")
    cidr := sprintf("%s/32", [entry])
}

ip_or_cidr(entry) = cidr {
    not contains(entry, "/")
    contains(entry, ":")
    cidr := sprintf("%s/128", [entry])
}

warnings[why] {
    not blacklists.source_ip_range.entries
    why := "Blacklist 'source_ip_range' is not defined, blacklisting by IP will NOT WORK."
}

warnings[why] {
    not whitelists.binapi_party_ids.entries
    why := "Whitelist 'binapi_party_ids' is not defined, whitelisting by partyID will NOT WORK."
}

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```
allowed[why] {
    input.shortener
    url_shortener.allowed[why]
}

allowed[why] {
    input.binapi
    binapi.allowed[why]
}

allowed[why] {
    input.capi
    capi.allowed[why]
}

allowed[why] {
    input.anapi
    anapi.allowed[why]
}

allowed[why] {
    input.orgmgmt
    orgmgmt.allowed[why]
}

allowed[why] {
    input.wapi
    wapi.allowed[why]
}

allowed[why] {
    input.claimmgmt
    claimmgmt.allowed[why]
}

allowed[why] {
    input.apikeymgmt
    apikeymgmt.allowed[why]
}

# Restrictions

restrictions[what] {
    input.anapi
    rstns := anapi.restrictions[_]
    what := {
        "type": "anapi",
        "restrictions": rstns
    }
}

restrictions[what] {
    input.capi
    rstns := capi.restrictions[_]
    what := {
        "type": "capi",
        "restrictions": rstns
    }
}
