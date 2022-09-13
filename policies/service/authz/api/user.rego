package service.authz.api.user

import data.service.authz.roles

is_owner(party_id) {
    organization := org_by_party(party_id)
    input.user.id == organization.owner.id
}

is_owner(org_id) {
    organization := org_by_org_id(org_id)
    input.user.id == organization.owner.id
}

operations_by_role(api_name, user_role) = operations {
    operations := {
        operation |
            operation := roles.roles[user_role.id].apis[api_name].operations[_]
    }
}

org_by_party(party_id) = org {
    org := input.user.orgs[_]
    org.party.id == party_id
}

org_by_org_id(org_id) = org {
    org := input.user.orgs[_]
    org.id == org_id
}
