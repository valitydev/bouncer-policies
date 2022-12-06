package service.authz.api.apikeymgmt

import data.service.authz.api.user
import data.service.authz.access
import data.service.authz.roles
import data.service.authz.methods

import input.apikeymgmt.op
import input.entities

api_name := "ApiKeyMgmt"
access_matrix := access.api[api_name]

access_mandatory := "mandatory"

access_requirements := {
    access_mandatory
}

# Set of assertions which tell why operation under the input context is forbidden.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

forbidden[why] {
    not allowed_operation_for_auth_method
    why := {
        "code": "unknown_auth_method_forbids_operation",
        "description": sprintf("Unknown auth method for this operation: %v", [input.auth.method])
    }
}

forbidden[why] {
    input.auth.method == "SessionToken"
    access_violations[why]
}

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

allowed[why] {
    allowed_operation_for_auth_method
    auth_method_allowed[why]
}

auth_method_allowed[why] {
    input.auth.method == "SessionToken"
    count(access_violations) == 0
    session_token_allowed[why]
}

session_token_allowed[why] {
    access_status.owner
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

session_token_allowed[why] {
    role := operation_roles[_]
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [role.id])
    }
}

access_status = status {
    # NOTE
    # This is intentional. In there are no violations then the access status set
    # MUST NOT contain conflicting (i.e. more than one) status assertions.
    # Otherwise evaluation will end with a runtime error. Usually it would mean
    # that either incoming context or access matrix (access/data.yaml) is
    # malformed.
    count(access_violations) == 0
    status := access_status_set[_]
}

access_status_set[status] {
    operation_access_request[requirement][name]
    status := entity_access_requirement_status(name, requirement)
    is_object(status)
}

access_violations[violation] {
    violation := access_status_set[_].violation
}

operation_access_request[requirement] = names {
    requirement := access_requirements[_]
    entities := access_matrix[requirement]
    names := { name | entities[name].operations[_] == op.id }
}

entity_access_requirement_status(name, req) = status {
    req == access_mandatory
    status := entity_access_status[name]
} else = status {
    violation := {
        "code": "missing_access",
        "description": sprintf(
            "Missing %s access for %s with operation id = %s",
            [req, name, op.id]
        )
    }
    status := {"violation": violation}
}

entity_access_status["party"] = status {
    status := party_access_status(op.party.id)
}
entity_access_status["api_key"] = status {
    status := api_key_access_status(op.api_key.id)
}

party_access_status(party_id) = status {
    user.is_owner(party_id)
    status := {"owner": true}
} else = status {
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_party_access(role)
    }
    roles[_]
    status := {"roles": roles}
}

user_role_has_party_access(role) {
    not role.scope
}

api_key_access_status(id) = status {
    entity := entities_by_type["ApiKey"][id]
    status := party_access_status(entity.party)
}

operation_roles[role] {
    role := access_status.roles[_]
    operations := user.operations_by_role(api_name, role)
    operations[_] == op.id
}

entities_by_type[type] = out {
    type := entities[_].type
    out := { id: entity |
        entity := entities[_]
        id := entity.id
        entity.type == type
    }
}

allowed_operation_for_auth_method {
    operations_available := methods.permissions[input.auth.method].apis[api_name].operations
    operations_available[_] == op.id
}
