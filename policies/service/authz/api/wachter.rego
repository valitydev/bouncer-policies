package service.authz.api.wachter

import data.service.authz.api.user
import data.service.authz.access
import data.service.authz.roles
import data.service.authz.methods

import input.wachter.op


api_name := "Wachter"
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
    input.auth.method != "SessionToken"
    why := {
        "code": "unknown_auth_method_forbids_operation",
        "description": sprintf("Unknown auth method for this operation: %v", [input.auth.method])
    }
}

forbidden[why] {
    not allowed_operation_for_auth_method
    why := {
        "code": "unknown_auth_method_forbids_operation",
        "description": sprintf("Unknown auth method for this operation: %v", [op.id])
    }
}

forbidden[why] {
    not allowed_operation_for_service
    why := {
        "code": "unknown_service_forbids_operation",
        "description": sprintf("Unknown service %v for this operation: %v", [op.service_name, op.id])
    }
}

forbidden[why] {
    not allowed_operation_for_role
    why := {
        "code": "unknown_role_forbids_operation",
        "description": sprintf("Have no roles for this service: %v and operation: %v",
        [op.service_name, op.id])
    }
}

allowed[why] {
    input.auth.method == "SessionToken"
    allowed_operation_for_auth_method
    allowed_operation_for_service
    allowed_operation_for_role
    why := {
        "code": "allowed_operation",
        "description": sprintf("Allowed operation %v for service %v", [op.id, op.service_name])
    }
}

allowed_operation_for_auth_method {
    operations_available := methods.permissions[input.auth.method].apis[api_name].operations
    operations_available[_] == op.id
}


allowed_operation_for_service {
    operations_available := access.api[api_name].mandatory[op.service_name].operations
    operations_available[_] == op.id
}

allowed_operation_for_role {
      operations_available := operations_by_role
      operations_available[_] == op.id

}

operations_by_role = operations {
    operations := {
        operation |
            operation := roles.internal.apis[op.access[_].id].roles[op.access[_].roles[_]].operations[_]
    }
}
