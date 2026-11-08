package policyhelix.authz

# Default deny all access
default allow = false

# Allow authenticated subjects with operator or admin role
allow {
    input.subject.authenticated == true
    input.subject.role == "operator"
}

allow {
    input.subject.authenticated == true
    input.subject.role == "admin"
}
