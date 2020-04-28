package application.authz

default allow = false

allow {
    input.subject_type == "user"
    data.groups.developers[_] == input.subject_id
}