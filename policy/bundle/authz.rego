package application.authz

default allow = false

allow {
    input.subject.type == "user"
    data.groups.developers[_] == input.subject.id
}