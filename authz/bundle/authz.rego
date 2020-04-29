package application.authz

default allow = false

allow {
    input.subject.type == "person"
    input.operation == "write"
    input.resource.type == "post"
    channel_role := input.subject.attributes.channel_role
    count(data.post_restricted_channels[channel_role]) == 0
}

allow {
    input.subject.type == "person"
    input.operation == "write"
    input.resource.type == "post"
    channel_role := input.subject.attributes.channel_role
    data.post_restricted_channels[channel_role][_] != input.resource.attributes.channel_id
}