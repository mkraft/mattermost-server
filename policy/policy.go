package policy

import (
	"context"

	"github.com/mattermost/mattermost-server/mlog"
	"github.com/open-policy-agent/opa/rego"
)

type Subject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Resource struct {
	Name      string `json:"name"`
	TeamID    string `json:"team_id"`
	ChannelID string `json:"channel_id"`
}

type Input struct {
	Resource *Resource `json:"resource"` // post, channel, channel name, etc...
	Subject  *Subject  `json:"subject"`
	Action   string    `json:"action"` // crud
}

func Result(input *Input) (bool, error) {
	ctx := context.Background()

	query, err := rego.New(
		rego.Query("x = data.application.authz.allow"),
		rego.LoadBundle("./policy/bundle"),
	).PrepareForEval(ctx)
	if err != nil {
		return false, err
	}

	results, err := query.Eval(ctx, rego.EvalInput(input))
	var result, ok bool
	if err != nil {
		// evaluation error.
		return false, err
	} else if len(results) == 0 {
		// undefined result.
		mlog.Error("undefined result from authz policies")
		return false, nil
	} else if result, ok = results[0].Bindings["x"].(bool); !ok {
		// unexpected result type.
		mlog.Error("unexpected result from authz policies")
		return false, nil
	}

	return result, nil
}
