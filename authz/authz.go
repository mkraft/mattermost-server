package authz

import (
	"context"
	"fmt"
	"net/http"

	"github.com/mattermost/mattermost-server/mlog"
	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/open-policy-agent/opa/rego"
)

type SubjectType string

// OperationType are the possible actions as list in
// https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-162.pdf
type OperationType string

type ResourceType string

const (
	Person          SubjectType = "person"
	NonPersonEntity SubjectType = "non_person_entity"

	Post ResourceType = "post"

	Read    OperationType = "read"
	Write   OperationType = "write"
	Edit    OperationType = "edit"
	Delete  OperationType = "delete"
	Copy    OperationType = "copy"
	Execute OperationType = "execute"
	Modify  OperationType = "modify"
)

type Subject struct {
	Type       SubjectType            `json:"type"`
	ID         string                 `json:"id"`
	Attributes map[string]interface{} `json:"attributes"`
}

type Resource struct {
	Type       ResourceType           `json:"type"`
	Attributes map[string]interface{} `json:"attributes"`
}

type Input struct {
	Subject   *Subject      `json:"subject"` // aka requestor
	Operation OperationType `json:"operation"`
	Resource  *Resource     `json:"resource"`
}

// type ResOps struct {
// 	Res Resource
// 	Ops []OperationType
// }

// func NewResOps(res *Res, ops ...OperationType) *ResOps {
// 	return &ResOps{Res: res, Ops: ops}
// }

func Granted(input *Input) (bool, error) {
	ctx := context.Background()

	query, err := rego.New(
		rego.Query("x = data.application.authz.allow"),
		rego.LoadBundle("./authz/bundle"),
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

func MakePolicyError(input *Input) *model.AppError {
	details := fmt.Sprintf("subject_type=%s, subject_id=%s, subject_attributes=%v, operation=%s, resource_type=%s, resource_attributes=%v", input.Subject.Type, input.Subject.ID, input.Subject.Attributes, input.Operation, input.Resource.Type, input.Resource.Attributes)
	return model.NewAppError("authz", "api.context.policy.app_error", nil, details, http.StatusForbidden)
}
