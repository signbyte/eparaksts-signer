package routes

import (
	"azugo.io/azugo"

	"github.com/signbyte/eparaksts-signer/routes/response"
)

// info — GET /api/v1/info
//
// What this deployment offers: the signing flows it runs. A caller offers a person
// only these, so a method that would be refused is never shown; a CSC flow is
// listed only when a CSC client is configured.
func (r *router) info(ctx *azugo.Context) {
	flows := r.Orchestrator().OfferedFlows()
	out := response.Info{Flows: make([]response.InfoFlow, 0, len(flows))}
	for _, f := range flows {
		out.Flows = append(out.Flows, response.InfoFlow{Name: string(f)})
	}
	ctx.JSON(&out)
}
