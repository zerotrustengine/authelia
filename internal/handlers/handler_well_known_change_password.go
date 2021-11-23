package handlers

import (
	"fmt"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/middlewares"
)

// WellKnownChangePassword handles the .well-known/change-password requests.
func WellKnownChangePassword(defaultCode int) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		root, err := ctx.ExternalRootURL()
		if err != nil {
			ctx.Response.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString(fasthttp.StatusMessage(fasthttp.StatusBadRequest))

			return
		}

		var statusCode int

		switch {
		case ctx.IsXHR() || !ctx.AcceptsMIME("text/html"):
			statusCode = fasthttp.StatusUnauthorized
		default:
			statusCode = defaultCode
		}

		ctx.SpecialRedirect(fmt.Sprintf("%s/reset-password/step1", root), statusCode)
	}
}
