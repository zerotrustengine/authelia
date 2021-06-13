package handlers

import (
	"fmt"
	"net/http"

	"github.com/authelia/authelia/v4/internal/middlewares"
)

// SecondFactorU2FSignPost handler for completing a signing request.
func SecondFactorU2FSignPost(u2fVerifier U2FVerifier) middlewares.AutheliaHandlerFunc {
	return func(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
		var requestBody signU2FRequestBody
		err := ctx.ParseBody(&requestBody)

		if err != nil {
			ctx.Error(err, messageMFAValidationFailed)
			return
		}

		userSession := ctx.GetSession()
		if userSession.WebAuthnSession.SessionData == nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("webauthn session data does not exist"), messageMFAValidationFailed)
			return
		}

		_, err = web.FinishLogin(&userSession, *userSession.WebAuthnSession.SessionData, req)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to finish webauthn signing of user %s: %s",
				userSession.Username, err), messageMFAValidationFailed)
			return
		}

		err = ctx.Providers.SessionProvider.RegenerateSession(ctx.RequestCtx)

		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to regenerate session for user %s: %s", userSession.Username, err), messageMFAValidationFailed)
			return
		}

		userSession.SetTwoFactor(ctx.Clock.Now())

		err = ctx.SaveSession(userSession)
		if err != nil {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to update authentication level with U2F: %s", err), messageMFAValidationFailed)
			return
		}

		if userSession.OIDCWorkflowSession != nil {
			handleOIDCWorkflowResponse(ctx)
		} else {
			Handle2FAResponse(ctx, requestBody.TargetURL)
		}
	}
}
