package handlers

import (
	"fmt"

	"github.com/authelia/authelia/internal/middlewares"
	"github.com/authelia/authelia/internal/session"
	"github.com/authelia/authelia/internal/storage"
)

// SecondFactorU2FSignGet handler for initiating a signing request.
func SecondFactorU2FSignGet(ctx *middlewares.AutheliaCtx) {
	if ctx.XForwardedProto() == nil {
		ctx.Error(errMissingXForwardedProto, mfaValidationFailedMessage)
		return
	}

	if ctx.XForwardedHost() == nil {
		ctx.Error(errMissingXForwardedHost, mfaValidationFailedMessage)
		return
	}

	userSession := ctx.GetSession()
	credentialStr, err := ctx.Providers.StorageProvider.LoadWebAuthnCredential(userSession.Username)

	if err != nil {
		if err == storage.ErrNoU2FDeviceHandle {
			handleAuthenticationUnauthorized(ctx, fmt.Errorf("No device handle found for user %s", userSession.Username), mfaValidationFailedMessage)
			return
		}

		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to retrieve U2F device handle: %s", err), mfaValidationFailedMessage)

		return
	}

	cred, err := session.FromGOB64(credentialStr)
	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to deserialize webauthn credential: %s", err), mfaValidationFailedMessage)
		return
	}
	userSession.AddCredential(cred)

	options, sessionData, err := web.BeginLogin(&userSession)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to begin webauthn login: %s", err), mfaValidationFailedMessage)
		return
	}

	userSession.WebAuthnSessionData = sessionData
	err = ctx.SaveSession(userSession)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to save U2F challenge and registration in session: %s", err), mfaValidationFailedMessage)
		return
	}

	err = ctx.SetJSONBody(options)

	if err != nil {
		handleAuthenticationUnauthorized(ctx, fmt.Errorf("Unable to set sign request in body: %s", err), mfaValidationFailedMessage)
		return
	}
}
