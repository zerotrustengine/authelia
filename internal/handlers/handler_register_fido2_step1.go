package handlers

import (
	"fmt"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/sirupsen/logrus"
	"github.com/tstranex/u2f"

	"github.com/authelia/authelia/internal/middlewares"
)

var web *webauthn.WebAuthn

func init() {
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Authelia",                       // Display Name for your site
		RPID:          "example.com",                    // Generally the FQDN for your site
		RPOrigin:      "https://login.example.com:8080", // The origin URL for WebAuthn requests
	})
	if err != nil {
		logrus.Panic(err)
	}
	web = w
}

var u2fConfig = &u2f.Config{
	// Chrome 66+ doesn't return the device's attestation
	// certificate by default.
	SkipAttestationVerify: true,
}

// SecondFactorU2FIdentityStart the handler for initiating the identity validation.
var SecondFactorU2FIdentityStart = middlewares.IdentityVerificationStart(middlewares.IdentityVerificationStartArgs{
	MailTitle:             "Register your key",
	MailButtonContent:     "Register",
	TargetEndpoint:        "/security-key/register",
	ActionClaim:           U2FRegistrationAction,
	IdentityRetrieverFunc: identityRetrieverFromSession,
})

func secondFactorU2FIdentityFinish(ctx *middlewares.AutheliaCtx, username string) {
	if ctx.XForwardedProto() == nil {
		ctx.Error(errMissingXForwardedProto, operationFailedMessage)
		return
	}

	if ctx.XForwardedHost() == nil {
		ctx.Error(errMissingXForwardedHost, operationFailedMessage)
		return
	}

	userSession := ctx.GetSession()

	options, sessionData, err := web.BeginRegistration(&userSession)

	if err != nil {
		ctx.Error(fmt.Errorf("Unable to begin webauthn registration: %s", err), operationFailedMessage)
		return
	}

	// Save the challenge in the user session.
	userSession.WebAuthnSessionData = sessionData
	err = ctx.SaveSession(userSession)

	if err != nil {
		ctx.Error(fmt.Errorf("Unable to save U2F challenge in session: %s", err), operationFailedMessage)
		return
	}

	err = ctx.SetJSONBody(options)
	if err != nil {
		ctx.Logger.Errorf("Unable to create request to enrol new token: %s", err)
	}
}

// SecondFactorU2FIdentityFinish the handler for finishing the identity validation.
var SecondFactorU2FIdentityFinish = middlewares.IdentityVerificationFinish(
	middlewares.IdentityVerificationFinishArgs{
		ActionClaim:          U2FRegistrationAction,
		IsTokenUserValidFunc: isTokenUserValidFor2FARegistration,
	}, secondFactorU2FIdentityFinish)
