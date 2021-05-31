package handlers

import (
	"fmt"
	"net/http"

	"github.com/tstranex/u2f"

	"github.com/authelia/authelia/internal/middlewares"
	"github.com/authelia/authelia/internal/session"
)

// SecondFactorU2FRegister handler validating the client has successfully validated the challenge
// to complete the U2F registration.
func SecondFactorU2FRegister(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
	responseBody := u2f.RegisterResponse{}
	err := ctx.ParseBody(&responseBody)

	if err != nil {
		ctx.Error(fmt.Errorf("Unable to parse response body: %v", err), unableToRegisterSecurityKeyMessage)
	}

	userSession := ctx.GetSession()

	if userSession.WebAuthnSessionData == nil {
		ctx.Error(fmt.Errorf("U2F registration has not been initiated yet"), unableToRegisterSecurityKeyMessage)
		return
	}
	// Ensure the challenge is cleared if anything goes wrong.
	defer func() {
		userSession.WebAuthnSessionData = nil

		err := ctx.SaveSession(userSession)
		if err != nil {
			ctx.Logger.Errorf("Unable to clear U2F challenge in session for user %s: %s", userSession.Username, err)
		}
	}()

	cred, err := web.FinishRegistration(&userSession, *userSession.WebAuthnSessionData, req)

	if err != nil {
		ctx.Error(fmt.Errorf("Unable to verify U2F registration: %v", err), unableToRegisterSecurityKeyMessage)
		return
	}

	ctx.Logger.Debugf("Register U2F device for user %s", userSession.Username)

	credBlob, err := session.ToGOB64(*cred)
	if err != nil {
		ctx.Error(fmt.Errorf("Unable to serialize webauthn credential"), unableToRegisterSecurityKeyMessage)
	}

	err = ctx.Providers.StorageProvider.SaveWebAuthnCredential(userSession.Username, credBlob)

	if err != nil {
		ctx.Error(fmt.Errorf("Unable to register U2F device for user %s: %v", userSession.Username, err), unableToRegisterSecurityKeyMessage)
		return
	}

	ctx.ReplyOK()
}
