package session

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"

	"github.com/duo-labs/webauthn/webauthn"
)

// WebAuthnID returns the user's ID.
func (us *UserSession) WebAuthnID() []byte {
	return []byte(us.Username)
}

// WebAuthnName returns the user's username.
func (us *UserSession) WebAuthnName() string {
	return us.Username
}

// WebAuthnDisplayName returns the user's display name.
func (us *UserSession) WebAuthnDisplayName() string {
	return us.DisplayName
}

// WebAuthnIcon is not (yet) implemented.
func (us *UserSession) WebAuthnIcon() string {
	return ""
}

// AddCredential add a credential to this session.
func (us *UserSession) AddCredential(cred *webauthn.Credential) {
	us.WebAuthnSession.Credential = cred
}

// WebAuthnCredentials returns credentials owned by the user.
func (us *UserSession) WebAuthnCredentials() []webauthn.Credential {
	if us.WebAuthnSession.Credential == nil {
		return nil
	}

	return []webauthn.Credential{*us.WebAuthnSession.Credential}
}

// ToGOB64 marshal webauthn credential into encoded string.
func ToGOB64(m webauthn.Credential) (string, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(m)

	if err != nil {
		return "", fmt.Errorf(`failed gob Encode: %w`, err)
	}

	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

// FromGOB64 unmarshal string into a webauthn credential.
func FromGOB64(str string) (*webauthn.Credential, error) {
	m := webauthn.Credential{}
	by, err := base64.StdEncoding.DecodeString(str)

	if err != nil {
		return nil, fmt.Errorf(`failed base64 Decode: %w`, err)
	}

	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err = d.Decode(&m)

	if err != nil {
		return nil, fmt.Errorf(`failed gob Decode: %w`, err)
	}

	return &m, nil
}
