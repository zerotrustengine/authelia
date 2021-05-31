package session

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"

	"github.com/duo-labs/webauthn/webauthn"
)

// WebAuthnID returns the user's ID
func (u *UserSession) WebAuthnID() []byte {
	return []byte(u.Username)
}

// WebAuthnName returns the user's username
func (u *UserSession) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName returns the user's display name
func (u *UserSession) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon is not (yet) implemented
func (u *UserSession) WebAuthnIcon() string {
	return ""
}

func (u *UserSession) AddCredential(cred *webauthn.Credential) {
	u.WebAuthnCredential = cred
}

// WebAuthnCredentials returns credentials owned by the user
func (u *UserSession) WebAuthnCredentials() []webauthn.Credential {
	if u.WebAuthnCredential == nil {
		return nil
	}
	return []webauthn.Credential{*u.WebAuthnCredential}
}

func ToGOB64(m webauthn.Credential) (string, error) {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(m)
	if err != nil {
		return "", fmt.Errorf(`failed gob Encode`, err)
	}
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

func FromGOB64(str string) (*webauthn.Credential, error) {
	m := webauthn.Credential{}
	by, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, fmt.Errorf(`failed base64 Decode`, err)
	}
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err = d.Decode(&m)
	if err != nil {
		return nil, fmt.Errorf(`failed gob Decode`, err)
	}
	return &m, nil
}
