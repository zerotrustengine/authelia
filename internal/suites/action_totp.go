package suites

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (rs *RodSession) doRegisterTOTP(t *testing.T, page *rod.Page) string {
	err := rs.WaitElementLocatedByID(t, page, "#register-link").Click("left")
	require.NoError(t, err)
	rs.verifyMailNotificationDisplayed(t, page)
	link := doGetLinkFromLastMail(t)
	rs.doNavigate(t, page, link)
	// TODO: secretURL, err := rs.WaitElementLocatedByID(t, page, "#secret-url").GetAttribute("value")
	s := rs.WaitElementLocatedByID(t, page, "#secret-url")
	secretURL, err := s.Attribute("value")

	assert.NoError(t, err)

	secret := (*secretURL)[strings.LastIndex(*secretURL, "=")+1:]
	assert.NotEqual(t, "", secret)
	assert.NotNil(t, secret)

	return secret
}

func (wds *WebDriverSession) doRegisterTOTP(ctx context.Context, t *testing.T) string {
	err := wds.WaitElementLocatedByID(ctx, t, "register-link").Click()
	require.NoError(t, err)
	wds.verifyMailNotificationDisplayed(ctx, t)
	link := doGetLinkFromLastMail(t)
	wds.doVisit(t, link)
	secretURL, err := wds.WaitElementLocatedByID(ctx, t, "secret-url").GetAttribute("value")
	assert.NoError(t, err)

	secret := secretURL[strings.LastIndex(secretURL, "=")+1:]
	assert.NotEqual(t, "", secret)
	assert.NotNil(t, secret)

	return secret
}

func (rs *RodSession) doEnterOTP(t *testing.T, page *rod.Page, code string) {
	inputs := rs.WaitElementsLocatedByCSSSelector(t, page, "otp-input input")

	for i := 0; i < 6; i++ {
		err := inputs[i].Input(string(code[i]))
		require.NoError(t, err)
	}
}

func (wds *WebDriverSession) doEnterOTP(ctx context.Context, t *testing.T, code string) {
	inputs := wds.WaitElementsLocatedByCSSSelector(ctx, t, "#otp-input input")

	for i := 0; i < 6; i++ {
		err := inputs[i].SendKeys(string(code[i]))
		require.NoError(t, err)
	}
}

func (rs *RodSession) doValidateTOTP(t *testing.T, page *rod.Page, secret string) {
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)
	rs.doEnterOTP(t, page, code)
}

func (wds *WebDriverSession) doValidateTOTP(ctx context.Context, t *testing.T, secret string) {
	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)
	wds.doEnterOTP(ctx, t, code)
}
