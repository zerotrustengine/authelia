package suites

import (
	"context"
	"testing"

	"github.com/go-rod/rod"
)

func (rs *RodSession) doRegisterThenLogout(t *testing.T, page *rod.Page, username, password string) string {
	secret := rs.doLoginAndRegisterTOTP(t, page, username, password, false)
	rs.doLogout(t, page)

	return secret
}

func (wds *WebDriverSession) doRegisterThenLogout(ctx context.Context, t *testing.T, username, password string) string {
	secret := wds.doLoginAndRegisterTOTP(ctx, t, username, password, false)
	wds.doLogout(ctx, t)

	return secret
}
