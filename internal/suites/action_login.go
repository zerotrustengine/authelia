package suites

import (
	"context"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/stretchr/testify/require"
)

func (rs *RodSession) doFillLoginPageAndClick(t *testing.T, page *rod.Page, username, password string, keepMeLoggedIn bool) {
	usernameElement := rs.WaitElementLocatedByCSSSelector(t, page, "username-textfield")
	err := usernameElement.Input(username)
	require.NoError(t, err)

	passwordElement := rs.WaitElementLocatedByCSSSelector(t, page, "password-textfield")
	err = passwordElement.Input(password)
	require.NoError(t, err)

	if keepMeLoggedIn {
		keepMeLoggedInElement := rs.WaitElementLocatedByCSSSelector(t, page, "remember-checkbox")
		err = keepMeLoggedInElement.Click("left")
		require.NoError(t, err)
	}

	buttonElement := rs.WaitElementLocatedByCSSSelector(t, page, "sign-in-button")
	err = buttonElement.Click("left")
	require.NoError(t, err)
}

func (wds *WebDriverSession) doFillLoginPageAndClick(ctx context.Context, t *testing.T, username, password string, keepMeLoggedIn bool) {
	usernameElement := wds.WaitElementLocatedByID(ctx, t, "username-textfield")
	err := usernameElement.SendKeys(username)
	require.NoError(t, err)

	passwordElement := wds.WaitElementLocatedByID(ctx, t, "password-textfield")
	err = passwordElement.SendKeys(password)
	require.NoError(t, err)

	if keepMeLoggedIn {
		keepMeLoggedInElement := wds.WaitElementLocatedByID(ctx, t, "remember-checkbox")
		err = keepMeLoggedInElement.Click()
		require.NoError(t, err)
	}

	buttonElement := wds.WaitElementLocatedByID(ctx, t, "sign-in-button")
	err = buttonElement.Click()
	require.NoError(t, err)
}

// Login 1FA.
func (rs *RodSession) doLoginOneFactor(t *testing.T, page *rod.Page, username, password string, keepMeLoggedIn bool, targetURL string) {
	rs.doVisitLoginPage(t, page, targetURL)
	rs.doFillLoginPageAndClick(t, page, username, password, keepMeLoggedIn)
}

// Login 1FA.
func (wds *WebDriverSession) doLoginOneFactor(ctx context.Context, t *testing.T, username, password string, keepMeLoggedIn bool, targetURL string) {
	wds.doVisitLoginPage(ctx, t, targetURL)
	wds.doFillLoginPageAndClick(ctx, t, username, password, keepMeLoggedIn)
}

// Login 1FA and 2FA subsequently (must already be registered).
func (rs *RodSession) doLoginTwoFactor(t *testing.T, page *rod.Page, username, password string, keepMeLoggedIn bool, otpSecret, targetURL string) {
	rs.doLoginOneFactor(t, page, username, password, keepMeLoggedIn, targetURL)
	rs.verifyIsSecondFactorPage(t, page)
	rs.doValidateTOTP(t, page, otpSecret)
	// timeout when targetURL is not defined to prevent a show stopping redirect when visiting a protected domain
	if targetURL == "" {
		time.Sleep(1 * time.Second)
	}
}

// Login 1FA and 2FA subsequently (must already be registered).
func (wds *WebDriverSession) doLoginTwoFactor(ctx context.Context, t *testing.T, username, password string, keepMeLoggedIn bool, otpSecret, targetURL string) {
	wds.doLoginOneFactor(ctx, t, username, password, keepMeLoggedIn, targetURL)
	wds.verifyIsSecondFactorPage(ctx, t)
	wds.doValidateTOTP(ctx, t, otpSecret)
	// timeout when targetURL is not defined to prevent a show stopping redirect when visiting a protected domain
	if targetURL == "" {
		time.Sleep(1 * time.Second)
	}
}

// Login 1FA and register 2FA.
func (rs *RodSession) doLoginAndRegisterTOTP(t *testing.T, page *rod.Page, username, password string, keepMeLoggedIn bool) string {
	rs.doLoginOneFactor(t, page, username, password, keepMeLoggedIn, "")
	secret := rs.doRegisterTOTP(t, page)
	rs.doNavigate(t, page, GetLoginBaseURL())
	rs.verifyIsSecondFactorPage(t, page)

	return secret
}

// Login 1FA and register 2FA.
func (wds *WebDriverSession) doLoginAndRegisterTOTP(ctx context.Context, t *testing.T, username, password string, keepMeLoggedIn bool) string {
	wds.doLoginOneFactor(ctx, t, username, password, keepMeLoggedIn, "")
	secret := wds.doRegisterTOTP(ctx, t)
	wds.doVisit(t, GetLoginBaseURL())
	wds.verifyIsSecondFactorPage(ctx, t)

	return secret
}

// Register a user with TOTP, logout and then authenticate until TOTP-2FA.
func (rs *RodSession) doRegisterAndLogin2FA(t *testing.T, page *rod.Page, username, password string, keepMeLoggedIn bool, targetURL string) string {
	// Register TOTP secret and logout.
	secret := rs.doRegisterThenLogout(t, page, username, password)
	rs.doLoginTwoFactor(t, page, username, password, keepMeLoggedIn, secret, targetURL)

	return secret
}

// Register a user with TOTP, logout and then authenticate until TOTP-2FA.
func (wds *WebDriverSession) doRegisterAndLogin2FA(ctx context.Context, t *testing.T, username, password string, keepMeLoggedIn bool, targetURL string) string { //nolint:unparam
	// Register TOTP secret and logout.
	secret := wds.doRegisterThenLogout(ctx, t, username, password)
	wds.doLoginTwoFactor(ctx, t, username, password, keepMeLoggedIn, secret, targetURL)

	return secret
}
