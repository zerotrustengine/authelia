package suites

import (
	"context"
	"testing"

	"github.com/go-rod/rod"
)

func (rs *RodSession) verifyMailNotificationDisplayed(t *testing.T, page *rod.Page) {
	rs.verifyNotificationDisplayed(t, page, "An email has been sent to your address to complete the process.")
}

func (wds *WebDriverSession) verifyMailNotificationDisplayed(ctx context.Context, t *testing.T) {
	wds.verifyNotificationDisplayed(ctx, t, "An email has been sent to your address to complete the process.")
}
