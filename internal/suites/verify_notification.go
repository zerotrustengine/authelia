package suites

import (
	"context"
	"testing"

	"github.com/go-rod/rod"
	"github.com/stretchr/testify/assert"
)

func (rs *RodSession) verifyNotificationDisplayed(t *testing.T, page *rod.Page, message string) {
	el := rs.WaitElementLocatedByClassName(t, page, "notification")
	assert.NotNil(t, el)
	rs.WaitElementTextContains(t, page, el, message)
}

func (wds *WebDriverSession) verifyNotificationDisplayed(ctx context.Context, t *testing.T, message string) {
	el := wds.WaitElementLocatedByClassName(ctx, t, "notification")
	assert.NotNil(t, el)
	wds.WaitElementTextContains(ctx, t, el, message)
}
