package suites

import (
	"context"
	"testing"

	"github.com/go-rod/rod"
)

func (rs *RodSession) verifyIsFirstFactorPage(t *testing.T, page *rod.Page) {
	rs.WaitElementLocatedByCSSSelector(t, page, "first-factor-stage")
}

func (wds *WebDriverSession) verifyIsFirstFactorPage(ctx context.Context, t *testing.T) {
	wds.WaitElementLocatedByID(ctx, t, "first-factor-stage")
}
