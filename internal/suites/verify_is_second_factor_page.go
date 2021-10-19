package suites

import (
	"context"
	"testing"

	"github.com/go-rod/rod"
)

func (rs *RodSession) verifyIsSecondFactorPage(t *testing.T, page *rod.Page) {
	rs.WaitElementLocatedByCSSSelector(t, page, "second-factor-stage")
}

func (wds *WebDriverSession) verifyIsSecondFactorPage(ctx context.Context, t *testing.T) {
	wds.WaitElementLocatedByID(ctx, t, "second-factor-stage")
}
