package suites

import (
	"context"
	"testing"

	"github.com/go-rod/rod"
)

func (rs *RodSession) verifySecretAuthorized(t *testing.T, page *rod.Page) {
	rs.WaitElementLocatedByCSSSelector(t, page, "secret")
}

func (wds *WebDriverSession) verifySecretAuthorized(ctx context.Context, t *testing.T) {
	wds.WaitElementLocatedByID(ctx, t, "secret")
}
