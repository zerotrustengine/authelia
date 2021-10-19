package suites

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/stretchr/testify/assert"
)

func (rs *RodSession) doVisit(t *testing.T, url string) *rod.Page {
	p, err := rs.WebDriver.Page(proto.TargetCreateTarget{URL: url})
	assert.NoError(t, err)

	return p
}

func (rs *RodSession) doNavigate(t *testing.T, page *rod.Page, url string) {
	err := page.Navigate(url)
	assert.NoError(t, err)
}

func (wds *WebDriverSession) doVisit(t *testing.T, url string) {
	err := wds.WebDriver.Get(url)
	assert.NoError(t, err)
}

func (rs *RodSession) doVisitAndVerifyOneFactorStep(t *testing.T, page *rod.Page, url string) {
	rs.doNavigate(t, page, url)
	rs.verifyIsFirstFactorPage(t, page)
}

func (wds *WebDriverSession) doVisitAndVerifyOneFactorStep(ctx context.Context, t *testing.T, url string) {
	wds.doVisit(t, url)
	wds.verifyIsFirstFactorPage(ctx, t)
}

func (rs *RodSession) doVisitLoginPage(t *testing.T, page *rod.Page, targetURL string) {
	suffix := ""
	if targetURL != "" {
		suffix = fmt.Sprintf("?rd=%s", targetURL)
	}

	rs.doVisitAndVerifyOneFactorStep(t, page, fmt.Sprintf("%s/%s", GetLoginBaseURL(), suffix))
}

func (wds *WebDriverSession) doVisitLoginPage(ctx context.Context, t *testing.T, targetURL string) {
	suffix := ""
	if targetURL != "" {
		suffix = fmt.Sprintf("?rd=%s", targetURL)
	}

	wds.doVisitAndVerifyOneFactorStep(ctx, t, fmt.Sprintf("%s/%s", GetLoginBaseURL(), suffix))
}
