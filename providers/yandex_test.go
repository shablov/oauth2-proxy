package providers

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testYandexProvider(hostname string) *YandexProvider {
	p := NewYandexProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
		options.YandexOptions{},
	)

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testYandexBackend(payload string) *httptest.Server {
	paths := map[string]bool{
		"/info?format=json": true,
	}

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if !paths[url.Path+"?"+url.RawQuery] {
				log.Printf("%s not in %+v\n", url.Path, paths)
				w.WriteHeader(404)
			} else if !IsAuthorizedOAuthInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestNewYandexProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewYandexProvider(&ProviderData{}, options.YandexOptions{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Yandex"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://oauth.yandex.ru/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://oauth.yandex.ru/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://login.yandex.ru/info?format=json"))
	g.Expect(providerData.ValidateURL.String()).To(Equal(""))
	g.Expect(providerData.Scope).To(Equal("login:email"))
}

func TestYandexProviderScope(t *testing.T) {
	p := testYandexProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "login:email", p.Data().Scope)
}

func TestYandexProviderOverrides(t *testing.T) {
	p := NewYandexProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v3/user"},
			Scope: "email"},
		options.YandexOptions{})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Yandex", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v3/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "email", p.Data().Scope)
}

func TestYandexProviderGetUserInfo(t *testing.T) {
	b := testYandexBackend("{ \"default_email\": \"michael.bland@gsa.gov\", \"id\": \"123123\" }")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testYandexProvider(bURL.Host)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "123123", session.User)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestYandexProviderGetUserInfoFailedRequest(t *testing.T) {
	b := testYandexBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testYandexProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	err := p.EnrichSession(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", session.Email)
}

func TestYandexProviderGetUserInfoNotPresentInPayload(t *testing.T) {
	b := testYandexBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testYandexProvider(bURL.Host)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, "", session.Email)
	assert.Equal(t, nil, err)
}
