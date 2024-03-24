package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// YandexProvider represents an Yandex based Identity Provider
type YandexProvider struct {
	*ProviderData
	Team       string
	Repository string
}

var _ Provider = (*YandexProvider)(nil)

const (
	yandexProviderName = "Yandex"
	yandexDefaultScope = "login:email"
)

var (
	// Default Login URL for Yandex.
	// Pre-parsed URL of https://oauth.yandex.ru/authorize.
	yandexDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "oauth.yandex.ru",
		Path:   "/authorize",
	}

	// Default Redeem URL for Yandex.
	// Pre-parsed URL of https://oauth.yandex.ru/token.
	yandexDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "oauth.yandex.ru",
		Path:   "/token",
	}

	// Default Profile URL for Yandex.
	// This simply returns the info of the authenticated user.
	// Yandex does not have a Validation URL to use.
	// Pre-parsed URL of https://login.yandex.ru/info?format=json.
	yandexDefaultProfileURL = &url.URL{
		Scheme:   "https",
		Host:     "login.yandex.ru",
		Path:     "info",
		RawQuery: "format=json",
	}
)

// NewYandexProvider initiates a new YandexProvider
func NewYandexProvider(p *ProviderData, _ options.YandexOptions) *YandexProvider {
	p.setProviderDefaults(providerDefaults{
		name:        yandexProviderName,
		loginURL:    yandexDefaultLoginURL,
		redeemURL:   yandexDefaultRedeemURL,
		profileURL:  yandexDefaultProfileURL,
		validateURL: nil,
		scope:       yandexDefaultScope,
	})

	provider := &YandexProvider{ProviderData: p}

	return provider
}

// Redeem exchanges the OAuth2 authentication code for a token
func (p *YandexProvider) Redeem(ctx context.Context, _, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	authorizationBasic := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", p.ClientID, clientSecret)))

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", fmt.Sprintf("Basic %s", authorizationBasic)).
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		s := &sessions.SessionState{
			AccessToken:  jsonResponse.AccessToken,
			RefreshToken: jsonResponse.RefreshToken,
		}
		s.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

		return s, nil
	}

	return nil, fmt.Errorf("no access token found %s", result.Body())
}

// GetEmailAddress returns the email of the authenticated user.
// Stub for yandex, because email don't return in Redeem. All user data get in EnrichSession
func (p *YandexProvider) GetEmailAddress(_ context.Context, _ *sessions.SessionState) (string, error) {
	return "", nil
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *YandexProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	var jsonResponse struct {
		ID           string `json:"id"`
		DefaultEmail string `json:"default_email"`
	}

	err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithMethod("GET").
		SetHeader("Authorization", fmt.Sprintf("OAuth %s", session.AccessToken)).
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}

	session.User = jsonResponse.ID
	session.Email = jsonResponse.DefaultEmail

	return nil
}

func (p *YandexProvider) ValidateSession(_ context.Context, _ *sessions.SessionState) bool {
	return true
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *YandexProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

func (p *YandexProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	authorizationBasic := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", p.ClientID, clientSecret)))

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", fmt.Sprintf("Basic %s", authorizationBasic)).
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return err
	}

	s.AccessToken = jsonResponse.AccessToken
	s.RefreshToken = jsonResponse.RefreshToken

	s.CreatedAtNow()
	s.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return nil
}
