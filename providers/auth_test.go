package providers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

var authorizedAccessToken = "imaginary_access_token"

func CreateAuthorizedSession() *sessions.SessionState {
	return &sessions.SessionState{AccessToken: authorizedAccessToken}
}

func IsAuthorizedBearerInHeader(reqHeader http.Header) bool {
	return IsAuthorizedBearerInHeaderWithToken(reqHeader, authorizedAccessToken)
}

func IsAuthorizedBearerInHeaderWithToken(reqHeader http.Header, token string) bool {
	return reqHeader.Get("Authorization") == fmt.Sprintf("Bearer %s", token)
}

func IsAuthorizedOAuthInHeader(reqHeader http.Header) bool {
	return IsAuthorizedOAuthInHeaderWithToken(reqHeader, authorizedAccessToken)
}

func IsAuthorizedOAuthInHeaderWithToken(reqHeader http.Header, token string) bool {
	return reqHeader.Get("Authorization") == fmt.Sprintf("OAuth %s", token)
}

func IsAuthorizedInURL(reqURL *url.URL) bool {
	return reqURL.Query().Get("access_token") == authorizedAccessToken
}

func isAuthorizedRefreshInURLWithToken(reqURL *url.URL, token string) bool {
	if token == "" {
		return false
	}
	return reqURL.Query().Get("refresh_token") == token
}
