package model

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type AuthConfig struct {
	Verifier     *oidc.IDTokenVerifier
	Oauth2Config *oauth2.Config
	Provider     *oidc.Provider
}

type UserInfo struct {
	Realm    string         `json:"realm"`
	UserInfo *oidc.UserInfo `json:"userInfo"`
}
