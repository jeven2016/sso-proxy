package model

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// AuthConfig 认证相关信息
type AuthConfig struct {
	Verifier     *oidc.IDTokenVerifier
	Oauth2Config *oauth2.Config
	Provider     *oidc.Provider
}

// UserInfo 用户信息
type UserInfo struct {
	Realm    string         `json:"realm"`
	UserInfo *oidc.UserInfo `json:"userInfo"`
}
