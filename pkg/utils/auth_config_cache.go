package utils

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"sso-proxy/pkg/model"
)

var authConfigCache = map[string]*model.AuthConfig{}

var lock = &sync.RWMutex{}

func retrieve(realm string) (*model.AuthConfig, bool) {
	lock.RLock()
	defer lock.RUnlock()
	authCfg, exists := authConfigCache[realm]
	return authCfg, exists
}

func GetByRealm(realm string) *model.AuthConfig {
	var authCfg *model.AuthConfig
	var exists bool
	if authCfg, exists := retrieve(realm); exists {
		return authCfg
	}

	// initialize oauth config
	lock.Lock()
	defer lock.Unlock()

	authCfg, exists = authConfigCache[realm]
	if !exists {
		oidcClients := GetConfig().SsoProxyConfig.OidcClients
		var client *model.Client
		for _, c := range oidcClients {
			if c.Realm == realm {
				client = &c
				break
			}
		}

		if client != nil {
			provider, err := oidc.NewProvider(context.Background(), client.Issuer)
			if err != nil {
				Log().Error("Failed to initialize oidc client", zap.Error(err))
				return nil
			}

			verifier := provider.Verifier(&oidc.Config{ClientID: client.ClientId})

			// Configure an OpenID Connect aware OAuth2 client.
			oauth2Config := &oauth2.Config{
				ClientID:     client.ClientId,
				ClientSecret: client.Secret,
				RedirectURL:  client.RedirectUrl, // redirect url for generating token by code

				// Discovery returns the OAuth2 endpoints.
				Endpoint: provider.Endpoint(),

				// "openid" is a required scope for OpenID Connect flows.
				Scopes: client.Scopes,
			}

			authCfg = &model.AuthConfig{Verifier: verifier, Oauth2Config: oauth2Config, Provider: provider}
			authConfigCache[realm] = authCfg
		}
	}
	return authCfg
}
