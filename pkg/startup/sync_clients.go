package startup

import (
	"context"
	"strings"

	"github.com/Nerzal/gocloak/v11"
	"go.uber.org/zap"

	"sso-proxy/pkg/model"
	"sso-proxy/pkg/utils"
)

func SyncClients() {
	var masterClient *model.Client
	for _, client := range utils.GetConfig().SsoProxyConfig.OidcClients {
		if client.Realm == utils.IamMasterRealm {
			masterClient = &client
			break
		}
	}

	if masterClient == nil {
		utils.Log().Fatal("[!!!] no master client configured in config.yaml that means lacking ways to " +
			"figure out what realms and clients configured in IAM side")
		return
	}

	var ctx = context.Background()
	var authenticator = utils.GetAuthenticator()

	// keycloak service account client
	kcClient := gocloak.NewClient(authenticator.Url,
		gocloak.SetAuthRealms(utils.AuthRealm),
		gocloak.SetAuthAdminRealms(utils.AuthAdminRealms))

	// 申请一个master realm下service account的token
	grantType := "client_credentials"
	token, err := kcClient.GetToken(ctx, utils.IamMasterRealm, gocloak.TokenOptions{
		GrantType:    &grantType,
		ClientID:     &masterClient.ClientId,
		ClientSecret: &masterClient.Secret,
	})

	if err != nil {
		// 在日志中隐藏真实的secret，只提示是否为空
		var secretDesc = "[Blank]"
		if len(masterClient.Secret) > 0 {
			secretDesc = "[Not Blank]"
		}

		utils.Log().Warn("Failed to retrieve a token", zap.Error(err), zap.String("realm", "master"),
			zap.String("clientId", masterClient.ClientId), zap.String("secret", secretDesc))
		return
	}

	// 获取所有的realm
	results, err := kcClient.GetRealms(ctx, token.AccessToken)
	if err != nil {
		utils.Log().Error("Failed to retrieve all realms", zap.String("token", token.AccessToken))
		return
	}

	for _, realmRepresentation := range results {
		// 获取realm下sso-proxy的client配置
		syncRealmClients(kcClient, masterClient, ctx, token, realmRepresentation.Realm, authenticator)
	}
}

func syncRealmClients(kcClient gocloak.GoCloak, masterClient *model.Client, ctx context.Context,
	token *gocloak.JWT, realm *string, authenticator *model.Authenticator) {

	clients, err := kcClient.GetClients(ctx, token.AccessToken, *realm,
		gocloak.GetClientsParams{First: &authenticator.SyncClients.PageParam.First,
			Max: &authenticator.SyncClients.PageParam.Max})

	if err != nil {
		utils.Log().Error("Failed to retrieve clients for realm "+*realm, zap.Error(err))
		return
	}

	var hasRealmClient bool
	for _, client := range clients {
		if !strings.EqualFold(*client.ClientID, "sso-proxy") || clientExists(client, realm) {
			continue
		}

		issuer, err := kcClient.GetIssuer(ctx, *realm)
		if err != nil {
			utils.Log().Error("Failed to retrieve issuer url in realm " + *realm)
			return
		}

		// 从issuer url中截取oidc所需的Url前缀
		// keycloak issuer url: http://localhost:8080/realms/jeven/protocol/openid-connect
		// oidc provider url前缀：http://localhost:8080/realms/jeven
		issuerUrl := *issuer.TokenService
		excludeUriPartIndex := strings.Index(issuerUrl, utils.IssueProviderUri)
		providerUrlPrefix := issuerUrl[:excludeUriPartIndex]

		oidcClient := model.Client{
			Realm:             *realm,
			ClientId:          *client.ClientID,
			Secret:            *client.Secret,
			ProviderUrlPrefix: providerUrlPrefix,
		}
		utils.GetConfig().SsoProxyConfig.OidcClients = append(utils.GetConfig().SsoProxyConfig.OidcClients, oidcClient)
		hasRealmClient = true
		break
	}

	if !hasRealmClient {
		utils.Log().Info("No sso-proxy client configured in realm '" + *realm + "'")
	}
}

func clientExists(item *gocloak.Client, realm *string) bool {
	var clients = utils.GetConfig().SsoProxyConfig.OidcClients

	for _, c := range clients {
		if strings.EqualFold(*realm, c.Realm) && strings.EqualFold(*item.ClientID, c.ClientId) {
			return true
		}
	}
	return false
}
