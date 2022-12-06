package startup

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Nerzal/gocloak/v11"
	"go.uber.org/zap"

	"sso-proxy/pkg/handler"
	"sso-proxy/pkg/model"
	"sso-proxy/pkg/utils"
)

func SyncClients() {
	authenticator := utils.GetAuthenticator()
	if !authenticator.SyncClients.EnabledOnStartup {
		utils.Log().Info("client sync is ignored")
		return
	}

	iamClient := handler.NewIamClient()

	// 初始化一个master realm下的sso-proxy client
	masterClient, masterClientCfg := iamClient.InitMasterClient(utils.GetConfig().SsoProxyConfig.OidcClients,
		authenticator)

	if masterClient == nil || masterClientCfg == nil {
		utils.Log().Error("Failed to initialize a sso-proxy for master realm, the step 'SyncClients' is aborted")
		return
	}

	// 申请master realm下service account的token
	token, err := getServiceAccountToken(masterClient, masterClientCfg)
	if err != nil {
		logInitError(masterClientCfg, err)
		os.Exit(1)
		return
	}

	// 获取所有的realm
	results, err := (*masterClient).GetRealms(context.Background(), token.AccessToken)
	if err != nil {
		utils.Log().Error("Failed to retrieve all realms", zap.String("token", token.AccessToken),
			zap.Error(err))
		return
	}

	for _, realmRepresentation := range results {
		// 获取realm下sso-proxy的client配置
		syncRealmClients(masterClient, context.Background(),
			token, realmRepresentation.Realm, authenticator)
	}
	msg := fmt.Sprintf("Completed looking for registered clients(sso-proxy), %v sso-proxy clients in %v realms",
		len(utils.GetConfig().SsoProxyConfig.OidcClients),
		len(results))
	utils.Log().Info(msg)
}

func getServiceAccountToken(masterClient *gocloak.GoCloak, masterClientCfg *model.Client) (*gocloak.JWT, error) {
	grantType := "client_credentials"
	token, err := (*masterClient).GetToken(context.Background(),
		utils.IamMasterRealm, gocloak.TokenOptions{
			GrantType:    &grantType,
			ClientID:     &masterClientCfg.ClientId,
			ClientSecret: &masterClientCfg.Secret,
		})
	return token, err
}

func logInitError(masterClientCfg *model.Client, err error) {
	// 在日志中隐藏真实的secret，只提示是否为空
	var secretDesc = "[Blank]"
	if len(masterClientCfg.Secret) > 0 {
		secretDesc = "[Not Blank]"
	}

	utils.Log().Error("Failed to generate a token for service account", zap.Error(err), zap.String("realm", "master"),
		zap.String("clientId", masterClientCfg.ClientId), zap.String("secret", secretDesc),
		zap.String("providerUrlPrefix", masterClientCfg.ProviderUrlPrefix))
}

func syncRealmClients(kcClient *gocloak.GoCloak, ctx context.Context, token *gocloak.JWT, realm *string, authenticator *model.Authenticator) {
	thisClientId := utils.ClientId

	// Todo: master service account 无法获取其他realm下的client
	clients, err := (*kcClient).GetClients(ctx, token.AccessToken, *realm,
		gocloak.GetClientsParams{ClientID: &thisClientId, First: &authenticator.SyncClients.PageParam.First,
			Max: &authenticator.SyncClients.PageParam.Max})

	if err != nil {
		utils.Log().Error("Failed to retrieve clients for realm "+*realm, zap.Error(err))
		return
	}

	var hasRealmClient bool
	var ignoreClient bool
	for _, client := range clients {
		// 只关注sso-proxy client
		if *client.ClientID != utils.ClientId {
			continue
		}

		ignoreClient = hasOverlap(realm)

		issuer, err := (*kcClient).GetIssuer(ctx, *realm)
		if err != nil {
			utils.Log().Error("Failed to retrieve issuer url in realm "+*realm, zap.Error(err))
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
		appendOidcClient(oidcClient)
		hasRealmClient = true
		break
	}

	if !hasRealmClient && !ignoreClient {
		utils.Log().Info("No sso-proxy client configured in realm '" + *realm + "'")
		registerNewClient(kcClient, authenticator, token, realm)
	}
}

// 判断本地配置文件中是否已经配置了该oidcClient, 而且IAM上在对应的realm下也存在同名的client
func hasOverlap(realm *string) bool {
	// 如果配置文件中在对应的realm定义了该client, 则使用配置文件中的设定,不需要再重新创建一个model.Client
	for _, c := range utils.GetConfig().SsoProxyConfig.OidcClients {
		if c.Realm == *realm {
			return true
		}
	}
	return false
}

func appendOidcClient(oidcClient model.Client) {
	utils.GetConfig().SsoProxyConfig.OidcClients = append(utils.GetConfig().SsoProxyConfig.OidcClients, oidcClient)
}

func registerNewClient(kcClient *gocloak.GoCloak, authenticator *model.Authenticator, token *gocloak.JWT, realm *string) {
	if authenticator.SyncClients.AutoRegister {
		// 如果realm下没有client，自动注册一个
		registerSetting := authenticator.SyncClients.RegisterSetting

		// 如果需要自动生成secret，则生成
		var defaultSecret = registerSetting.Secret
		if registerSetting.GenerateSecret {
			secret, err := utils.RandString(16)
			if err != nil {
				utils.Log().Error("Failed to generate a client secret", zap.Error(err))
				return
			}
			defaultSecret = secret
		}

		// https://keycloak.discourse.group/t/invalid-realm-configuration-acr-loa-map-after-update-to-19-0-1/17332/7
		var attributes = map[string]string{
			"acr.loa.map": "{}",
		}

		realmId, err := (*kcClient).CreateClient(context.Background(), token.AccessToken, *realm, gocloak.Client{
			ClientID:               &registerSetting.ClientId,
			Name:                   &registerSetting.Name,
			Secret:                 &defaultSecret,
			Enabled:                &registerSetting.Enabled,
			StandardFlowEnabled:    &registerSetting.StandardFlowEnabled,
			ServiceAccountsEnabled: &registerSetting.ServiceAccountsEnabled,
			WebOrigins:             &registerSetting.WebOrigin,
			RedirectURIs:           &registerSetting.RedirectURIs,
			Attributes:             &attributes,
		})
		if err != nil {
			utils.Log().Error("Failed to register a client", zap.String("clientId", registerSetting.ClientId),
				zap.String("realm", *realm))
			return
		}
		utils.Log().Info("Registered a client automatically for this realm", zap.String("clientId", registerSetting.ClientId),
			zap.String("realm", *realm), zap.String("realmId", realmId))

		providerUrlPrefix := strings.TrimRight(authenticator.Url, utils.UrlSeparator) +
			utils.UrlSeparator + "realms/" + *realm

		oidcClient := model.Client{
			Realm:             *realm,
			ClientId:          registerSetting.ClientId,
			Secret:            registerSetting.Secret,
			ProviderUrlPrefix: providerUrlPrefix,
		}
		appendOidcClient(oidcClient)
	}
}
