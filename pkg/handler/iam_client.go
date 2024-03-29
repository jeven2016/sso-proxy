package handler

import (
	"crypto/tls"
	"github.com/Nerzal/gocloak/v11"
	"sso-proxy/pkg/model"
	"sso-proxy/pkg/utils"
)

type IamClient struct {
	masterClient    *gocloak.GoCloak
	masterClientCfg *model.Client
}

var iamClient *IamClient

func NewIamClient() *IamClient {
	iamClient = &IamClient{}
	return iamClient
}

// InitMasterClient 初始化一个master realm下的sso-proxy client，以便能够以service account方式操纵IAM的内部资源
func (c *IamClient) InitMasterClient(clients []*model.Client,
	authenticator *model.Authenticator) (*gocloak.GoCloak, *model.Client) {
	var masterClientCfg *model.Client
	for _, client := range clients {
		if client.Realm == utils.IamMasterRealm {
			masterClientCfg = client
			break
		}
	}

	if masterClientCfg == nil {
		utils.Log().Fatal("[!!!] no master client configured in config.yaml that means lacking ways to " +
			"figure out what realms and clients configured in IAM side")
		return nil, nil
	}

	// keycloak service account client
	kcClient := gocloak.NewClient(authenticator.Url,
		gocloak.SetAuthRealms(utils.AuthRealm),
		gocloak.SetAuthAdminRealms(utils.AuthAdminRealms))

	//skip (X509) certificate validation in gocloak
	restyClient := kcClient.RestyClient()
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	c.masterClient = &kcClient
	c.masterClientCfg = masterClientCfg
	return c.masterClient, c.masterClientCfg
}
