package handler

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/Nerzal/gocloak/v11"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"sso-proxy/pkg/model"
	"sso-proxy/pkg/utils"
)

func HandleAuthCode(c *gin.Context) {
	realm, exists := c.GetQuery("realm")
	if !exists || len(realm) == 0 || utils.GetByRealm(realm) == nil {
		utils.Log().Warn("No valid client found for this realm", zap.String("realm", realm))
		utils.RedirectLogin(c)
		return
	}
	authCfg := utils.GetByRealm(realm)
	if authCfg == nil {
		utils.Log().Warn("No valid client retrieved from cache for this realm", zap.String("realm", realm))
		utils.RedirectLogin(c)
		return
	}

	state, err := utils.RandString(16)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	nonce, err := utils.RandString(16)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	maxAge := utils.GetConfig().SsoProxyConfig.SessionSetting.MaxAge

	// 设置临时cookie
	utils.SetCookie(c, utils.COOKIE_REALM_PARAM, realm, maxAge)
	utils.SetCookie(c, utils.COOKIE_STATE_PARAM, state, maxAge)
	utils.SetCookie(c, utils.COOKIE_NONCE_PARAM, nonce, maxAge)

	c.Redirect(http.StatusFound, authCfg.Oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)))
}

func HandleToken(c *gin.Context) {
	var state string
	var realm string
	var nonce string
	var err error
	if state, err = getCookie(c, utils.COOKIE_STATE_PARAM); err != nil {
		utils.RedirectLogin(c)
		return
	}
	if realm, err = getCookie(c, utils.COOKIE_REALM_PARAM); err != nil {
		utils.RedirectLogin(c)
		return
	}

	if nonce, err = getCookie(c, utils.COOKIE_NONCE_PARAM); err != nil {
		utils.RedirectLogin(c)
		return
	}

	authCfg := utils.GetByRealm(realm)
	if authCfg == nil {
		utils.Log().Warn("No valid client retrieved from cache for this realm", zap.String("realm", realm))
		utils.RedirectLogin(c)
		return
	}

	oauth2Token, err := authCfg.Oauth2Config.Exchange(context.Background(), c.Query("code"))
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to exchange token:%v", err.Error())
		return
	}

	rawIdToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		utils.Log().Warn("No id_token field in oauth2 token", zap.Any("rawIdToken", rawIdToken))
		return
	}

	idToken, err := authCfg.Verifier.Verify(context.Background(), rawIdToken)
	if err != nil {
		utils.Log().Warn("Failed to verify ID Token: ", zap.String("rawIdToken", rawIdToken),
			zap.Error(err))
		return
	}

	if idToken.Nonce != nonce {
		utils.Log().Warn("nonce did not match ", zap.String("idToken.Nonce", idToken.Nonce),
			zap.String("nonce", nonce))
		c.String(http.StatusBadRequest, "nonce did not match")
		return
	}

	// 清理cookie
	utils.SetCookie(c, utils.COOKIE_REALM_PARAM, realm, -1)
	utils.SetCookie(c, utils.COOKIE_STATE_PARAM, state, -1)
	utils.SetCookie(c, utils.COOKIE_NONCE_PARAM, "", -1)

	// utils.SetCookie(c, utils.COOKIE_TOKEN_PARAM, oauth2Token.AccessToken,
	// 	utils.GetConfig().SsoProxyConfig.SessionSetting.MaxAge)

	// 保存Session
	session := sessions.Default(c)
	session.Set(utils.OAUTH2_TOKEN, oauth2Token)
	session.Set(utils.OAUTH2_RAW_ID_TOKEN, rawIdToken)
	session.Set(utils.REALM_PARAM, realm)
	err = session.Save()

	if err != nil {
		utils.Log().Error("failed to save session", zap.Error(err))
		utils.RedirectLogin(c)
		return
	}

	utils.RedirectHome(c)
}

func GetUserInfo(c *gin.Context) {
	session := sessions.Default(c)
	oauth2Token := session.Get(utils.OAUTH2_TOKEN).(oauth2.Token)
	realm := session.Get(utils.REALM_PARAM).(string)
	userInfo, err := utils.GetByRealm(realm).Provider.UserInfo(context.Background(), oauth2.StaticTokenSource(&oauth2Token))
	if err != nil {
		c.String(http.StatusUnauthorized, "%v", err.Error())
		utils.Log().Warn("failed to get userinfo", zap.String("response", err.Error()),
			zap.Reflect("errorType", reflect.TypeOf(err)))
		return
	}
	utils.Log().Info("userInfo", zap.Any("data", userInfo))
	c.JSON(200, userInfo)
}

func Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	c.Status(http.StatusOK)
}

func GetAllClients(c *gin.Context) {
	// keycloak service account client
	kcClient := gocloak.NewClient(utils.GetConfig().SsoProxyConfig.Authenticators[0].Url,
		gocloak.SetAuthRealms("realms"),
		gocloak.SetAuthAdminRealms("admin/realms"))

	var masterClient *model.Client
	for _, client := range utils.GetConfig().SsoProxyConfig.OidcClients {
		if client.Realm == "master" {
			masterClient = &client
			break
		}
	}

	grantType := "client_credentials"
	token, err := kcClient.GetToken(context.Background(), "master", gocloak.TokenOptions{
		GrantType:    &grantType,
		ClientID:     &masterClient.ClientId,
		ClientSecret: &masterClient.Secret,
	})

	if err != nil {
		utils.Log().Warn("error", zap.Error(err))
		return
	}

	// realms, err := kcClient.GetRealms(context.Background(), token.AccessToken)
	var first = 0
	var max = 1000
	clients, err := kcClient.GetClients(context.Background(), token.AccessToken, "master", gocloak.GetClientsParams{
		First: &first,
		Max:   &max,
	})
	if err != nil {
		utils.Log().Warn("error", zap.Error(err))
		return
	}
	c.JSON(http.StatusOK, clients)
}

func getCookie(c *gin.Context, name string) (string, error) {
	state, err := c.Cookie(name)
	if err != nil {
		msg := fmt.Sprintf("%v not found", name)
		c.String(http.StatusBadRequest, msg)
		utils.Log().Warn(msg)
		return "", err
	}
	return state, err
}
