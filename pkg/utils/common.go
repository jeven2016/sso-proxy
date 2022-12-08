package utils

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"

	"github.com/duke-git/lancet/v2/slice"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"sso-proxy/pkg/model"
)

func RandString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func GetApp() *model.App {
	return &GetConfig().SsoProxyConfig.Apps[0]
}

func GetAuthenticator() *model.Authenticator {
	authenticators := GetConfig().SsoProxyConfig.Authenticators
	if len(authenticators) == 0 {
		panic("There should be any authenticators defined")
	}
	authenticator := authenticators[0]
	authenticator.Url = constructProviderUrl(authenticator.Url)
	return &authenticator
}

func RedirectLogin(c *gin.Context) {
	c.Redirect(302, GetApp().LoginPage)
	c.Abort()
}

func RedirectHome(c *gin.Context) {
	c.Redirect(302, GetApp().HomePage)
	c.Abort()
}

func IsRestApi(uri string) bool {
	proxyPrefix := GetConfig().SsoProxyConfig.ReverseProxy.UrlPrefix
	return strings.HasPrefix(uri, proxyPrefix) ||
		strings.HasPrefix(uri, "/auth/userinfo") ||
		strings.HasPrefix(uri, "/internal/")
}

func SetCookie(c *gin.Context, name string, value string, maxAge int) {
	c.SetCookie(name, value, maxAge, "/", "", false, true)
}

func Exists(array []string, value string) bool {
	checkExists := func(_ int, item string) bool {
		return value == item
	}

	_, exists := slice.Find(array, checkExists)
	return exists
}

func GetRealm(session *sessions.Session) string {
	return (*session).Get(RealmParam).(string)
}

// 将provider url中的变量替换成真正的地址
func constructProviderUrl(providerUrl string) string {
	return strings.ReplaceAll(providerUrl, VarIamBaseUrl, GetConfig().
		SsoProxyConfig.IamBaseUrl)
}

func SetSession(ctx *gin.Context, key string, value any, saveImmediately bool) error {
	session := sessions.Default(ctx)
	session.Set(key, value)
	if saveImmediately {
		return session.Save()
	}
	return nil
}

func RemoveFromSession(ctx *gin.Context, key string, saveImmediately bool) error {
	session := sessions.Default(ctx)
	session.Delete(key)
	if saveImmediately {
		return session.Save()
	}
	return nil
}
