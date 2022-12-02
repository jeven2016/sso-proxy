package utils

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"

	"github.com/duke-git/lancet/v2/slice"
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

func RedirectLogin(c *gin.Context) {
	c.Redirect(302, GetApp().LoginPage)
}

func RedirectHome(c *gin.Context) {
	c.Redirect(302, GetApp().HomePage)
}

func IsRestApi(uri string) bool {
	return strings.HasPrefix(uri, "/api/") ||
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
