package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"sso-proxy/pkg/utils"
)

// CheckSession 拦截请求并对session和token的失效期进行检测。
func CheckSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		uri := c.Request.URL.Path

		// 需要排除的请求，对应无需登录调用的url
		isPublic := isPublicUri(c)
		if isPublic {
			c.Next()
			return
		}

		session := sessions.Default(c)
		oauth2Token := session.Get(utils.Oauth2Token)

		// session中没有token(视为refresh_token失效时间到达),跳转登录页面
		if oauth2Token == nil {
			if utils.IsRestApi(uri) {
				c.AbortWithStatus(http.StatusUnauthorized)
			} else {
				utils.RedirectLogin(c)
			}
			return
		}

		rawToken := oauth2Token.(oauth2.Token)
		realm := session.Get(utils.RealmParam).(string)
		authCfg := utils.GetByRealm(realm)

		// token处于有效期，校验token是否真实
		if rawToken.Valid() {
			idToken := session.Get(utils.Oauth2RawIdToken).(string)
			verifiedIdToken, err := authCfg.Verifier.Verify(context.Background(), idToken)
			if err != nil {
				utils.Log().Error("Invalid id token", zap.Any("idToken", verifiedIdToken))
				if utils.IsRestApi(uri) {
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				utils.RedirectLogin(c)
				return
			}
			c.Next()
			return
		}

		// The refresh token lifetime is controlled by the SSO Session Idle Setting. 30 minutes = 30 * 60 = 1800 seconds (the refresh_expires_in value)
		// session不过期(视为没有到达refresh token expiry time)，但是token过期
		if !rawToken.Valid() {
			oldRefreshToken := rawToken.RefreshToken
			session.Delete("oauth2Token")

			// refresh token
			ts := authCfg.Oauth2Config.TokenSource(context.Background(), &oauth2.Token{RefreshToken: oldRefreshToken})
			rawToken, err := ts.Token()
			if err != nil {
				utils.Log().Error("Failed to refresh token", zap.Error(err), zap.String(utils.RealmParam, realm))
				if utils.IsRestApi(uri) {
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				utils.RedirectLogin(c)
				return
			}
			utils.Log().Info("token refreshed", zap.String("old refresh token", oldRefreshToken))
			session.Set(utils.Oauth2Token, *rawToken)
			c.Next()
		}
	}
}

// 判断当前Uri是否是public uri
func isPublicUri(c *gin.Context) bool {
	path := c.Request.URL.Path
	ssoProxyConfig := utils.GetConfig().SsoProxyConfig

	// 是否全局配置的public uris
	var isPublic = publicUriMatches(ssoProxyConfig.GlobalPublicUris, path)
	if !isPublic {

		// 必须是代理的请求才会被处理
		if !strings.HasPrefix(path, ssoProxyConfig.ReverseProxy.UrlPrefix) {
			return isPublic
		}

		// 每个route内部的public uris， 先根据uri获取对应的serviceName，再获取对应的route
		// format: /proxy/{serviceName}/***
		var serviceName string
		segments := strings.Split(path, utils.UrlSeparator)
		if len(segments) < 3 {
			return false
		}
		serviceName = segments[2]
		if len(serviceName) == 0 {
			return false
		}

		// 判断uri是否是配置文件中配置的public uri
		for _, route := range ssoProxyConfig.ReverseProxy.Routes {
			if route.ServiceName == serviceName {
				isPublic = publicUriMatches(route.PublicUris, path)
				break
			}
		}
	}
	return isPublic
}

func publicUriMatches(uris []string, specificUri string) bool {
	for _, publicUri := range uris {
		if glob.MustCompile(publicUri).Match(specificUri) {
			return true
		}
	}
	return false
}
