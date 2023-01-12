package middleware

import (
	"context"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
	"strings"

	"sso-proxy/pkg/utils"
)

// ValidateSession 拦截请求并对session和token的有效期进行校验
func ValidateSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		uri := c.Request.URL.Path
		method := c.Request.Method

		// 需要排除的请求，对应无需登录即可调用的url
		isPublic := isPublicUri(c)
		if isPublic {
			utils.Log().Debug("a request is permitted to call this public endpoint", zap.String("httpMethod", method),
				zap.String("uri", uri))
			c.Next()
			return
		}

		utils.Log().Debug("a request for non-public endpoint", zap.String("httpMethod", method),
			zap.String("uri", uri))

		session := sessions.Default(c)
		oauth2Token := session.Get(utils.Oauth2Token)

		// session中没有token(视为refresh_token失效时间到达),跳转登录页面
		if oauth2Token == nil {
			if utils.IsRestApi(uri) {
				//存在一种场景： 当session超时，但是token未超时，重新登录时，IAM上不需要输入用户名、密码即可登入
				utils.Log().Debug("session not found for calling rest api", zap.String("uri", uri))
				c.AbortWithStatus(http.StatusUnauthorized)
			} else {
				utils.Log().Debug("session not found for non-rest api and just redirect to login page", zap.String("uri", uri))
				utils.RedirectLogin(c)
			}
			return
		}

		rawToken := oauth2Token.(oauth2.Token)
		realm := session.Get(utils.RealmParam).(string)
		authCfg := utils.GetByRealm(realm)

		// 校验token是否真实
		// The refresh token lifetime is controlled by the SSO Session Idle Setting. 30 minutes = 30 * 60 = 1800 seconds (the refresh_expires_in value)
		// session不过期(视为没有到达refresh token expiry time)，但是token过期
		if !rawToken.Valid() {
			utils.Log().Debug("access token is expired, trying to refresh later", zap.String("uri", uri))
			oldRefreshToken := rawToken.RefreshToken
			if err := utils.RemoveFromSession(c, utils.Oauth2Token, true); err != nil {
				utils.Log().Error("Failed to remove old token from session", zap.Error(err), zap.String("uri", uri))
			}

			// refresh token
			ts := authCfg.Oauth2Config.TokenSource(context.Background(), &oauth2.Token{RefreshToken: oldRefreshToken})
			rawToken, err := ts.Token()
			if err != nil {
				utils.Log().Debug("No token retrieved while the refresh token may expired", zap.Error(err), zap.String(utils.RealmParam, realm),
					zap.String("uri", uri))
				if utils.IsRestApi(uri) {
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				utils.RedirectLogin(c)
				return
			}
			utils.Log().Debug("token refreshed", zap.String("old refresh token", oldRefreshToken), zap.String("uri", uri))

			// 将刷新后的session再保存到session中
			if err = utils.SetSession(c, utils.Oauth2Token, *rawToken, true); err != nil {
				utils.Log().Error("Failed to update refreshed token in session", zap.Error(err), zap.String("uri", uri))
				return
			}
		}

		//将当前session会话时间向后延
		updateSessionExpireTime(session, c)

		//如果session有效的清情况下，访问的是根路径则重定向到home首页
		if uri == "/" {
			utils.RedirectHome(c)
		}

		utils.Log().Debug("a valid request will be handled after session validation", zap.String("httpMethod", method),
			zap.String("uri", uri))
		c.Next()
	}
}

func updateSessionExpireTime(session sessions.Session, c *gin.Context) {
	//https: //github.com/gin-contrib/sessions/issues/68
	//将当前session会话时间向后延
	maxAge := utils.GetConfig().SsoProxyConfig.SessionSetting.MaxAge
	session.Options(sessions.Options{
		MaxAge: maxAge,
	})
	if err := session.Save(); err != nil {
		utils.Log().Error("failed to save session", zap.Error(err))
		return
	}
	utils.Log().Debug("update session timeout now", zap.Int("maxAge", maxAge))

	//https://blog.csdn.net/zhanghongxia8285/article/details/107321838
	//将当前session会话关联的cookie向后延
	if sessionCookie, err := c.Cookie(utils.CookieSessionName); err == nil {
		maxAge := utils.GetConfig().SsoProxyConfig.SessionSetting.MaxAge
		utils.SetCookie(c, utils.CookieSessionName, sessionCookie, maxAge)
		utils.Log().Debug("updated maxAge of session related cookie", zap.Int("maxAge", maxAge))
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
		// format: /proxy/{serviceName}/*** => segments[0]的值"", segments[1]的值"proxy",segments[2]的值"{serviceName}"
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
