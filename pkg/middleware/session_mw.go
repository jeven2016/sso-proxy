package middleware

import (
	"context"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"sso-proxy/pkg/utils"
)

// CheckSession 拦截请求并对session和token的失效期进行检测。
func CheckSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		uri := c.Request.URL.Path

		// 需要排除的请求，对应无需登录调用的url
		publicUris := []string{"/auth", "/auth/callback", "/internal/clients"}

		// public uri不需要校验token
		ok := utils.Exists(publicUris, uri)
		if ok {
			c.Next()
			return
		}

		session := sessions.Default(c)
		oauth2Token := session.Get("oauth2Token")

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
		realm := session.Get(utils.REALM_PARAM).(string)
		authCfg := utils.GetByRealm(realm)

		// token处于有效期，校验token是否真实
		if rawToken.Valid() {
			idToken := session.Get(utils.OAUTH2_RAW_ID_TOKEN).(string)
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
				utils.Log().Error("Failed to refresh token", zap.Error(err), zap.String(utils.REALM_PARAM, realm))
				if utils.IsRestApi(uri) {
					c.AbortWithStatus(http.StatusUnauthorized)
					return
				}
				utils.RedirectLogin(c)
				return
			}
			utils.Log().Info("token refreshed", zap.String("old refresh token", oldRefreshToken))
			session.Set(utils.OAUTH2_TOKEN, *rawToken)
			c.Next()
		}
	}
}
