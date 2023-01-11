package proxyfilters

import (
	"go.uber.org/zap"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"sso-proxy/pkg/utils"
)

// SetBearerToken ,在http header中添加bearer token
func SetBearerToken(request *http.Request, _ *http.Response, c *gin.Context, value string) {
	// "SetBearerToken: Bearer=iam.accessToken #iam.accessToken or openstack.accessToken"
	entrySet := parseEntrySet(value)
	for key, v := range entrySet {
		// 设置IAM的access token
		if strings.EqualFold(v, utils.ValueIamAccesstoken) {
			session := sessions.Default(c)
			token := session.Get(utils.Oauth2Token)
			if token != nil {
				oauth2Token := token.(oauth2.Token)
				iamAccessToken := key + " " + oauth2Token.AccessToken
				utils.Log().Debug("set bearer token for "+request.URL.String(), zap.String(utils.HeaderAuthorization, iamAccessToken))
				request.Header.Set(utils.HeaderAuthorization, iamAccessToken)
			}
		}
	}
}
