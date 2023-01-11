package proxyfilters

import (
	"go.uber.org/zap"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"sso-proxy/pkg/utils"
)

// SetHeader filter
// 解析字符串： SetHeader: Host=www.test.com, X-Forwarded-Host=www.test.com
// 然后逐项设置http header
func SetHeader(request *http.Request, _ *http.Response, c *gin.Context, value string) {
	// parse:  key=value,key2=value2
	entrySet := parseEntrySet(value)
	for key, val := range entrySet {
		if strings.EqualFold(key, utils.HeaderHost) {
			// https://github.com/golang/go/issues/28168
			// 如果直接通过header设置Host无法生效
			request.Host = val
			utils.Log().Debug("set host header for "+request.URL.String(), zap.String("host", val))
		} else {
			request.Header.Set(key, val)
		}
	}
}
