package proxyfilters

import (
	"net/http"
	"strings"

	"sso-proxy/pkg/utils"
)

// SetHeader filter
// 解析字符串： SetHeader: Host=www.test.com, X-Forwared-Host=www.test.com
// 然后设置http header
func SetHeader(request *http.Request, _ *http.Response, value string) {
	if len(value) == 0 {
		return
	}
	// parse:  key=value,key2=value2
	segments := strings.Split(value, ",")
	for _, segment := range segments {
		segment = strings.Trim(segment, utils.SPACE)
		if len(segment) == 0 {
			continue
		}
		// parse: key=value
		items := strings.Split(segment, "=")
		if len(items) < 2 {
			continue
		}
		key := strings.Trim(items[0], utils.SPACE)
		val := strings.Trim(items[1], utils.SPACE)

		if len(key) == 0 || len(val) == 0 {
			continue
		}
		request.Header.Set(key, val)
	}
}
