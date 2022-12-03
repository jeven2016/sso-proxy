package proxyfilters

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"sso-proxy/pkg/utils"
)

type FilterFunc func(request *http.Request, response *http.Response, c *gin.Context, value string)

var filterMap = map[string]FilterFunc{}

func init() {
	filterMap[utils.FilterSetHeader] = SetHeader
	filterMap[utils.FilterSetBearerToken] = SetBearerToken
}

func GetFilter(key string) FilterFunc {
	if filterFunc, ok := filterMap[key]; ok {
		return filterFunc
	}
	return nil
}

func parseEntrySet(value string) map[string]string {
	entrySetMap := map[string]string{}
	if len(value) == 0 {
		return entrySetMap
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
		entrySetMap[key] = val
	}
	return entrySetMap
}
