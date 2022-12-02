package proxyfilters

import (
	"net/http"

	"sso-proxy/pkg/utils"
)

type FilterFunc func(request *http.Request, response *http.Response, value string)

var filterMap = map[string]FilterFunc{}

func init() {
	filterMap[utils.FILTER_SET_HEADER] = SetHeader
}

func GetFilter(key string) FilterFunc {
	if filterFunc, ok := filterMap[key]; ok {
		return filterFunc
	}
	return nil
}
