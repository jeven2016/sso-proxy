package handler

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"sso-proxy/pkg/model"
	"sso-proxy/pkg/proxyfilters"
	"sso-proxy/pkg/utils"
)

func Proxy(c *gin.Context) {
	proxySetting := utils.GetConfig().SsoProxyConfig.ReverseProxy
	serviceName := c.Param("serviceName")

	var serviceRoute *model.Route
	for _, route := range proxySetting.Routes {
		if strings.EqualFold(serviceName, route.ServiceName) {
			serviceRoute = &route
			break
		}
	}
	if serviceRoute == nil {
		utils.Log().Warn("no valid route found", zap.String("serviceName", serviceName))
		c.AbortWithError(http.StatusBadRequest, errors.New("no valid route found"))
		return
	}

	parsedUrl, err := url.Parse(serviceRoute.Url)
	if err != nil {
		utils.Log().Warn("invalid reverseProxy.routes.route.url", zap.String("url", serviceRoute.Url),
			zap.Error(err))
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	httpTransport := proxySetting.HttpTransport
	var transport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(httpTransport.Timeout) * time.Second,
			KeepAlive: time.Duration(httpTransport.KeepAlive) * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          httpTransport.MaxIdleConnections,
		IdleConnTimeout:       time.Duration(httpTransport.IdleConnectionTimeout) * time.Second,
		TLSHandshakeTimeout:   time.Duration(httpTransport.Tls.HandShakeTimeout) * time.Second,
		ExpectContinueTimeout: time.Duration(httpTransport.Tls.ExpectContinueTimeout) * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: httpTransport.Tls.InsecureSkipVerify},
	}

	proxy := httputil.NewSingleHostReverseProxy(parsedUrl)
	proxy.Transport = transport
	originDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originDirector(req)
		req.Method = c.Request.Method
		req.Header = c.Request.Header
		req.URL.Scheme = parsedUrl.Scheme
		req.URL.Host = parsedUrl.Host
		req.URL.Path = c.Param("proxyPath")
		handleFilters(req, serviceRoute.Filters)
	}

	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		reqUrl := request.URL.String()
		utils.Log().Error("proxy error occurs", zap.Error(err), zap.String("url", reqUrl),
			zap.String("method", request.Method))
		writer.WriteHeader(http.StatusServiceUnavailable)
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

// 处理过滤器
func handleFilters(req *http.Request, filters map[string]string) {
	for key, value := range filters {
		if filter := proxyfilters.GetFilter(key); filter != nil {
			filter(req, nil, value)
		}
	}
}