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

// Proxy 反向代理其他服务的请求，并确保设置了对应的http头或access token
func Proxy(c *gin.Context) {
	proxyUrl := c.Request.URL.String()
	utils.Log().Debug("A request incoming", zap.String("url", proxyUrl))
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
		utils.Log().Warn("no valid route found", zap.String("serviceName", serviceName), zap.String("url", proxyUrl))
		c.AbortWithError(http.StatusBadRequest, errors.New("no valid route found for "+serviceName))
		return
	}

	forwardRequest(c, serviceRoute, proxySetting)
}

// 向后端服务转发请求
func forwardRequest(c *gin.Context, serviceRoute *model.Route, proxySetting model.ReverseProxy) {
	parsedUrl, err := url.Parse(serviceRoute.Url)
	if err != nil {
		utils.Log().Warn("invalid reverseProxy.routes.route.url", zap.String("url", serviceRoute.Url),
			zap.Error(err))
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	transport := initHttpTransport(proxySetting)

	proxy := httputil.NewSingleHostReverseProxy(parsedUrl)
	proxy.Transport = transport
	originDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		updateRequest(req, originDirector, c, parsedUrl, serviceRoute)
	}

	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, err error) {
		reqUrl := request.URL.String()
		utils.Log().Error("proxy error occurs", zap.Error(err), zap.String("url", reqUrl),
			zap.String("method", request.Method))
		writer.WriteHeader(http.StatusServiceUnavailable)
	}

	// 添加response
	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Set("proxy-server", "SSO-PROXY v0.0.1")
		return nil
	}

	proxy.ServeHTTP(c.Writer, c.Request)
}

//更新转发后的请求对象
func updateRequest(req *http.Request, originDirector func(*http.Request), c *gin.Context,
	parsedUrl *url.URL, serviceRoute *model.Route) {
	originDirector(req)
	req.Method = c.Request.Method
	req.Header = c.Request.Header
	req.URL.Scheme = parsedUrl.Scheme
	req.URL.Host = parsedUrl.Host
	req.URL.Path = c.Param("proxyPath")

	//执行过滤器处理
	handleFilters(req, serviceRoute.Filters, c)
}

//初始化http请求
func initHttpTransport(proxySetting model.ReverseProxy) http.RoundTripper {
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
	return transport
}

// 处理过滤器
func handleFilters(req *http.Request, filters map[string]string, c *gin.Context) {
	for key, value := range filters {
		if filter := proxyfilters.GetFilter(key); filter != nil {
			if len(value) > 0 {
				filter(req, nil, c, value)
			}
		}
	}
}
