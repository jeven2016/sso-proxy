package model

import (
	"bytes"
	"text/template"
)

// Config 统一配置
type Config struct {
	SsoProxyConfig *SsoProxyConfig `mapstructure:"sso-proxy"`
}

// LogSetting 日志相关配置
type LogSetting struct {
	LogLevel      string `mapstructure:"logLevel"`
	LogPath       string `mapstructure:"logPath"`
	OutputConsole bool   `mapstructure:"outputToConsole"`
	FileName      string `mapstructure:"fileName"`
	MaxSizeInMB   int    `mapstructure:"maxSizeInMB"`
	MaxAgeInDay   int    `mapstructure:"maxAgeInDay"`
	MaxBackups    int    `mapstructure:"maxBackups"`
	Compress      bool   `mapstructure:"compress"`
}

type SessionSetting struct {
	MaxAge int `mapstructure:"maxAge"`
}

// SsoProxyConfig SSO统一配置
type SsoProxyConfig struct {
	Port                int              `mapstructure:"port"`
	BindAddress         string           `mapstructure:"bindAddress"`
	SessionSetting      SessionSetting   `mapstructure:"sessionSetting"`
	IamBaseUrl          string           `mapstructure:"iamBaseUrl"`
	InternalIamBaseUrl  string           `mapstructure:"internalIamBaseUrl"`
	OidcAuthCallbackUrl string           `mapstructure:"oidcAuthCallbackUrl"`
	GlobalPublicUris    []string         `mapstructure:"globalPublicUris"`
	OidcScopes          []string         `mapstructure:"oidcScopes"`
	OidcClients         []*Client        `mapstructure:"oidcClients"`
	EnableDevFeatures   bool             `mapstructure:"enableDevFeatures"`
	Authenticators      []*Authenticator `mapstructure:"authenticators"`
	Apps                []*App           `mapstructure:"apps"`
	ReverseProxy        *ReverseProxy    `mapstructure:"reverseProxy"`
	LogSetting          *LogSetting      `mapstructure:"logSetting"`
}

type PageParam struct {
	First int `mapstructure:"first"`
	Max   int `mapstructure:"max"`
}

type RegisterSetting struct {
	ClientId               string   `mapstructure:"clientId"`
	Name                   string   `mapstructure:"name"`
	GenerateSecret         bool     `mapstructure:"generateSecret"`
	Secret                 string   `mapstructure:"secret"`
	Enabled                bool     `mapstructure:"enabled"`
	StandardFlowEnabled    bool     `mapstructure:"standardFlowEnabled"`
	ServiceAccountsEnabled bool     `mapstructure:"serviceAccountsEnabled"`
	WebOrigin              []string `mapstructure:"webOrigin"`
	RedirectURIs           []string `mapstructure:"redirectURIs"`
}

type SyncClients struct {
	EnabledOnStartup bool             `mapstructure:"enabledOnStartup"`
	AutoRegister     bool             `mapstructure:"autoRegister"`
	RegisterSetting  *RegisterSetting `mapstructure:"registerSetting"`
	PageParam        *PageParam       `mapstructure:"pageParam"`
}

// Authenticator 校验器, 当前只支持keycloak
type Authenticator struct {
	Type        string       `mapstructure:"type"`
	Name        string       `mapstructure:"name"`
	Url         string       `mapstructure:"url"`
	SyncClients *SyncClients `mapstructure:"syncClients"`
}

// App 对接的应用
type App struct {
	AppId     string `mapstructure:"appId"`
	LoginPage string `mapstructure:"loginPage"`
	HomePage  string `mapstructure:"homePage"`
	GrantType string `mapstructure:"grantType"`
}

type Client struct {
	Realm             string `mapstructure:"realm"`
	ClientId          string `mapstructure:"clientId"`
	Secret            string `mapstructure:"secret"`
	ProviderUrlPrefix string `mapstructure:"providerUrlPrefix"`
}

type Route struct {
	ServiceName      string            `mapstructure:"serviceName"`
	Url              string            `mapstructure:"url"`
	MirroringRequest bool              `mapstructure:"mirroringRequest"`
	PublicUris       []string          `mapstructure:"publicUris"`
	Filters          map[string]string `mapstructure:"filters"`
}

type Tls struct {
	HandShakeTimeout      int  `mapstructure:"handShakeTimeout"`
	ExpectContinueTimeout int  `mapstructure:"expectContinueTimeout"`
	InsecureSkipVerify    bool `mapstructure:"insecureSkipVerify"`
}

type HttpTransport struct {
	Timeout               int `mapstructure:"urlPrefix"`
	KeepAlive             int `mapstructure:"keepAlive"`
	MaxIdleConnections    int `mapstructure:"maxIdleConnections"`
	IdleConnectionTimeout int `mapstructure:"idleConnectionTimeout"`
	Tls                   Tls `mapstructure:"tls"`
}

type ReverseProxy struct {
	UrlPrefix     string         `mapstructure:"urlPrefix"`
	Routes        []*Route       `mapstructure:"routes"`
	HttpTransport *HttpTransport `mapstructure:"httpTransport"`
}

// Validate 校验参数
func (c *Config) Validate() error {
	return nil
}

// Complete 加载完成后的处理
func (c *Config) Complete() error {
	var err error
	proxyConfig := c.SsoProxyConfig

	//url中如果存在template字符串则进行特殊处理
	internalIamBaseUrl, err := parseTemplate(c.SsoProxyConfig.InternalIamBaseUrl, proxyConfig)
	if err != nil {
		return err
	}
	c.SsoProxyConfig.InternalIamBaseUrl = internalIamBaseUrl

	for _, client := range c.SsoProxyConfig.OidcClients {
		prefix, err := parseTemplate(client.ProviderUrlPrefix, proxyConfig)
		if err != nil {
			return err
		}
		client.ProviderUrlPrefix = prefix
	}

	for _, authenticator := range c.SsoProxyConfig.Authenticators {
		authUrl, err := parseTemplate(authenticator.Url, proxyConfig)
		if err != nil {
			return err
		}
		authenticator.Url = authUrl
	}

	for _, route := range c.SsoProxyConfig.ReverseProxy.Routes {
		routeUrl, err := parseTemplate(route.Url, proxyConfig)
		if err != nil {
			return err
		}
		route.Url = routeUrl
	}

	return nil
}

// ParseTemplate 如果值是template字符串，则解析后返回。 提供了一个value函数
func parseTemplate(value string, cfg *SsoProxyConfig) (string, error) {
	tmpl, err := template.New("urlTemplate").Funcs(template.FuncMap{
		"value": func(baseUrl string, defaultUrl string) string {
			if len(baseUrl) > 0 {
				return baseUrl
			}
			return defaultUrl
		},
	}).Parse(value)
	if err != nil {
		return "", err
	}
	var tmpBytes bytes.Buffer
	err = tmpl.Execute(&tmpBytes, cfg)
	if err != nil {
		return "", err
	}
	return tmpBytes.String(), nil
}
