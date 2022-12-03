package model

// Config 统一配置
type Config struct {
	SsoProxyConfig SsoProxyConfig `mapstructure:"sso-proxy"`
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
	Port                int             `mapstructure:"port"`
	BindAddress         string          `mapstructure:"bindAddress"`
	SessionSetting      SessionSetting  `mapstructure:"sessionSetting"`
	OidcAuthCallbackUrl string          `mapstructure:"oidcAuthCallbackUrl"`
	OidcScopes          []string        `mapstructure:"oidcScopes"`
	OidcClients         []Client        `mapstructure:"oidcClients"`
	EnableDevFeatures   bool            `mapstructure:"enableDevFeatures"`
	Authenticators      []Authenticator `mapstructure:"authenticators"`
	Apps                []App           `mapstructure:"apps"`
	ReverseProxy        ReverseProxy    `mapstructure:"reverseProxy"`
	LogSetting          LogSetting      `mapstructure:"logSetting"`
}

type PageParam struct {
	First int `mapstructure:"first"`
	Max   int `mapstructure:"max"`
}

type SyncClients struct {
	EnabledOnStartup bool      `mapstructure:"enabledOnStartup"`
	PageParam        PageParam `mapstructure:"pageParam"`
}

// Authenticator 校验器, 当前只支持keycloak
type Authenticator struct {
	Type        string      `mapstructure:"type"`
	Name        string      `mapstructure:"name"`
	Url         string      `mapstructure:"url"`
	SyncClients SyncClients `mapstructure:"syncClients"`
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
	ServiceName string            `mapstructure:"serviceName"`
	Url         string            `mapstructure:"url"`
	Filters     map[string]string `mapstructure:"filters"`
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
	UrlPrefix     string        `mapstructure:"urlPrefix"`
	Routes        []Route       `mapstructure:"routes"`
	HttpTransport HttpTransport `mapstructure:"httpTransport"`
}

// Validate 校验参数
func (c *Config) Validate() error {
	return nil
}
