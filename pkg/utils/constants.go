package utils

const ClientId = "sso-proxy"

const (
	RealmParam       = "realm"
	Oauth2Token      = "oauth2Token"
	Oauth2RawIdToken = "rawIdToken"

	CookieSessionName = "SSO-PROXY"
	CookieRealmParam  = "realm"
	CookieStateParam  = "state"
	CookieNonceParam  = "nonce"
)

const (
	SPACE         = " "
	UrlSeparator  = "/"
	VarIamBaseUrl = "${iamBaseUrl}"
)

const (
	// FilterSetHeader https://github.com/spf13/viper/issues/1014
	// viper将下列key序列化成map时，key会全部为小写, 故这里的key全部使用小写进行规避
	FilterSetHeader      = "setheader"
	FilterSetBearerToken = "setbearertoken"
	HeaderAuthorization  = "Authorization"
	HeaderHost           = "Host"
)

const (
	ValueIamAccesstoken = "iam.accessToken"
)

const (
	IamMasterRealm   = "master"
	AuthRealm        = "realms"
	AuthAdminRealms  = "admin/realms"
	IssueProviderUri = "/protocol/openid-connect"
)
