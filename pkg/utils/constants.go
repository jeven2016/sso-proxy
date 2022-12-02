package utils

const (
	REALM_PARAM         = "realm"
	OAUTH2_TOKEN        = "oauth2Token"
	OAUTH2_RAW_ID_TOKEN = "rawIdToken"
	SESSION_USER_INFO   = "userInfo"

	COOKIE_REALM_PARAM = "realm"
	COOKIE_STATE_PARAM = "state"
	COOKIE_NONCE_PARAM = "nonce"
	COOKIE_TOKEN_PARAM = "token"
)

const (
	URL_SEPERATOR = "/"
	SPACE         = " "
)

const (
	// FILTER_SET_HEADER https://github.com/spf13/viper/issues/1014
	// viper将下列key序列化成map时，key会全部为小写, 故这里的key全部使用小写进行规避
	FILTER_SET_HEADER = "setheader"
)
