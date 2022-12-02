package startup

import (
	"encoding/gob"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"sso-proxy/pkg/handler"
	"sso-proxy/pkg/middleware"
	"sso-proxy/pkg/model"
	"sso-proxy/pkg/utils"
)

// InitWebServer Start a web server
func InitWebServer() *gin.Engine {
	registerGobType()
	store := memstore.NewStore([]byte("secret"))

	// store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   utils.GetConfig().SsoProxyConfig.SessionSetting.MaxAge,
		Secure:   false,
		HttpOnly: true,
	})

	var engine = gin.Default()
	engine.Use(sessions.Sessions("session", store))
	engine.Use(middleware.CheckSession(),
		middleware.GinLogger(),
		middleware.GinRecovery(utils.GetConfig().SsoProxyConfig.EnableDevFeatures))

	gin.SetMode(gin.ReleaseMode)

	engine.GET("/", func(c *gin.Context) {
		utils.RedirectHome(c)
		return
	})

	// refresh token
	// ts := oauth2Config.TokenSource(context.Background(), &oauth2.Token{RefreshToken: ""})
	// tok, err := ts.Token()
	engine.GET("/auth", handler.HandleAuthCode)

	// https://blog.csdn.net/zhanghongxia8285/article/details/107321838
	engine.GET("/auth/callback", handler.HandleToken)

	engine.GET("/auth/userinfo", handler.GetUserInfo)
	engine.POST("/auth/logout", handler.Logout)

	// 该服务内部提供的功能接口
	engine.GET("/internal/clients", handler.GetAllClients)

	// 需要代理的请求
	engine.Any("/proxy/:serviceName/*proxyPath", handler.Proxy)

	return engine
}

func registerGobType() {
	// 使用sessions 中间件注意要点：
	// session 仓库其实就是一个 map[interface]interface 对象，所有 session可以存储任意数据
	// session 使用的编解码器是自带的gob，所以存储类似： struct、map 这些对象时需要先注册对象，不然会报错 gob: type not registered for...
	// session 存储引擎支持： cookie、内存、mongodb、redis、postgres、memstore、memcached 以及 gorm 支持的各类数据库（mysql、sqlite）
	// session 在创建时有一个配置项，可以配置session过期时间、cookie、domain、secure、path等参数
	// 调用 session 方法： Set()、 Delete()、 Clear()、方法后，必须调用一次 Save() 方法。否则session数据不会更新
	gob.Register(model.Session{})
	gob.Register(time.Time{})
	gob.Register(oauth2.Token{})
	gob.Register(oidc.UserInfo{})
	gob.Register(oidc.IDToken{})
}