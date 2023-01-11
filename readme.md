
## Architecture
![Architecture](docs/architecture.png)

## 类似的开源项目
https://github.com/oauth2-proxy/oauth2-proxy

## API
- /auth/
- /proxy/{SERVICE}/
- /internal/**

## 编译可执行文件
+ 在linux环境编译可执行文件
```shell
go build cmd/sso-proxy.go

// 去除调试信息以减小二进制体积
// -s：忽略符号表和调试信息。
// -w：忽略DWARFv3调试信息，使用该选项后将无法使用gdb进行调试。
go build -ldflags="-s -w" -o sso-proxy cmd/sso-proxy.go

```

+ 编译其他环境可执行包
```shell
# linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/ cmd/sso-proxy.go

# linux arm
CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -o dist/ cmd/sso-proxy.go

# Mac
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/ cmd/sso-proxy.go

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/ cmd/sso-proxy.go

```


### 配置文件
#### Host参数的的正确使用
sso-proxy使用iamBaseUrl参数定义的URL去获取openid-connect对应的endpoints.  
之后生成的token，包含的issuer url，其Host与openid-connect endpoint中的Host相同。  
如果不一致，IAM会返回**invalid token**的错误。  

因此当routes中需要将请求转发到IAM服务时，请确Host属性与issuer url中的值一致。Host的值一般是  
IP：Port这种格式。 如果routes.url使用的是跟iamBaseUrl相同Host的URL，可以不设置 ‘- SetHeader: Host=xxx：8080’  
， 否则需要设置Host 属性，并且将值设置为跟iamBaseUrl相同的Host。  

+ 当申请token的地址和转发的地址，Host相同，就不需要添加SetHeader属性设置Host属性
```yaml

sso-proxy:
  ......
  iamBaseUrl: http://localhost:8080 # SSO相关的URL， 生成的Token中issue会包含此部分的Host属性(localhost：8080)

  reverseProxy:
    routes:
      - serviceName: iam
        url: http://localhost:8080 # sso-proxy向后端IAM转发的请求，使用了一个相同的地址(此时Host对应的是localhost:8080)
        ......
        filters:
          - SetBearerToken: Bearer=iam.accessToken
```

+ 如果申请token的地址和转发的地址，Host不同，就需要添加SetHeader属性设置 
```yaml

sso-proxy:
  ......
  iamBaseUrl: http://localhost:8080 # SSO相关的URL， 生成的Token中issue会包含此部分的Host属性(localhost：8080)

  reverseProxy:
    routes:
      - serviceName: iam
        url: http://192.168.159.129:8080/ # sso-proxy向后端IAM转发的请求，使用了一个不同的地址(此时Host对应的是192.168.159.129:8080)
        ......
        filters:
          - SetHeader: Host=localhost:8080 # !!!这里需要设置Host属性，确保是localhost:8080, IAM在比较Host时发现与token中的issue一致，会成功通过验证
          - SetBearerToken: Bearer=iam.accessToken


```