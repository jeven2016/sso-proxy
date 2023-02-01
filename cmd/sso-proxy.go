package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/duke-git/lancet/v2/fileutil"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"sso-proxy/pkg/startup"
	"sso-proxy/pkg/utils"
)

const banner string = `
   _____ _____  ____         _____  _____   ______   ____     __
  / ____/ ____|/ __ \       |  __ \|  __ \ / __ \ \ / /\ \   / /
 | (___| (___ | |  | |______| |__) | |__) | |  | \ V /  \ \_/ /
  \___ \\___ \| |  | |______|  ___/|  _  /| |  | |> <    \   /
  ____) |___) | |__| |      | |    | | \ \| |__| / . \    | |
 |_____/_____/ \____/       |_|    |_|  \_\\____/_/ \_\   |_|
A centralized SSO service to proxy any sso requests sent from different 3rd party application (version: 0.0.1)`

// 启动web服务
func main() {
	run()
}

func PrintBanner() {
	fmt.Println(banner)
}

// 使用命令行启动server
func run() {
	var rootCmd = &cobra.Command{
		Version: "0.0.1",
		Use:     "sso-proxy [command]",
		Short:   "sso-proxy CLI",
		Long:    `sso-proxy can proxy the requests sent to IAM and perform standard OIDC flow to interact with IAM`,
		Args:    cobra.MinimumNArgs(1),
	}

	var startServerCmd = &cobra.Command{
		Use:   "start ",
		Short: "start a web server to handle HTTP requests",
		Long:  `start a web server to handle HTTP requests and perform standard OIDC flow to interact with IAM`,
		Run: func(cmd *cobra.Command, args []string) {
			start(cmd)
		},
	}

	// 配置文件的绝对路径
	startServerCmd.Flags().StringP("configFile", "c", "", "the absolute path of config file that in yaml format")

	rootCmd.AddCommand(startServerCmd)

	if err := rootCmd.Execute(); err != nil {
		printCmdErr(err)
		os.Exit(1)
	}
}

// 开始启动Server
func start(cmd *cobra.Command) {
	// 获取配置文件路径，加载并解析
	cfgPath, err := cmd.Flags().GetString("configFile")
	if err != nil {
		printCmdErr(err)
		return
	}
	if len(cfgPath) != 0 && !fileutil.IsExist(cfgPath) {
		printCmdErr(errors.New("The config file doesn't exist :" + cfgPath))
		return
	}

	PrintBanner()

	// 加载配置文件
	err = utils.LoadConfig(cfgPath)
	if err == nil {
		cfg := utils.GetConfig()

		if err = cfg.Validate(); err != nil {
			printCmdErr(err)
			return
		}

		if err = cfg.Complete(); err != nil {
			printCmdErr(err)
			return
		}

		// 初始化Log
		utils.SetupLog(utils.GetConfig())

		// 初始化web服务
		server := startup.InitWebEndpoints()

		// 同步IAM上的client
		startup.SyncClients()

		// 绑定地址，启动
		bindAddr := fmt.Sprintf("%v:%v", cfg.SsoProxyConfig.BindAddress, cfg.SsoProxyConfig.Port)
		if err := server.Run(bindAddr); err != nil {
			utils.Log().Error("Server fails to start", zap.Error(err))
		}
	}
}

// 在控制台输出出错信息
func printCmdErr(err error) {
	_, err = fmt.Fprintf(os.Stderr, "Error: '%s' \n", err)
	if err != nil {
		panic(err)
	}
}
