package utils

import (
	"fmt"
	"log"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	"sso-proxy/pkg/model"
)

var config = new(model.Config)

// LoadConfig 加载配置文件
func LoadConfig(configPath string) error {
	// 如果没有在命令行参数中指定配置文件的具体路径，则从默认路径查找
	if len(configPath) == 0 {
		// 支持从以下目录查找配置文件： ./config/config.yaml,  /etc/sso-proxy/config.yaml
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/sso-proxy/")
	} else {
		// 从命令行指定的目录加载配置文件
		viper.SetConfigFile(configPath)
	}

	// 加载配置文件
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Failed to load config.yaml: %v", err)
		return err
	}

	// 序列化成struct
	if err := viper.Unmarshal(config); err != nil {
		log.Fatalf("Failed to unmarshal config.yaml: %v", err)
		return err
	}

	// 监控配置文件变化
	viper.WatchConfig()

	// 注意！！！配置文件发生变化后要同步到全局变量
	viper.OnConfigChange(func(in fsnotify.Event) {
		fmt.Println("Config file is changed, reload it now")
		var newConfig = &model.Config{}

		// 更新现有的配置
		if err := viper.Unmarshal(newConfig); err != nil {
			panic(fmt.Errorf("The config cann't be updated:%s \n", err))
		}
		config = newConfig

		// todo：日志组件更新
	})
	return nil
}

// GetConfig 返回全局配置
func GetConfig() *model.Config {
	return config
}
