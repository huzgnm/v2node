package conf

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

const DefaultNodeRetryCount = 1
const DefaultNodeTimeout = 15

type Conf struct {
	LogConfig   LogConfig    `mapstructure:"Log"`
	NodeConfigs []NodeConfig `mapstructure:"Nodes"`
	PprofPort   int          `mapstructure:"PprofPort"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type ControlConfig struct {
	Listen string `mapstructure:"Listen"`
	Secret string `mapstructure:"Secret"`
	// Optional override. Left empty, the control listener reuses the certificate
	// this agent already holds for the node, so nothing has to be configured;
	// set them only to serve the channel with a different certificate.
	CertFile string `mapstructure:"CertFile"`
	KeyFile  string `mapstructure:"KeyFile"`
	// Serve plain http instead of https. Local test benches only: the panel
	// refuses a plain-http endpoint in production because the reconfig body
	// carries the ApiKey.
	Insecure bool `mapstructure:"Insecure"`
}

type NodeConfig struct {
	APIHost    string         `mapstructure:"ApiHost"`
	NodeID     int            `mapstructure:"NodeID"`
	Key        string         `mapstructure:"ApiKey"`
	Timeout    int            `mapstructure:"Timeout"`
	RetryCount *int           `mapstructure:"RetryCount"`
	Control    *ControlConfig `mapstructure:"Control"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open config file error: %s", err)
	}
	defer f.Close()
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config file error: %s", err)
	}
	if err := v.Unmarshal(p); err != nil {
		return fmt.Errorf("unmarshal config error: %s", err)
	}
	for i := range p.NodeConfigs {
		if p.NodeConfigs[i].RetryCount == nil {
			p.NodeConfigs[i].RetryCount = intPtr(DefaultNodeRetryCount)
		}
	}
	return nil
}

func intPtr(v int) *int {
	return &v
}
