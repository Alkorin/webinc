package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var defaultConfig = map[string]interface{}{
	"log-file":  "webinc.log",
	"log-level": "info",
}

type Config struct {
	configFileName string
	config         map[string]interface{}
}

func NewConfig() (*Config, error) {
	// Search TOML configuration
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Info("Failed to locate HOME folder, defaulting to CWD")
	}

	configFile := filepath.Join(homeDir, ".config/webinc/webinc.conf")

	c := &Config{
		configFileName: configFile,
		config:         make(map[string]interface{}),
	}

	return c, c.readConfigFile()
}

func (c *Config) getValue(name string) interface{} {
	if v, ok := c.config[name]; ok {
		return v
	}

	return defaultConfig[name]
}

func (c *Config) readConfigFile() error {
	if _, err := os.Stat(c.configFileName); os.IsNotExist(err) {
		// Nothing to read
		return nil
	}

	if _, err := toml.DecodeFile(c.configFileName, &c.config); err != nil {
		return errors.Wrap(err, "failed to parse config file")
	}

	return nil
}

func (c *Config) GetString(name string) string {
	v := c.getValue(name)

	if v == nil {
		return ""
	} else if s, ok := v.(string); ok {
		return s
	} else {
		return fmt.Sprintf("%v", v)
	}
}

func (c *Config) SetString(name string, value string) {
	c.config[name] = value
}

func (c *Config) Save() error {
	// Check if folder exists
	folder := filepath.Dir(c.configFileName)
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		err := os.MkdirAll(folder, 0700)
		if err != nil {
			return errors.Wrap(err, "failed to create folder for configuration file")
		}
	}

	file, err := os.OpenFile(c.configFileName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "failed to open file to write configuration")
	}
	defer file.Close()

	err = toml.NewEncoder(file).Encode(c.config)
	if err != nil {
		return errors.Wrap(err, "failed to write configuration")
	}

	return nil
}
