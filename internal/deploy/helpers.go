package deploy

import (
	"os"
	"gopkg.in/yaml.v3"

	"kgate/internal/model"
)

func yamlMarshal(c *model.Config) ([]byte, error) { return yaml.Marshal(c) }

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "/tmp"
	}
	return h
}
