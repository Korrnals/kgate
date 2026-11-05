package deploy

import (
	"gopkg.in/yaml.v3"

	"kgate/internal/model"
)

func yamlMarshal(c *model.Config) ([]byte, error) { return yaml.Marshal(c) }
