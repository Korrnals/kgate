package model

import "gopkg.in/yaml.v3"

func yamlUnmarshal(b []byte, c *Config) error { return yaml.Unmarshal(b, c) }
