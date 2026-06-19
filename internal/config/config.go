package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "agentguard.yml"

type Config struct {
	Version int     `yaml:"version"`
	Protect Protect `yaml:"protect"`
	Deny    Rules   `yaml:"deny"`
	Confirm Rules   `yaml:"confirm"`
	Allow   Rules   `yaml:"allow"`
}

type Protect struct {
	Paths []string `yaml:"paths"`
}

type Rules struct {
	Commands []string `yaml:"commands"`
	Domains  []string `yaml:"domains,omitempty"`
}

func Default() Config {
	return Config{
		Version: 1,
		Protect: Protect{Paths: []string{
			".env", ".env.*", "~/.ssh/*", "~/.gnupg/*", "*.pem", "*.key", "id_rsa", "id_ed25519",
		}},
		Deny: Rules{
			Commands: []string{
				"rm -rf *", "git push --force", "curl * | bash", "wget * | sh",
				"terraform destroy", "kubectl delete *", "docker system prune *",
			},
			Domains: []string{"pastebin.com", "webhook.site"},
		},
		Confirm: Rules{Commands: []string{
			"sudo *", "docker *", "kubectl *", "terraform apply", "git push *",
		}},
		Allow: Rules{Commands: []string{
			"git status", "git diff", "npm test", "pnpm test", "go test ./...",
		}},
	}
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Version == 0 {
		return Config{}, errors.New("config version is required")
	}
	return cfg, nil
}

func WriteDefault(path string) error {
	b, err := yaml.Marshal(Default())
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
