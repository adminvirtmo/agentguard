package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const DefaultPath = "agentguard.yml"

const (
	ProfileBalanced   = "balanced"
	ProfileStrict     = "strict"
	ProfilePermissive = "permissive"
)

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
	return Profile(ProfileBalanced)
}

func Profile(name string) Config {
	cfg := balanced()
	switch name {
	case "", ProfileBalanced:
		return cfg
	case ProfileStrict:
		cfg.Protect.Paths = append(cfg.Protect.Paths,
			".npmrc", ".pypirc", ".netrc", ".docker/config.json", "kubeconfig", "*.kubeconfig",
			"*.p12", "*.pfx", "*.crt", "*.cer", "*.der", "credentials", "credentials.json",
		)
		cfg.Deny.Commands = append(cfg.Deny.Commands,
			"git push *", "gh repo delete *", "gh auth token", "npm publish *", "pnpm publish *",
			"docker login *", "kubectl config view *", "aws configure *",
		)
		cfg.Confirm.Commands = append(cfg.Confirm.Commands,
			"gh *", "aws *", "gcloud *", "az *", "npm install *", "pnpm install *", "pip install *",
		)
		return cfg
	case ProfilePermissive:
		cfg.Deny.Commands = []string{
			"rm -rf *", "curl * | bash", "wget * | sh", "terraform destroy", "kubectl delete *",
		}
		cfg.Confirm.Commands = []string{"sudo *", "git push *"}
		return cfg
	default:
		return Config{}
	}
}

func ValidProfile(name string) bool {
	switch name {
	case ProfileBalanced, ProfileStrict, ProfilePermissive:
		return true
	default:
		return false
	}
}

func ProfileNames() []string {
	return []string{ProfileBalanced, ProfileStrict, ProfilePermissive}
}

func balanced() Config {
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
	return WriteProfile(path, ProfileBalanced)
}

func WriteProfile(path, profile string) error {
	if !ValidProfile(profile) {
		return fmt.Errorf("unknown profile %q", profile)
	}
	b, err := yaml.Marshal(Profile(profile))
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
