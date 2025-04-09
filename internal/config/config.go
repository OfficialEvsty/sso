package config

import (
	"flag"
	"github.com/ilyakaznacheev/cleanenv"
	"os"
	"time"
)

type Config struct {
	Env                  string        `yaml:"env" env-default:"local"`
	StoragePath          string        `yaml:"conn_string" env-required:"true"`
	TokenTTL             time.Duration `yaml:"token_ttl" env-required:"true"`
	RefreshTokenTTL      time.Duration `yaml:"refresh_token_ttl" env-required:"true"`
	SessionTTL           time.Duration `yaml:"session_ttl" env-required:"true"`
	AuthorizationCodeTTL time.Duration `yaml:"authorization_code_ttl" env-required:"true"`
	SessionEnabled       bool          `yaml:"session_enabled"`
	UseCache             bool          `yaml:"use_cache"`
	GRPC                 GRPCConfig    `yaml:"grpc" env-required:"true"`
	Redis                RedisConfig   `yaml:"redis" env-required:"true"`
}

type GRPCConfig struct {
	Port    int           `yaml:"port"`
	Timeout time.Duration `yaml:"timeout"`
}

type RedisConfig struct {
	Host                  string        `yaml:"host"`
	Port                  int           `yaml:"port"`
	Password              string        `yaml:"password"`
	DB                    int           `yaml:"db"`
	SessionTTL            time.Duration `yaml:"session_ttl" env-required:"true"`
	EmailAuthTokenTTL     time.Duration `yaml:"email_auth_token_ttl" env-default:"24h"`
	PasswordResetTokenTTL time.Duration `yaml:"password_reset_token_ttl" env-required:"true"`
}

func MustLoad() *Config {
	path := fetchConfigPath()
	if path == "" {
		panic("config path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config path does not exist: " + path)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic(err)
	}

	return &cfg
}

func MustLoadPath(path string) *Config {
	if path == "" {
		panic("config path is empty")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		panic("config path does not exist: " + path)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(path, &cfg); err != nil {
		panic(err)
	}

	return &cfg
}

// Priority: flag > env > default
func fetchConfigPath() string {
	var res string

	flag.StringVar(&res, "config", "", "path to config file")
	flag.Parse()

	if res == "" {
		res = os.Getenv("CONFIG_PATH")
	}
	return res
}
