package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

type Config struct {
	App          AppConfig
	Postgres     PostgresConfig
	ClickHouse   ClickHouseConfig
	ML           MLConfig
	JWT          JWTConfig
	Telegram     TelegramConfig
	InitialAdmin InitialAdminConfig
}

type AppConfig struct{ Env, Port, Version string }
type PostgresConfig struct{ Host, Port, User, Password, Database string }
type ClickHouseConfig struct{ Host, Port, User, Password, Database string }
type MLConfig struct {
	ServiceURL        string
	Timeout           time.Duration
	WindowSizeSeconds float64
}
type JWTConfig struct {
	Secret     string
	Expiration time.Duration
}
type TelegramConfig struct {
	BotToken, AdminChatID   string
	WebhookSecret           string
	Timeout                 time.Duration
	RetryCount, MinSeverity int
	MinScore                float64
	BaseIncidentURL         string
}
type InitialAdminConfig struct{ Login, Password string }

func Load() Config {
	return Config{
		App:          AppConfig{Env: env("APP_ENV", "development"), Port: env("APP_PORT", "8080"), Version: env("APP_VERSION", "1.0.0")},
		Postgres:     PostgresConfig{Host: env("DB_POSTGRES_HOST", "localhost"), Port: env("DB_POSTGRES_PORT", "5432"), User: env("DB_POSTGRES_USER", "nm_user"), Password: env("DB_POSTGRES_PASSWORD", env("DB_PASSWORD", "network_monitor")), Database: env("DB_POSTGRES_DB", "network_monitor")},
		ClickHouse:   ClickHouseConfig{Host: env("DB_CLICKHOUSE_HOST", "localhost"), Port: env("DB_CLICKHOUSE_PORT", "9000"), User: env("DB_CLICKHOUSE_USER", "default"), Password: env("DB_CLICKHOUSE_PASSWORD", env("CLICKHOUSE_PASSWORD", "")), Database: env("DB_CLICKHOUSE_DB", "default")},
		ML:           MLConfig{ServiceURL: env("ML_SERVICE_URL", "http://localhost:5000"), Timeout: duration("ML_TIMEOUT", 30*time.Second), WindowSizeSeconds: float("ML_WINDOW_SECONDS", 300)},
		JWT:          JWTConfig{Secret: env("JWT_SECRET", "change-me-minimum-32-characters-secret"), Expiration: duration("JWT_EXPIRATION", 24*time.Hour)},
Telegram:     TelegramConfig{BotToken: env("TELEGRAM_BOT_TOKEN", ""), AdminChatID: env("TELEGRAM_ADMIN_CHAT_ID", ""), WebhookSecret: env("TELEGRAM_WEBHOOK_SECRET", ""), Timeout: duration("TELEGRAM_TIMEOUT", 10*time.Second), RetryCount: integer("TELEGRAM_RETRY_COUNT", 3), MinSeverity: integer("TELEGRAM_MIN_SEVERITY", 3), MinScore: float("TELEGRAM_MIN_ML_SCORE", 0.6), BaseIncidentURL: env("BASE_INCIDENT_URL", "https://fluxmon.ru/incidents")},
		InitialAdmin: InitialAdminConfig{Login: env("INIT_ADMIN_LOGIN", "admin"), Password: env("INIT_ADMIN_PASSWORD", "ChangeMe123!")},
	}
}

func (c PostgresConfig) DSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", c.User, url.QueryEscape(c.Password), c.Host, c.Port, c.Database)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func duration(key string, fallback time.Duration) time.Duration {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
func integer(key string, fallback int) int {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
func float(key string, fallback float64) float64 {
	v := env(key, "")
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return n
}
