package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"time"
)

// Config содержит всю конфигурацию приложения
type Config struct {
	Server   ServerConfig
	Services ServicesConfig
	Log      LogConfig
	JWT      JWTConfig
	Security SecurityConfig
	Proxy    ProxyConfig
	Redis    RedisConfig
	Scope    ScopeConfig
}

// ScopeConfig — режим границы токена пространства (SDL-613 S9, EP-111).
//
// RequireWorkspaceToken (env SCOPE_REQUIRE_WORKSPACE_TOKEN, по умолчанию
// false): true — на маршрутах со скоупом шлюз принимает только токен
// пространства (токен сессии — 401 workspace_token_required), а токен
// пространства становится границей и вне них (middleware.WorkspaceTokenBoundary).
// false — поведение до S9. Нераспознанное значение читается как false,
// поэтому действующее значение шлюз пишет в лог при старте.
type ScopeConfig struct {
	RequireWorkspaceToken bool
}

// ProxyConfig конфигурация прокси
type ProxyConfig struct {
	Timeout time.Duration
}

// JWTConfig конфигурация JWT.
//
// Phase -1.5: gw — pure verifier, RS256 verify-only. PublicKeyPEM
// (PKIX RSA public key) — обязательное. HS256 fallback и SecretKey
// удалены: только auth-service (signer) держит приватный ключ.
type JWTConfig struct {
	PublicKeyPEM string
}

// SecurityConfig конфигурация безопасности
type SecurityConfig struct {
	ServiceKey string
}

// ServerConfig конфигурация сервера
type ServerConfig struct {
	Port         string
	Host         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// ServicesConfig конфигурация сервисов
type ServicesConfig struct {
	Auth         ServiceConfig
	User         ServiceConfig
	Notification ServiceConfig
	Dictionary   ServiceConfig
	TelegramBot  ServiceConfig
	Collections  ServiceConfig
	Files        ServiceConfig
	Pages        ServiceConfig
}

// URLMap возвращает карту "имя сервиса -> URL" для proxy.NewProxyService.
//
// Карта строится рефлексией по полям ServicesConfig, а не перечислением
// вручную: раньше её собирал main.go, и добавление апстрима требовало трёх
// согласованных правок (поле структуры, загрузка переменной, строка в карте).
// Пропуск третьей давал маршрут, который регистрируется в Gin и проходит
// тесты роутера, но в рантайме отвечает "сервис не найден" — сквозной тест
// это не ловит, потому что работает на стабе прокси. Теперь третьей правки
// не существует: поле структуры и есть источник карты.
func (s ServicesConfig) URLMap() map[string]string {
	v := reflect.ValueOf(s)
	out := make(map[string]string, v.NumField())
	for i := 0; i < v.NumField(); i++ {
		svc, ok := v.Field(i).Interface().(ServiceConfig)
		if !ok || svc.Name == "" {
			continue
		}
		out[svc.Name] = svc.URL
	}
	return out
}

// ServiceConfig конфигурация отдельного сервиса
type ServiceConfig struct {
	Name string
	URL  string
}

// LogConfig конфигурация логирования
type LogConfig struct {
	Level string
}

// RedisConfig конфигурация Redis
type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

// Load загружает конфигурацию из переменных окружения
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         getEnv("PORT", "8080"),
			Host:         getEnv("HOST", "0.0.0.0"),
			ReadTimeout:  getEnvDuration("READ_TIMEOUT", 30*time.Second),
			WriteTimeout: getEnvDuration("WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getEnvDuration("IDLE_TIMEOUT", 60*time.Second),
		},
		Services: ServicesConfig{
			Auth: ServiceConfig{
				Name: "auth",
				URL:  getEnvRequired("AUTH_SERVICE_URL"),
			},
			User: ServiceConfig{
				Name: "user",
				URL:  getEnvRequired("USER_SERVICE_URL"),
			},
			Notification: ServiceConfig{
				Name: "notification",
				URL:  getEnvRequired("NOTIFICATION_SERVICE_URL"),
			},
			Dictionary: ServiceConfig{
				Name: "dictionary",
				URL:  getEnvRequired("DICTIONARY_SERVICE_URL"),
			},
			TelegramBot: ServiceConfig{
				Name: "telegram-bot",
				URL:  getEnvRequired("TELEGRAM_BOT_SERVICE_URL"),
			},
			Collections: ServiceConfig{
				Name: "collections",
				URL:  getEnvRequired("COLLECTIONS_SERVICE_URL"),
			},
			// files — getEnv с дефолтом, а НЕ getEnvRequired. Разница не
			// стилистическая: getEnvRequired паникует на пустой переменной, и
			// выкат шлюза с новым апстримом обгонял бы выкат ConfigMap —
			// то есть добавление сервиса роняло бы прод на несколько минут.
			// Дефолт совпадает с адресом Service в кластере, поэтому
			// переменная нужна только чтобы его переопределить.
			Files: ServiceConfig{
				Name: "files",
				URL:  getEnv("FILES_SERVICE_URL", "http://files-service:80"),
			},
			// SDL-572 (EP-108): апстрим редактора страниц. Тот же getEnv с
			// дефолтом, что и у files выше, и по той же причине: пода шлюза
			// с новым апстримом не должен зависеть от того, успел ли выкат
			// ConfigMap обогнать выкат образа.
			//
			// Сейчас под этот апстрим опубликован ровно один путь —
			// /api/v1/pages/health, он вне permissionMiddleware. Продуктовые
			// маршруты придут из EP-110/EP-112 и тогда же потребуют записей
			// в GetRouteConfigs: защищённый роут без записи отвечает 403
			// всем и всегда (fail-safe, прецедент SDL-135).
			Pages: ServiceConfig{
				Name: "pages",
				URL:  getEnv("PAGES_SERVICE_URL", "http://pages-service:80"),
			},
		},
		Log: LogConfig{
			Level: getEnv("LOG_LEVEL", "info"),
		},
		JWT: JWTConfig{
			PublicKeyPEM: getEnvRequired("JWT_PUBLIC_KEY"),
		},
		Security: SecurityConfig{
			ServiceKey: getEnvRequired("SERVICE_KEY"),
		},
		Proxy: ProxyConfig{
			Timeout: getEnvDuration("PROXY_TIMEOUT", 30*time.Second),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", ""),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
		Scope: ScopeConfig{
			RequireWorkspaceToken: getEnvBool("SCOPE_REQUIRE_WORKSPACE_TOKEN", false),
		},
	}
}

// getEnv получает значение переменной окружения или возвращает значение по умолчанию
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt получает целочисленное значение переменной окружения
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvDuration получает значение переменной окружения как duration
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// getEnvBool получает булево значение переменной окружения
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// getEnvRequired получает обязательную переменную окружения или паникует
func getEnvRequired(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("обязательная переменная окружения %s не установлена", key))
	}
	return value
}
