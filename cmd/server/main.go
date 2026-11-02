package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"gateway-service/internal/config"
	"gateway-service/internal/handlers"
	"gateway-service/internal/proxy"
	"gateway-service/internal/routes"

	// Импорт go-sdk
	"gitlab.com/markerloop/go-sdk/pkg/logger"
	"gitlab.com/markerloop/go-sdk/pkg/redis"
	sentrysdk "gitlab.com/markerloop/go-sdk/pkg/sentry"
)

func main() {
	// Загружаем переменные окружения
	if err := godotenv.Load(); err != nil {
		log.Println("Файл .env не найден, используем переменные окружения по умолчанию")
	}

	// Загружаем конфигурацию
	cfg := config.Load()

	// Инициализируем логгер SDK
	loggerInstance := logger.InitLogger("gateway-service")

	// Sentry (SDL-86): включается только когда контур задал SENTRY_DSN;
	// без переменной — рабочий no-op, сервис стартует как раньше.
	sentrysdk.Init("gateway-service", loggerInstance)
	defer sentrysdk.Flush()

	// Карта сервисов выводится из ServicesConfig, а не перечисляется здесь:
	// иначе новый апстрим требует правки в двух местах, и забытая вторая
	// даёт "сервис не найден" уже в рантайме (SDL-175).
	services := cfg.Services.URLMap()

	// Создаем сервис проксирования
	proxyService := proxy.NewProxyService(services, cfg.Proxy.Timeout, loggerInstance)

	// Инициализируем Redis (опционально, не критично если недоступен)
	var redisService *redis.RedisService
	if cfg.Redis.Addr != "" {
		// Временно устанавливаем переменные окружения для Redis
		os.Setenv("REDIS_ADDR", cfg.Redis.Addr)
		os.Setenv("REDIS_PASSWORD", cfg.Redis.Password)
		os.Setenv("REDIS_DB", fmt.Sprintf("%d", cfg.Redis.DB))
		redisService = redis.NewRedisService(loggerInstance)
	} else {
		loggerInstance.Warn("Redis не настроен, кэширование разрешений отключено")
	}

	// Создаем хендлер
	proxyHandler := handlers.NewProxyHandler(proxyService, loggerInstance)

	// Создаем роутер
	r := gin.New()

	// Отключаем автоматический редирект trailing slash (чтобы CORS работал корректно)
	r.RedirectTrailingSlash = false

	// Sentry: паники и 5xx уходят событиями; при пустом DSN остаётся
	// обычное восстановление паник с ответом 500.
	r.Use(sentrysdk.GinMiddleware("gateway-service"))

	// Настраиваем роуты
	routes.SetupRoutes(r, proxyHandler, cfg, proxyService, redisService, loggerInstance)

	// Создаем HTTP сервер с таймаутами
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port),
		Handler:      r,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Запускаем сервер в горутине
	go func() {
		loggerInstance.Infof("Gateway service запущен на %s:%s", cfg.Server.Host, cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			loggerInstance.Fatal("Ошибка запуска сервера:", err)
		}
	}()

	// Ожидаем сигнал для graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	loggerInstance.Info("Завершение работы сервера...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		loggerInstance.Fatal("Ошибка graceful shutdown:", err)
	}

	loggerInstance.Info("Сервер успешно остановлен")
}
