FROM golang:1.23-alpine AS builder

# Принимаем токены как build arguments
ARG DEPLOY_TOKEN_USERNAME
ARG DEPLOY_TOKEN_PASSWORD


# Устанавливаем git и ca-certificates
RUN apk add --no-cache git ca-certificates

# Отладочная информация для проверки групповых токенов
RUN echo "=== Проверка групповых переменных CI/CD ===" && \
    echo "DEPLOY_TOKEN_USERNAME установлен: $(if [ -n "$DEPLOY_TOKEN_USERNAME" ]; then echo "ДА"; else echo "НЕТ"; fi)" && \
    echo "Длина DEPLOY_TOKEN_USERNAME: ${#DEPLOY_TOKEN_USERNAME}" && \
    echo "DEPLOY_TOKEN_PASSWORD установлен: $(if [ -n "$DEPLOY_TOKEN_PASSWORD" ]; then echo "ДА"; else echo "НЕТ"; fi)" && \
    echo "Длина DEPLOY_TOKEN_PASSWORD: ${#DEPLOY_TOKEN_PASSWORD}" && \
    echo "=== Конец отладки ==="

WORKDIR /app

# Настройка переменных окружения для приватных Go модулей
# GONOSUMDB критически важен - отключает проверку через публичную базу данных checksums
ENV GOPRIVATE=gitlab.com/markerloop/*
ENV GONOPROXY=gitlab.com/markerloop/*
ENV GONOSUMDB=gitlab.com/markerloop/*

# Копируем go mod файлы
COPY go.mod go.sum ./

# Настраиваем git для приватных репозиториев
RUN git config --global url."https://${DEPLOY_TOKEN_USERNAME}:${DEPLOY_TOKEN_PASSWORD}@gitlab.com/".insteadOf "https://gitlab.com/"

# Скачиваем зависимости
RUN go mod download

# Копируем исходный код
COPY . .

# Обновляем go.sum с учетом всех импортов из исходного кода
RUN go mod tidy

# Собираем приложение
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/server

# Финальный образ
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Копируем бинарный файл из builder
COPY --from=builder /app/main .

# Копируем .env файл если есть
COPY --from=builder /app/.env* ./

# Открываем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./main"]
