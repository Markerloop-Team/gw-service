package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// dataPlanePrefix — префикс публичной плоскости коллекций (EP-13 §11.3,
// SDL-172): под ним ходят анонимы, владельцы mlp_-токенов и залогиненные
// пользователи внешних приложений.
const dataPlanePrefix = "/api/v1/data/"

// IsDataPlanePath сообщает, относится ли путь к публичной плоскости /data.
func IsDataPlanePath(path string) bool {
	return strings.HasPrefix(path, dataPlanePrefix)
}

// DataCORS — CORS публичной плоскости /api/v1/data (EP-13 §17, SDL-172):
// Allow-Origin * и Credentials false. Это безопасно ИМЕННО потому, что
// плоскость никогда не использует cookies: личность выводится только из
// заголовка Authorization, который браузер по wildcard-CORS не подставит
// сам — его явно шлёт клиентский код. Общий CORS шлюза (allowlist origins
// + credentials) на эту группу не подходит: публичную коллекцию читает
// произвольный сайт произвольного клиента, перечислить их нельзя.
//
// Preflight (OPTIONS) гасится здесь и не проксируется вниз.
func DataCORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Max-Age", "43200")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// SplitCORS выбирает CORS-обвязку по пути: /api/v1/data — публичная
// (wildcard, без credentials), всё остальное — переданный стандартный
// обработчик. Вешается как ГЛОБАЛЬНЫЙ middleware вместо голого
// sdkMiddleware.CORS(): группа /data не может «выйти» из-под r.Use, поэтому
// ветвление живёт внутри одного обработчика.
func SplitCORS(standard gin.HandlerFunc) gin.HandlerFunc {
	data := DataCORS()
	return func(c *gin.Context) {
		if IsDataPlanePath(c.Request.URL.Path) {
			data(c)
			return
		}
		standard(c)
	}
}
