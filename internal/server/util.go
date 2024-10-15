package server

import (
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func rewriteRequest(c *gin.Context) {
	log.Debug().Msg("rewrite request")
	c.Request.URL.Scheme = c.Request.Header.Get("X-Forwarded-Proto")
	c.Request.Method = c.Request.Header.Get("X-Forwarded-Method")
	c.Request.URL.Host = c.Request.Header.Get("X-Forwarded-Host")
	if _, ok := c.Request.Header["X-Forwarded-Uri"]; ok {
		c.Request.URL, _ = url.Parse(c.Request.Header.Get("X-Forwarded-Uri"))
	}
}

func LogForwardedHeaders(c *gin.Context) {
	log.Trace().
		Str("X-Forwarded-Proto", c.Request.Header.Get("X-Forwarded-Proto")).
		Str("X-Forwarded-Method", c.Request.Header.Get("X-Forwarded-Method")).
		Str("X-Forwarded-Host", c.Request.Header.Get("X-Forwarded-Host")).
		Str("X-Forwarded-Uri", c.Request.Header.Get("X-Forwarded-Uri")).
		Msg("forwarded header")
}

func LogRequest(c *gin.Context) {
	log.Trace().
		Str("method", c.Request.Method).
		Str("path", c.Request.URL.Path).
		Str("query", c.Request.URL.RawQuery).
		Str("remote_addr", c.ClientIP()).
		Msg("request")
}
