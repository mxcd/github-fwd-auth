package server

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func (s *Server) handleApiKeyAuthentication(c *gin.Context) (handled bool) {
	validApiKeys := s.Options.ApiKeys

	providedApiKey := c.GetHeader("X-Api-Key")
	if providedApiKey == "" {
		log.Trace().Msg("no api key provided by requesting client")
		return false
	}

	for _, apiKey := range validApiKeys {
		if apiKey == providedApiKey {
			log.Trace().Msg("client provided a valid api key")
			c.Status(200)
			return true
		}
	}

	log.Warn().Msg("client provided an invalid api key")
	c.Status(401)
	c.Writer.Write([]byte("invalid api key"))
	return true
}
