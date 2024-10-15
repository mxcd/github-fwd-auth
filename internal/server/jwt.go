package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/mxcd/github-fwd-auth/internal/github"
	"github.com/rs/zerolog/log"
)

func (s *Server) handleJwtAddition(c *gin.Context) error {
	// TODO add jwt cache for session id
	err := s.addJwtHeader(c)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		c.Writer.Write([]byte("failed to generate JWT"))
		return err
	}

	return nil
}

func (s *Server) addJwtHeader(c *gin.Context) error {
	log.Trace().Msg("adding jwt header")
	session, ok := s.Options.SessionStore.GetSession(c)
	if !ok {
		log.Warn().Msg("no session found for request")
		return fmt.Errorf("no session found for request")
	}

	token := s.Options.JwtSigner.NewToken()
	token.Set("sub", session.UserInformation.Profile.Login)
	token.Set("uid", session.UserInformation.Profile.ID)
	token.Set("name", session.UserInformation.Profile.Name)
	token.Set("email", session.UserInformation.Profile.Email)
	token.Set("teams", github.GetTeamSlugs(session.UserInformation.Teams))

	tokenData, err := s.Options.JwtSigner.SignToken(token)
	if err != nil {
		return err
	}

	c.Header("Authorization", "Bearer "+string(tokenData))
	return nil
}
