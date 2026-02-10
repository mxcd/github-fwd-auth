package server

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	githuboauth "github.com/mxcd/github-fwd-auth/pkg/githuboauth"
)

func (s *Server) addJwtHeader(c *gin.Context) error {
	log.Trace().Msg("adding jwt header")

	session, ok := s.Options.OAuthHandle.GetSessionStore().GetSession(c)
	if !ok {
		log.Warn().Msg("no session found for JWT generation")
		return fmt.Errorf("no session found for request")
	}

	sessionID := session.GetSessionID()
	if sessionID == "" {
		return fmt.Errorf("session has no ID for caching")
	}

	tokenString, ok := s.JwtCache.Get(sessionID)
	if !ok {
		token := s.Options.JwtSigner.NewToken()
		token.Set("sub", session.UserInformation.Profile.Login)
		token.Set("uid", session.UserInformation.Profile.ID)
		token.Set("name", session.UserInformation.Profile.Name)
		token.Set("email", session.UserInformation.Profile.Email)
		token.Set("teams", githuboauth.GetTeamSlugs(session.UserInformation.Teams))

		tokenData, err := s.Options.JwtSigner.SignToken(token)
		if err != nil {
			return err
		}

		tokenString = string(tokenData)
		s.JwtCache.Add(sessionID, tokenString)
	}

	c.Header("Authorization", "Bearer "+tokenString)
	return nil
}
