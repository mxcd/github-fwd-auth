package server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/mxcd/github-fwd-auth/internal/github"
)

func (s *Server) handleAllowedTeams(c *gin.Context) error {
	session, ok := s.Options.SessionStore.GetSession(c)
	if !ok {
		return fmt.Errorf("no session found for request")
	}

	teams := github.GetTeamSlugs(session.UserInformation.Teams)
	for _, allowedTeam := range s.Options.AllowedTeams {
		if slices.Contains(teams, allowedTeam) {
			return nil
		}
	}

	c.Status(http.StatusUnauthorized)
	c.Writer.Write([]byte(fmt.Sprintf("user is not member of any of the allowed teams: %s", s.Options.AllowedTeams)))
	return errors.New("user is not member of any of the allowed teams")
}
